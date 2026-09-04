"""
AthenAI - Threat Detector

Detección automática y bloqueo de:
  1. Code Injection  — SQL Injection, XSS, Command Injection en body/path/params
  2. Credential Stuffing — múltiples usuarios desde misma IP o mismo usuario desde muchas IPs
  3. Impossible Travel — mismo usuario autenticado desde IPs geográficamente distintas en < 30 min

Todas las detecciones bloquean la IP automáticamente via IPBlocker + Redis.
"""

import re
import time
import json
import logging
import urllib.parse
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Normalización de input antes de inspección
# ─────────────────────────────────────────────

def _normalize(text: str, _sql_sep: str = ' ') -> str:
    """
    Normaliza input HTTP antes de aplicar los patrones WAF.

    Pasos (relevantes para SQLi, XSS y CMDi — alcance de la tesis):
      1. %uXXXX  → carácter real  (encoding Unicode estilo IIS, e.g. %u0027 → ')
      2. %XX / %25XX → decodificación URL multicapa hasta punto fijo (doble encoding)
      3. Entidades HTML numéricas y nombradas (&#39; &#x27; &lt; &gt; &amp;)
      4. Comentarios SQL inline eliminados con separador configurable
      5. Lowercase uniforme para matching insensible a mayúsculas

    _sql_sep=' '  → SELECT/*x*/col  → SELECT col  (preserva word boundaries)
    _sql_sep=''   → SE/**/LECT      → SELECT      (reconstruye keyword partido)
    """
    if not text:
        return ''

    # 1. %uXXXX — IIS Unicode encoding (%u0027 → ', %u003c → <)
    text = re.sub(
        r'%u([0-9a-fA-F]{4})',
        lambda m: chr(int(m.group(1), 16)),
        text,
    )

    # 2. URL decoding multicapa hasta punto fijo (máx. 5 iteraciones)
    prev = None
    for _ in range(5):
        if prev == text:
            break
        prev = text
        text = urllib.parse.unquote(text)

    # 3. Entidades HTML numéricas hex (&#x27; → ') y decimales (&#39; → ')
    text = re.sub(r'&#x([0-9a-fA-F]+);?', lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r'&#([0-9]+);?',        lambda m: chr(int(m.group(1))),      text)
    # Entidades HTML nombradas relevantes para inyección
    for entity, char in (('&lt;', '<'), ('&gt;', '>'), ('&amp;', '&'),
                         ('&quot;', '"'), ('&apos;', "'")):
        text = text.replace(entity, char)

    # 4. Comentarios SQL inline con separador configurable
    text = re.sub(r'/\*.*?\*/', _sql_sep, text, flags=re.DOTALL)

    return text.lower()

# ─────────────────────────────────────────────
# Patrones de inyección (sobre texto normalizado)
# ─────────────────────────────────────────────
_SQL_RE = re.compile(
    r"(?i)(\bselect\b.+\bfrom\b|\bunion\b.+\bselect\b|\binsert\b.+\binto\b"
    r"|\bdrop\b.+\btable\b|\bdelete\b.+\bfrom\b|\bupdate\b.+\bset\b"
    r"|--|;\s*--|'\s*or\s*'[^']*'\s*=\s*'|1\s*=\s*1|0\s*=\s*0"
    r"|\bexec\b\s*\(|\bexecute\b\s*\(|\bxp_cmdshell\b"
    r"|\bchar\s*\(|\b0x[0-9a-f]{4,}\b|\bcase\b.+\bwhen\b.+\bthen\b)"
)
_XSS_RE = re.compile(
    r"(?i)(<script[\s/>]|</script>|javascript\s*:|vbscript\s*:"
    r"|onerror\s*=|onload\s*=|onclick\s*=|ontoggle\s*=|onanimation"
    r"|<img[^>]+onerror|<svg[^>]*/?>.*?on\w+\s*="
    r"|<details[^>]+open[^>]+on\w+|data\s*:\s*text/html"
    r"|document\.cookie|alert\s*\(|eval\s*\(|expression\s*\()"
)
_CMD_RE = re.compile(
    r"(?i)(;?\s*\b(ls|cat|wget|curl|bash|sh|cmd|powershell)\b[\s\x00]"
    r"|\|.*?\b(ls|cat|id|whoami|uname)\b"
    r"|`[^`]+`|\$\([^)]+\)|\$\{ifs\}"
    r"|\.\.\/\.\.\/|/etc/passwd|/etc/shadow|/proc/self"
    r"|\x00|%00)"
)
_PATH_RE = re.compile(
    r"(?i)(\.\.\/|\.\.\\|/etc/passwd|/etc/shadow|/proc/self"
    r"|/windows/system32|\x00|%00"
    r"|\.\.%2f|\.\.%5c)"
)

def looks_malicious(text: str) -> Optional[str]:
    """
    Chequeo de patrones compartido: SQLi, XSS, Command Injection, Path Traversal.

    Aplica la misma normalización (decodificación URL/Unicode/entidades HTML,
    remoción de comentarios SQL) que inspect_request(), pero solo detecta —
    no bloquea ni escribe en Redis. Pensado para consumidores que necesitan
    un chequeo de patrones rápido antes de invocar el modelo ML (ver
    app/ml/ai_engine.py) sin mantener su propia lista de patrones.

    Returns:
        El nombre del tipo de amenaza si algún patrón coincide, None si es limpio.
    """
    if not text:
        return None
    for normalized in (_normalize(text, _sql_sep=' '), _normalize(text, _sql_sep='')):
        if _SQL_RE.search(normalized):
            return "SQL Injection"
        if _XSS_RE.search(normalized):
            return "XSS"
        if _CMD_RE.search(normalized):
            return "Command Injection"
        if _PATH_RE.search(normalized):
            return "Path Traversal"
    return None


# ─────────────────────────────────────────────
# Claves Redis
# ─────────────────────────────────────────────
_CRED_STUFF_IP_KEY   = "athenai:credstuff:ip:{ip}"       # usernames intentados desde IP
_CRED_STUFF_USER_KEY = "athenai:credstuff:user:{user}"   # IPs que intentaron usuario
_TRAVEL_KEY          = "athenai:travel:{user_id}"        # último login de usuario

# Ventanas y umbrales
_CRED_STUFF_WINDOW   = 300   # 5 minutos
_CRED_STUFF_MAX_USERS = 5    # >5 usuarios distintos desde misma IP → stuffing
_CRED_STUFF_MAX_IPS   = 8    # >8 IPs distintas para mismo usuario → stuffing
_TRAVEL_WINDOW       = 1800  # 30 minutos — si cambia IP → sospechoso
_INJECTION_BLOCK_TTL = 86400 # 24 horas bloqueado por inyección
_STUFFING_BLOCK_TTL  = 3600  # 1 hora por credential stuffing
_TRAVEL_BLOCK_TTL    = 1800  # 30 min por impossible travel


class ThreatDetector:
    """
    Detecta y bloquea amenazas en tiempo real.
    Se instancia una sola vez y se reutiliza en cada request.
    """

    def __init__(self, ip_blocker=None, redis_client=None):
        self.ip_blocker = ip_blocker
        self.redis = redis_client   # puede ser None (fail-open)

    # ──────────────────────────────────────────
    # API pública
    # ──────────────────────────────────────────

    def inspect_request(self, ip: str, method: str, path: str,
                        query_params: str, body: str) -> Optional[dict]:
        """
        Analiza un request entrante en busca de inyecciones.
        Llamar ANTES de procesar el request.

        Returns:
            dict con {threat_type, reason} si se detecta amenaza, None si es limpio.
        """
        raw = " ".join(filter(None, [path, query_params or "", body or ""]))
        threat_type = looks_malicious(raw)
        if threat_type is None:
            return None

        reasons = {
            "SQL Injection": f"SQL pattern detected in {method} {path}",
            "XSS": f"XSS pattern detected in {method} {path}",
            "Command Injection": f"Command injection pattern in {method} {path}",
            "Path Traversal": f"Path traversal pattern in {method} {path}",
        }
        threat = {"threat_type": threat_type, "reason": reasons[threat_type]}

        self._block(ip, threat["threat_type"], threat["reason"], _INJECTION_BLOCK_TTL)
        return threat

    def record_login_attempt(self, ip: str, username: str, success: bool) -> Optional[dict]:
        """
        Registra un intento de login y detecta credential stuffing.
        Llamar después de cada intento de login (exitoso o fallido).

        Returns:
            dict con {threat_type, reason} si se detecta stuffing, None si limpio.
        """
        if not self.redis:
            return None

        try:
            now = int(time.time())
            window_start = now - _CRED_STUFF_WINDOW

            # Registrar username intentado desde esta IP
            ip_key = _CRED_STUFF_IP_KEY.format(ip=ip)
            self.redis.zadd(ip_key, {f"{username}:{now}": now})
            self.redis.zremrangebyscore(ip_key, 0, window_start)
            self.redis.expire(ip_key, _CRED_STUFF_WINDOW + 10)
            unique_users = len({m.split(b":")[0] if isinstance(m, bytes) else m.split(":")[0]
                                for m in self.redis.zrange(ip_key, 0, -1)})

            # Registrar IP que intentó este username
            user_key = _CRED_STUFF_USER_KEY.format(user=username)
            self.redis.zadd(user_key, {f"{ip}:{now}": now})
            self.redis.zremrangebyscore(user_key, 0, window_start)
            self.redis.expire(user_key, _CRED_STUFF_WINDOW + 10)
            unique_ips = len({m.split(b":")[0] if isinstance(m, bytes) else m.split(":")[0]
                              for m in self.redis.zrange(user_key, 0, -1)})

            if unique_users > _CRED_STUFF_MAX_USERS:
                reason = (f"Credential stuffing: {unique_users} distinct usernames "
                          f"from {ip} in {_CRED_STUFF_WINDOW}s")
                self._block(ip, "Credential Stuffing", reason, _STUFFING_BLOCK_TTL)
                return {"threat_type": "Credential Stuffing", "reason": reason}

            if unique_ips > _CRED_STUFF_MAX_IPS:
                reason = (f"Credential stuffing: username '{username}' tried from "
                          f"{unique_ips} distinct IPs in {_CRED_STUFF_WINDOW}s")
                self._block(ip, "Credential Stuffing", reason, _STUFFING_BLOCK_TTL)
                return {"threat_type": "Credential Stuffing", "reason": reason}

        except Exception as e:
            logger.warning(f"ThreatDetector.record_login_attempt error: {e}")

        return None

    def check_impossible_travel(self, user_id: str, username: str,
                                 ip: str) -> Optional[dict]:
        """
        Detecta impossible travel comparando la IP actual con la última conocida.
        Llamar después de un login EXITOSO.

        Returns:
            dict con {threat_type, reason} si se detecta viaje imposible, None si limpio.
        """
        if not self.redis:
            return None

        try:
            key = _TRAVEL_KEY.format(user_id=user_id)
            stored = self.redis.get(key)

            if stored:
                data = json.loads(stored)
                last_ip = data.get("ip")
                last_time = data.get("ts", 0)
                elapsed = time.time() - last_time

                if last_ip and last_ip != ip and elapsed < _TRAVEL_WINDOW:
                    reason = (f"Impossible travel: user '{username}' logged in from "
                              f"{ip} only {int(elapsed)}s after login from {last_ip}")
                    self._block(ip, "Impossible Travel", reason, _TRAVEL_BLOCK_TTL)
                    logger.warning(f"🌍 {reason}")
                    # Actualizar registro con nueva IP
                    self.redis.set(key, json.dumps({"ip": ip, "ts": time.time()}),
                                   ex=_TRAVEL_WINDOW * 2)
                    return {"threat_type": "Impossible Travel", "reason": reason}

            # Guardar IP y timestamp del login exitoso
            self.redis.set(key, json.dumps({"ip": ip, "ts": time.time()}),
                           ex=_TRAVEL_WINDOW * 2)

        except Exception as e:
            logger.warning(f"ThreatDetector.check_impossible_travel error: {e}")

        return None

    # ──────────────────────────────────────────
    # Interno
    # ──────────────────────────────────────────

    def _block(self, ip: str, threat_type: str, reason: str, ttl: int):
        """Bloquea una IP via IPBlocker y persiste el evento en Redis."""
        logger.warning(f"🚫 Auto-block [{threat_type}] IP={ip} | {reason}")
        if self.ip_blocker:
            try:
                self.ip_blocker.block_ip(ip, duration=ttl, reason=f"[{threat_type}] {reason}", auto_blocked=True)
            except Exception as e:
                logger.error(f"ThreatDetector._block ip_blocker error: {e}")
        # Persistir en threat_events independientemente del whitelist
        if self.redis:
            try:
                self.redis.lpush('athenai:threat_events', json.dumps({
                    'ip': ip,
                    'threat_type': threat_type,
                    'reason': f'[{threat_type}] {reason}',
                    'blocked_at': datetime.now().isoformat(),
                    'auto_blocked': True,
                    'permanent': False,
                }))
                self.redis.ltrim('athenai:threat_events', 0, 999)
            except Exception as e:
                logger.error(f"ThreatDetector._block redis error: {e}")
