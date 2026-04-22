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
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# Patrones de inyección
# ─────────────────────────────────────────────
_SQL_RE = re.compile(
    r"(?i)(\bselect\b.+\bfrom\b|\bunion\b.+\bselect\b|\binsert\b.+\binto\b"
    r"|\bdrop\b.+\btable\b|\bdelete\b.+\bfrom\b|\bupdate\b.+\bset\b"
    r"|--|;\s*--|'\s*or\s*'[^']*'\s*=\s*'|1\s*=\s*1|0\s*=\s*0"
    r"|\bexec\b\s*\(|\bexecute\b\s*\(|\bxp_cmdshell\b)"
)
_XSS_RE = re.compile(
    r"(?i)(<script[\s>]|</script>|javascript\s*:|onerror\s*=|onload\s*="
    r"|onclick\s*=|<img[^>]+src\s*=\s*['\"]?javascript|<svg[^>]+onload"
    r"|document\.cookie|alert\s*\(|eval\s*\()"
)
_CMD_RE = re.compile(
    r"(?i)(;?\s*\b(ls|cat|wget|curl|bash|sh|cmd|powershell)\b\s"
    r"|\|.*?\b(ls|cat|id|whoami|uname)\b"
    r"|`[^`]+`|\$\([^)]+\)"
    r"|\.\.\/\.\.\/|/etc/passwd|/etc/shadow|/proc/self)"
)

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
        text = " ".join(filter(None, [path, query_params or "", body or ""]))

        if _SQL_RE.search(text):
            threat = {"threat_type": "SQL Injection",
                      "reason": f"SQL pattern detected in {method} {path}"}
        elif _XSS_RE.search(text):
            threat = {"threat_type": "XSS",
                      "reason": f"XSS pattern detected in {method} {path}"}
        elif _CMD_RE.search(text):
            threat = {"threat_type": "Command Injection",
                      "reason": f"Command injection pattern in {method} {path}"}
        else:
            return None

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
        """Bloquea una IP via IPBlocker y loggea el evento."""
        logger.warning(f"🚫 Auto-block [{threat_type}] IP={ip} | {reason}")
        if self.ip_blocker:
            try:
                self.ip_blocker.block_ip(ip, duration=ttl, reason=f"[{threat_type}] {reason}", auto_blocked=True)
            except Exception as e:
                logger.error(f"ThreatDetector._block error: {e}")
