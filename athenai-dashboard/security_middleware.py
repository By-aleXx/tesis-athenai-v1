"""
AthenAI - Security Middleware

Middleware para aplicar IP Blocker y Rate Limiter automáticamente
a todas las peticiones HTTP.

Autor: AthenAI Team
Fecha: 2026-02-11 — Actualizado: 2026-03-17 (ML asíncrona)
"""

from flask import request, jsonify
from functools import wraps
import logging
import os
import uuid

# Importar predictor ML asíncrono
try:
    from ml_async_predictor import ml_predictor
    ML_ASYNC_AVAILABLE = True
except ImportError:
    ml_predictor = None
    ML_ASYNC_AVAILABLE = False

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityMiddleware:
    """
    Middleware de seguridad que aplica:
    - IP Blocking
    - Rate Limiting
    - Evidence logging
    """
    
    def __init__(self, app=None, ip_blocker=None, rate_limiter=None, evidence_store=None, mock_sagemaker=None, ai_engine=None):
        """
        Inicializa el middleware de seguridad.
        
        Args:
            app: Flask app
            ip_blocker: Instancia de IP Blocker
            rate_limiter: Instancia de Rate Limiter
            evidence_store: Instancia de Evidence Store
            mock_sagemaker: Instancia de Mock SageMaker para ML
            ai_engine: Instancia de AIEngine para predicciones ML
        """
        self.ip_blocker = ip_blocker
        self.rate_limiter = rate_limiter
        self.evidence_store = evidence_store
        self.mock_sagemaker = mock_sagemaker
        self.ai_engine = ai_engine

        # Threat Detector (injection, credential stuffing, impossible travel)
        try:
            from threat_detector import ThreatDetector
            redis_client = ip_blocker.redis_client if ip_blocker else None
            self.threat_detector = ThreatDetector(ip_blocker=ip_blocker, redis_client=redis_client)
            logger.info("🛡️  Threat Detector inicializado (injection + stuffing + travel)")
        except Exception as _td_err:
            self.threat_detector = None
            logger.warning(f"⚠️  Threat Detector no disponible: {_td_err}")

        # Predictor ML asíncrono (singleton global)
        self.ml_predictor = ml_predictor if ML_ASYNC_AVAILABLE else None

        # Tracking de tráfico por IP para ML
        import threading as _threading
        self.traffic_stats = {}  # {ip: {request_count, error_count, response_times, ...}}
        self._stats_lock = _threading.Lock()
        
        if ai_engine is not None and ML_ASYNC_AVAILABLE:
            logger.info("🤖 ML Detection asíncrona HABILITADA (ThreadPoolExecutor x4 workers)")
        elif ai_engine is None:
            logger.warning("⚠️  ML Detection DESHABILITADA: ai_engine=None")
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Registra el middleware en la app Flask"""
        app.before_request(self.check_security)
    
    def check_security(self):
        """
        Verifica seguridad antes de cada request.
        Scope: SOLO rutas /api/** (nunca assets, HTML, fuentes o health check).
        """
        path = request.path
        source_ip = request.remote_addr

        # WAF scope: only API endpoints — static assets, HTML pages and fonts are never analyzed
        if not path.startswith('/api/') or path == '/api/health':
            return None

        # Development bypass: localhost and private LAN ranges
        _LOCAL_IPS = {'127.0.0.1', '::1', 'localhost'}
        if source_ip in _LOCAL_IPS or (source_ip or '').startswith('192.168.') or (source_ip or '').startswith('10.'):
            return None
        
        # 1. Verificar IP Blocker
        if self.ip_blocker:
            try:
                if self.ip_blocker.is_blocked(source_ip):
                    block_info = self.ip_blocker.get_block_info(source_ip)
                    
                    incident_id = str(uuid.uuid4())[:8].upper()
                    logger.warning(f"🚫 IP bloqueada intentó acceder: {source_ip} → {path} | ID: {incident_id}")

                    if self.evidence_store:
                        try:
                            self.evidence_store.store_block_event({
                                'source_ip': source_ip, 'path': path,
                                'method': request.method, 'reason': 'blocked_ip_attempt',
                                'block_reason': block_info.get('reason', 'unknown'),
                                'incident_id': incident_id,
                            })
                        except Exception as e:
                            logger.error(f"Error logging blocked IP attempt: {e}")

                    return jsonify({
                        'error': 'Access Denied',
                        'message': 'Your IP address has been blocked',
                        'reason': block_info.get('reason', 'Security violation'),
                        'blocked_at': block_info.get('blocked_at'),
                        'expires_at': block_info.get('expires_at'),
                        'incident_id': incident_id,
                    }), 403
            except Exception as e:
                logger.error(f"Error checking IP blocker: {e}")
        
        # 2. Injection Detection (SQL, XSS, Command Injection)
        if self.threat_detector:
            try:
                query_params = request.query_string.decode('utf-8', errors='ignore')
                body = request.get_data(as_text=True)
                threat = self.threat_detector.inspect_request(
                    ip=source_ip,
                    method=request.method,
                    path=path,
                    query_params=query_params,
                    body=body[:2000] if body else ''
                )
                if threat:
                    logger.warning(f"🔴 {threat['threat_type']} bloqueado: {source_ip} → {path}")
                    return jsonify({
                        'error': 'Forbidden',
                        'message': f"{threat['threat_type']} detected and blocked",
                        'threat_type': threat['threat_type'],
                    }), 403
            except Exception as e:
                logger.error(f"Error en injection detection: {e}")

        # 3. ML Threat Detection — ASÍNCRONA (fire-and-forget por IP)
        # Estrategia:
        #   a) Comprobar si el análisis del request ANTERIOR de esta IP terminó con amenaza.
        #      Si es así → bloquear ahora (latencia: <1ms, solo dict lookup).
        #   b) Lanzar la predicción del request ACTUAL en background (no bloquea Flask).
        #      La predicción se almacena y se revisará en el próximo request de la IP.
        # Cache hit: <1ms | Cache miss: ~300ms (en background)
        if self.ai_engine and self.ml_predictor:
            try:
                # Construir payload para análisis ML
                ml_payload = f"{request.method} {path}"
                try:
                    body = request.get_data(as_text=True)
                    if body:
                        ml_payload += f" {body[:500]}"
                except Exception:
                    pass
                
                # Callback que se ejecuta cuando la predicción async termina
                ip_blocker_ref = self.ip_blocker
                evidence_store_ref = self.evidence_store
                ai_engine_ref = self.ai_engine

                def _on_prediction_done(label: str, confidence: float, detected_ip: str):
                    """Callback ejecutado en el thread del executor."""
                    confidence_decimal = confidence / 100.0
                    if label == 'malicious' and confidence_decimal >= 0.9:
                        logger.warning(
                            f"🤖 ML async: Amenaza detectada → {detected_ip} | "
                            f"Confianza: {confidence_decimal:.2%}"
                        )
                        # Bloquear IP directamente desde el thread del executor
                        if ip_blocker_ref:
                            try:
                                ip_blocker_ref.block_ip(
                                    detected_ip,
                                    duration=900,
                                    reason=f'ML Async Detection ({confidence_decimal:.2%})',
                                    auto_blocked=True
                                )
                            except Exception as be:
                                logger.error(f"Error blocking IP {detected_ip}: {be}")
                        # Log en Evidence Store
                        if evidence_store_ref:
                            try:
                                evidence_store_ref.store_block_event({
                                    'source_ip': detected_ip,
                                    'path': path,
                                    'method': request.method,
                                    'reason': 'ml_async_threat_detected',
                                    'confidence': confidence_decimal,
                                })
                            except Exception as ee:
                                logger.error(f"Error logging ML evidence: {ee}")
                        # Feedback de Continuous Learning
                        if ai_engine_ref:
                            try:
                                ai_engine_ref.provide_feedback(
                                    payload=ml_payload,
                                    true_label='malicious',
                                )
                            except Exception as fe:
                                logger.error(f"Error ML feedback: {fe}")
                
                # a) Comprobar resultado del request anterior + b) Lanzar análisis actual
                threat_result = self.ml_predictor.check_and_fire(
                    ai_engine=self.ai_engine,
                    ip=source_ip,
                    payload=ml_payload,
                    callback=_on_prediction_done,
                )
                
                if threat_result is not None:
                    # El análisis del request anterior determinó que esta IP es una amenaza
                    confidence_decimal = threat_result.confidence / 100.0
                    incident_id = str(uuid.uuid4())[:8].upper()
                    logger.warning(
                        f"🤖 ML: Bloqueando {source_ip} → {path} | "
                        f"Confianza previa: {confidence_decimal:.2%} | ID: {incident_id}"
                    )
                    # Devolver HTML si el cliente acepta HTML (navegador), JSON si no (API)
                    accept = request.headers.get('Accept', '')
                    if 'text/html' in accept:
                        from flask import make_response
                        html = f"""<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>Acceso bloqueado — AthenAI</title>
<style>
  body{{font-family:system-ui,sans-serif;background:#0f172a;color:#f1f5f9;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}
  .box{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:2.5rem;max-width:480px;text-align:center}}
  .icon{{font-size:3rem;margin-bottom:1rem}}
  h1{{color:#f87171;font-size:1.5rem;margin:0 0 .75rem}}
  p{{color:#94a3b8;line-height:1.6;margin:.5rem 0}}
  .badge{{display:inline-block;background:#1e3a5f;color:#93c5fd;font-family:monospace;font-size:.85rem;padding:.3rem .75rem;border-radius:6px;margin-top:1rem}}
  a{{color:#818cf8;text-decoration:none}}a:hover{{text-decoration:underline}}
</style></head>
<body><div class="box">
  <div class="icon">🛡️</div>
  <h1>Acceso bloqueado temporalmente</h1>
  <p>El sistema de detección de amenazas AthenAI identificó actividad sospechosa en tu dirección IP.</p>
  <p>El bloqueo se levantará automáticamente en <strong>1 hora</strong>.</p>
  <p>Si crees que es un error, contacta con soporte indicando el ID de incidente:</p>
  <div class="badge">Incidente: {incident_id}</div>
  <p style="margin-top:1.5rem"><a href="/">← Volver al inicio</a></p>
</div></body></html>"""
                        resp = make_response(html, 403)
                        resp.headers['Content-Type'] = 'text/html; charset=utf-8'
                        return resp
                    return jsonify({
                        'error': 'Threat Detected',
                        'message': 'Suspicious activity detected by ML model',
                        'confidence': f'{confidence_decimal:.2%}',
                        'blocked_duration': '15 minutes',
                        'incident_id': incident_id,
                    }), 403

            except Exception as e:
                logger.error(f"Error en ML threat detection async: {e}")
        
        # 3. Verificar Rate Limiter
        if self.rate_limiter:
            try:
                # Determinar tipo de límite según el path
                if path.startswith('/api/security'):
                    limit_type = 'security'
                elif path.startswith('/api/auth'):
                    limit_type = 'auth'
                elif path.startswith('/api'):
                    limit_type = 'api'
                else:
                    limit_type = 'global'
                
                is_allowed, info = self.rate_limiter.check_rate_limit(source_ip, limit_type)
                
                if not is_allowed:
                    logger.warning(
                        f"⏱️ Rate limit excedido: {source_ip} → {path} | "
                        f"Tipo: {limit_type} | Límite: {info.get('limit')}"
                    )
                    
                    # Log en Evidence Store
                    if self.evidence_store:
                        try:
                            evidence_data = {
                                'source_ip': source_ip,
                                'path': path,
                                'method': request.method,
                                'reason': 'rate_limit_exceeded',
                                'limit_type': limit_type,
                                'limit': info.get('limit'),
                                'window': info.get('window')
                            }
                            self.evidence_store.store_traffic_log(evidence_data)
                        except Exception as e:
                            logger.error(f"Error logging rate limit: {e}")
                    
                    return jsonify({
                        'error': 'Rate Limit Exceeded',
                        'message': f'Too many requests. Please try again later.',
                        'limit': info.get('limit'),
                        'window': info.get('window'),
                        'retry_after': info.get('retry_after', 60)
                    }), 429
            except Exception as e:
                logger.error(f"Error checking rate limiter: {e}")
        
        # Si pasa todas las verificaciones, continuar
        # 📚 CONTINUOUS LEARNING: Enviar feedback de request benigno
        # Solo enviar feedback ocasionalmente para no sobrecargar (1 de cada 10 requests)
        import random
        if random.random() < 0.1:  # 10% de probabilidad
            self._send_feedback_to_ai(
                payload=path,
                true_label='benign',
                confidence=0.7  # Confianza moderada (no tenemos certeza absoluta)
            )
        
        return None
    
    def _update_traffic_stats(self, ip):
        """Actualiza estadísticas de tráfico para una IP"""
        import time
        
        if ip not in self.traffic_stats:
            self.traffic_stats[ip] = {
                'request_count': 0,
                'error_count': 0,
                'response_times': [],
                'first_seen': time.time(),
                'last_seen': time.time()
            }
        
        stats = self.traffic_stats[ip]
        stats['request_count'] += 1
        stats['last_seen'] = time.time()
        
        # Limpiar stats viejos (más de 5 minutos)
        window = 300  # 5 minutos
        if time.time() - stats['first_seen'] > window:
            # Reset stats
            self.traffic_stats[ip] = {
                'request_count': 1,
                'error_count': 0,
                'response_times': [],
                'first_seen': time.time(),
                'last_seen': time.time()
            }
    
    def _get_traffic_features(self, ip):
        """
        Obtiene features de tráfico para ML.
        
        Returns:
            [request_count, error_rate, avg_response_time, unique_ips]
        """
        if ip not in self.traffic_stats:
            return None
        
        stats = self.traffic_stats[ip]
        
        request_count = stats['request_count']
        error_count = stats.get('error_count', 0)
        error_rate = error_count / request_count if request_count > 0 else 0.0
        
        response_times = stats.get('response_times', [])
        avg_response_time = sum(response_times) / len(response_times) if response_times else 100
        
        # unique_ips siempre es 1 para este contexto (estamos analizando una IP)
        unique_ips = 1
        
        return [request_count, error_rate, avg_response_time, unique_ips]
    
    def record_response(self, ip, status_code, response_time):
        """
        Registra la respuesta de una request para tracking.
        Debe ser llamado después de cada request.
        """
        if ip in self.traffic_stats:
            stats = self.traffic_stats[ip]
            
            # Registrar error si status >= 400
            if status_code >= 400:
                stats['error_count'] = stats.get('error_count', 0) + 1
            
            # Registrar response time
            if 'response_times' not in stats:
                stats['response_times'] = []
            stats['response_times'].append(response_time)
            
            # Mantener solo los últimos 100 response times
            if len(stats['response_times']) > 100:
                stats['response_times'] = stats['response_times'][-100:]
    
    def _send_feedback_to_ai(self, payload, true_label, confidence=1.0):
        """
        Envía feedback al AI Engine para continuous learning.
        
        Args:
            payload: Texto del request (query params, body, etc.)
            true_label: 'malicious' o 'benign'
            confidence: Confianza en la etiqueta (0.0-1.0)
        """
        if not self.ai_engine:
            return
        
        try:
            # Extraer payload del request
            if not payload:
                # Intentar construir payload desde el request actual
                query_params = request.args.to_dict()
                body = request.get_data(as_text=True) if request.method in ['POST', 'PUT'] else None
                
                payload_parts = []
                if query_params:
                    payload_parts.append(str(query_params))
                if body:
                    payload_parts.append(body)
                
                payload = ' '.join(payload_parts) if payload_parts else request.path
            
            # Enviar feedback
            self.ai_engine.provide_feedback(
                payload=payload,
                true_label=true_label,
                confidence=confidence
            )
            
            logger.debug(f"📚 Feedback sent to AI Engine: {true_label} (confidence: {confidence})")
        
        except Exception as e:
            logger.error(f"Error sending feedback to AI Engine: {e}")



def require_api_key(f):
    """
    Decorator para requerir API key en endpoints protegidos.
    Usa la variable de entorno VALID_API_KEYS (separadas por coma).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Obtener API key del header
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'API key required'
            }), 401
        
        # Cargar API keys válidas desde .env (VALID_API_KEYS=key1,key2,key3)
        valid_keys_str = os.environ.get('VALID_API_KEYS', '')
        valid_keys = [k.strip() for k in valid_keys_str.split(',') if k.strip()]
        
        if not valid_keys:
            logger.warning("⚠️  VALID_API_KEYS no configurado en .env")
        
        if api_key not in valid_keys:
            return jsonify({
                'error': 'Unauthorized',
                'message': 'Invalid API key'
            }), 401
        
        return f(*args, **kwargs)
    
    return decorated_function


if __name__ == "__main__":
    print("=" * 80)
    print("ATHENAI SECURITY MIDDLEWARE")
    print("=" * 80)
    print("\nEste módulo proporciona:")
    print("  1. IP Blocking automático")
    print("  2. Rate Limiting por tipo de endpoint")
    print("  3. Evidence logging de eventos de seguridad")
    print("  4. API key authentication decorator")
    print("\nUso:")
    print("  from security_middleware import SecurityMiddleware")
    print("  security_middleware = SecurityMiddleware(app, ip_blocker, rate_limiter, evidence_store)")
    print("=" * 80)
