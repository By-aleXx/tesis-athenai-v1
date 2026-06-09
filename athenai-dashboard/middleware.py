"""
AthenAI - Traffic Logging Middleware
Middleware Flask para interceptar y registrar todo el tráfico HTTP
con marcado especial para pruebas de seguridad autorizadas
"""

from flask import request, g, current_app
from functools import wraps
import json
import os
import time
from dotenv import load_dotenv
from database import save_traffic_log

load_dotenv()

# ========================================
# RUTAS IGNORADAS (No registrar en BD)
# ========================================
# Estas rutas de telemetría pura del dashboard hacen polling constante
# y llenarían la BD con ruido propio del sistema, no del tráfico externo.
# Nota: mantén esta lista lo más corta posible; solo rutas de auto-telemetría.
IGNORED_PATHS = [
    '/api/traffic-logs',          # Dashboard consultando sus propios logs
    '/api/traffic-stats',         # Dashboard consultando sus propias stats
    '/api/traffic',               # Dashboard consultando datos de gráficos
    '/api/health',                # Health checks de infraestructura
    '/api/system-health',         # Métricas de sistema (CPU/RAM)
    '/api/ab-testing/stats',      # Stats A/B testing (auto-polling)
    '/api/continuous-learning',   # Stats ML (auto-polling)
    '/api/ip-stats',              # Stats de IPs (auto-polling)
    '/api/auth/refresh',          # Token refresh silencioso
    '/api/cache-stats',           # Debug de caché
]

# IP del atacante autorizado para pruebas de seguridad (lee del .env)
AUTHORIZED_TEST_IP = os.getenv('AUTHORIZED_TEST_IP', '')


def get_client_ip():
    """
    Obtiene la IP real del cliente, solo confiando en X-Forwarded-For desde proxies conocidos.
    """
    trusted_proxies = {'127.0.0.1', '::1'}
    remote = request.remote_addr
    if remote in trusted_proxies:
        xff = request.headers.get('X-Forwarded-For', '')
        if xff:
            return xff.split(',')[0].strip()
        real_ip = request.headers.get('X-Real-IP', '')
        if real_ip:
            return real_ip
    return remote


def is_test_attack(ip):
    """
    Verifica si la IP corresponde al atacante autorizado
    
    Args:
        ip: IP a verificar
    
    Returns:
        bool: True si es una prueba de seguridad autorizada
    """
    return ip == AUTHORIZED_TEST_IP


def log_traffic():
    """
    Decorator para endpoints que deben registrar tráfico
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Ejecutar la función original primero
            response = f(*args, **kwargs)
            
            # Registrar el tráfico después (no bloquear la respuesta)
            try:
                _log_request(response)
            except Exception as e:
                print(f"⚠️ Error logging traffic: {e}")
            
            return response
        return decorated_function
    return decorator


def _log_request(response=None):
    """
    Registra la solicitud actual en la base de datos
    
    Args:
        response: Respuesta Flask (opcional)
    """
    try:
        # Obtener IP del cliente
        client_ip = get_client_ip()
        
        # Verificar si es un ataque de prueba
        is_test = is_test_attack(client_ip)
        
        # Extraer información de la solicitud
        method = request.method
        path = request.path
        query_params = request.query_string.decode('utf-8') if request.query_string else None
        user_agent = request.headers.get('User-Agent')
        content_type = request.headers.get('Content-Type')
        
        # Convertir headers a dict (excluyendo algunos sensibles)
        headers_dict = {}
        excluded_headers = ['Cookie', 'Authorization']  # No guardar credenciales
        for key, value in request.headers:
            if key not in excluded_headers:
                headers_dict[key] = value
        
        # Intentar obtener el body
        body = None
        try:
            if request.is_json:
                body = json.dumps(request.get_json())
            elif request.data:
                # Limitar tamaño del body para evitar problemas de memoria
                body_data = request.data.decode('utf-8', errors='ignore')
                if len(body_data) > 10000:  # Limitar a 10KB
                    body = body_data[:10000] + '... [TRUNCATED]'
                else:
                    body = body_data
        except Exception as e:
            body = f"[Error reading body: {str(e)}]"
        
        # Obtener código de respuesta si está disponible
        response_status = None
        if response:
            try:
                response_status = response.status_code
            except AttributeError:
                pass
        
        # Clasificar con ML si el engine está disponible
        risk_score = None
        ai_prediction = None
        try:
            brain = current_app.config.get('AI_BRAIN')
            if brain:
                payload = query_params or body or path or ''
                if payload:
                    label, confidence = brain.predict(payload)
                    ai_prediction = label
                    risk_score = float(confidence)
        except Exception as _ml_e:
            print(f"[middleware] ML prediction skipped: {_ml_e}")

        # Guardar en la base de datos
        save_traffic_log(
            source_ip=client_ip,
            method=method,
            path=path,
            headers=headers_dict,
            body=body,
            query_params=query_params,
            user_agent=user_agent,
            is_test_attack=is_test,
            content_type=content_type,
            content_length=request.content_length,
            risk_score=risk_score,
            ai_prediction=ai_prediction,
        )
        
    except Exception as e:
        print(f"❌ Error en _log_request: {e}")


class TrafficLoggingMiddleware:
    """
    Middleware Flask para registrar automáticamente todo el tráfico HTTP
    """
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """
        Inicializa el middleware con la aplicación Flask
        
        Args:
            app: Aplicación Flask
        """
        # Registrar before_request para capturar inicio de request
        app.before_request(self.before_request)
        
        # Registrar after_request para capturar respuesta
        app.after_request(self.after_request)
        
        print("✅ Traffic Logging Middleware activado")
        print(f"🎯 IP de pruebas autorizadas: {AUTHORIZED_TEST_IP}")
    
    def before_request(self):
        """
        Se ejecuta antes de cada request
        """
        # Guardar timestamp de inicio
        g.request_start_time = time.time()
        g.client_ip = get_client_ip()
    
    def after_request(self, response):
        """
        Se ejecuta después de cada request
        
        Args:
            response: Respuesta Flask
        
        Returns:
            response: La misma respuesta (sin modificar)
        """
        # Ignorar requests a archivos estáticos y health checks
        if request.path.startswith('/static/') or request.path == '/favicon.ico':
            return response

        # No registrar peticiones desde localhost (evita loops de self-request)
        _src_ip = getattr(g, 'client_ip', request.remote_addr) or ''
        if _src_ip in ('127.0.0.1', '::1', 'localhost') or _src_ip.startswith('192.168.') or _src_ip.startswith('10.'):
            return response

        # No registrar assets estáticos (html, js, css, etc.)
        _static_exts = ('.html', '.js', '.css', '.ico', '.png', '.svg', '.woff', '.woff2', '.ttf', '.map')
        if any(request.path.endswith(ext) for ext in _static_exts):
            return response
        
        # ========================================
        # FILTRAR RUTAS IGNORADAS (Dashboard polling)
        # ========================================
        # No registrar peticiones internas del dashboard
        if any(request.path.startswith(ignored_path) for ignored_path in IGNORED_PATHS):
            # Agregar header de tiempo de respuesta pero NO registrar en BD
            if hasattr(g, 'request_start_time'):
                elapsed = (time.time() - g.request_start_time) * 1000  # ms
                response.headers['X-Response-Time'] = f'{elapsed:.2f}ms'
            return response
        
        try:
            # Registrar el tráfico SOLO si no está en la lista de ignorados
            _log_request(response)
            
            # Calcular tiempo de respuesta
            if hasattr(g, 'request_start_time'):
                elapsed = (time.time() - g.request_start_time) * 1000  # ms
                
                # Agregar header con tiempo de respuesta
                response.headers['X-Response-Time'] = f'{elapsed:.2f}ms'
        
        except Exception as e:
            print(f"⚠️ Error en after_request middleware: {e}")
        
        return response
