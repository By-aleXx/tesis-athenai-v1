"""
EJEMPLO: Integración de AthenAI en Django/Flask

Este middleware se puede usar en Django o Flask para proteger
tu aplicación web con AthenAI.

Arquitectura:
Cliente → Django/Flask → AthenAI Middleware → Verificación → Vista/Endpoint
"""

import requests
import time
from functools import wraps
from flask import Flask, request, jsonify, g

# ============================================
# CONFIGURACIÓN
# ============================================

ATHENAI_API_URL = 'http://localhost:5000'
ATHENAI_TOKEN = 'tu_jwt_token_aqui'  # Obtener desde /api/auth/login

# ============================================
# CLIENTE ATHENAI
# ============================================

class AthenAIClient:
    """Cliente para comunicarse con AthenAI"""
    
    def __init__(self, api_url, token):
        self.api_url = api_url.rstrip('/')
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        })
    
    def check_ip_blocked(self, ip):
        """Verifica si una IP está bloqueada"""
        try:
            response = self.session.get(
                f'{self.api_url}/api/blocked-ips',
                timeout=2
            )
            
            if response.ok:
                blocked_ips = response.json().get('blocked_ips', [])
                return ip in blocked_ips
            
            return False
            
        except Exception as e:
            print(f'Error verificando IP: {e}')
            return False  # Fail-open
    
    def check_rate_limit(self, ip):
        """Verifica rate limit para una IP"""
        try:
            response = self.session.get(
                f'{self.api_url}/api/rate-limit/check/{ip}',
                timeout=2
            )
            
            if response.ok:
                data = response.json()
                return data.get('allowed', True)
            
            return True  # Fail-open
            
        except Exception as e:
            print(f'Error verificando rate limit: {e}')
            return True
    
    def verify_request(self, request_data):
        """Verificación completa de seguridad"""
        try:
            response = self.session.post(
                f'{self.api_url}/api/security/verify',
                json=request_data,
                timeout=3
            )
            
            if response.ok:
                return response.json()
            
            return {'safe': True}  # Fail-open
            
        except Exception as e:
            print(f'Error en verificación completa: {e}')
            return {'safe': True}
    
    def log_request(self, log_data):
        """Envía log de request a AthenAI"""
        try:
            self.session.post(
                f'{self.api_url}/api/traffic/log',
                json=log_data,
                timeout=1
            )
        except Exception:
            pass  # Logging no debe fallar requests
    
    def get_stats(self):
        """Obtiene estadísticas de seguridad"""
        try:
            response = self.session.get(
                f'{self.api_url}/api/stats',
                timeout=5
            )
            
            if response.ok:
                return response.json()
            
            return None
            
        except Exception as e:
            print(f'Error obteniendo stats: {e}')
            return None

# Inicializar cliente global
athenai = AthenAIClient(ATHENAI_API_URL, ATHENAI_TOKEN)

# ============================================
# MIDDLEWARES FLASK
# ============================================

def get_client_ip():
    """Obtiene IP real del cliente"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def athenai_ip_blocker():
    """Middleware: bloquea IPs en lista negra"""
    ip = get_client_ip()
    
    if athenai.check_ip_blocked(ip):
        print(f'🚫 IP bloqueada intentó acceder: {ip}')
        return jsonify({
            'error': 'Forbidden',
            'message': 'Tu IP ha sido bloqueada por comportamiento sospechoso'
        }), 403

def athenai_rate_limiter():
    """Middleware: verifica rate limit"""
    ip = get_client_ip()
    
    if not athenai.check_rate_limit(ip):
        print(f'⚠️ Rate limit excedido: {ip}')
        return jsonify({
            'error': 'Too Many Requests',
            'message': 'Demasiadas peticiones. Intenta más tarde.'
        }), 429

def athenai_full_check():
    """Middleware: verificación completa ML"""
    ip = get_client_ip()
    
    request_data = {
        'ip': ip,
        'method': request.method,
        'path': request.path,
        'headers': dict(request.headers),
        'timestamp': time.time()
    }
    
    result = athenai.verify_request(request_data)
    
    if not result.get('safe', True):
        print(f'🚨 Amenaza detectada desde {ip}: {result.get("threat_type")}')
        return jsonify({
            'error': 'Forbidden',
            'message': 'Request bloqueado por sistema de seguridad',
            'threat_id': result.get('threat_id')
        }), 403

def athenai_logger():
    """Middleware: registra todas las requests en AthenAI"""
    # Registrar tiempo de inicio
    g.start_time = time.time()
    
    # Después de la respuesta
    @after_this_request
    def log_response(response):
        duration = (time.time() - g.start_time) * 1000  # ms
        
        log_data = {
            'ip': get_client_ip(),
            'method': request.method,
            'path': request.path,
            'status_code': response.status_code,
            'response_time': duration,
            'user_agent': request.headers.get('User-Agent'),
            'timestamp': time.time()
        }
        
        # Enviar log de forma asíncrona
        import threading
        threading.Thread(
            target=athenai.log_request,
            args=(log_data,),
            daemon=True
        ).start()
        
        return response

# ============================================
# DECORADORES PARA ENDPOINTS
# ============================================

def require_athenai_check(full_check=False):
    """
    Decorador para proteger endpoints específicos
    
    Uso:
        @app.route('/api/admin/users')
        @require_athenai_check(full_check=True)
        def admin_users():
            return {...}
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Verificar IP bloqueada
            result = athenai_ip_blocker()
            if result:
                return result
            
            # 2. Verificar rate limit
            result = athenai_rate_limiter()
            if result:
                return result
            
            # 3. Verificación completa (opcional)
            if full_check:
                result = athenai_full_check()
                if result:
                    return result
            
            # Request aprobado
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# ============================================
# EJEMPLO DE APLICACIÓN FLASK
# ============================================

app = Flask(__name__)

# Aplicar middleware a TODAS las requests
@app.before_request
def before_request_middleware():
    """Middlewares que se aplican a todo"""
    
    # IP Blocker (siempre)
    result = athenai_ip_blocker()
    if result:
        return result
    
    # Logger (opcional, descomentar para habilitar)
    # athenai_logger()

# Endpoint público (solo verifica IP)
@app.route('/api/public/status')
def public_status():
    return jsonify({
        'status': 'OK',
        'protected_by': 'AthenAI'
    })

# Endpoint con rate limit
@app.route('/api/users')
@require_athenai_check()
def get_users():
    return jsonify({
        'users': [
            {'id': 1, 'name': 'Juan'},
            {'id': 2, 'name': 'María'}
        ]
    })

# Endpoint crítico con verificación completa
@app.route('/api/admin/delete', methods=['POST'])
@require_athenai_check(full_check=True)
def admin_delete():
    return jsonify({
        'success': True,
        'message': 'Elemento eliminado'
    })

# Endpoint para ver estadísticas de AthenAI
@app.route('/api/athenai/stats')
def athenai_stats():
    stats = athenai.get_stats()
    
    if stats:
        return jsonify(stats)
    else:
        return jsonify({
            'error': 'No se pudieron obtener estadísticas'
        }), 500

# ============================================
# CLASE PARA DJANGO (opcional)
# ============================================

class AthenAIMiddleware:
    """
    Middleware para Django
    
    Agregar a settings.py:
    MIDDLEWARE = [
        ...
        'path.to.AthenAIMiddleware',
        ...
    ]
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        self.athenai = AthenAIClient(ATHENAI_API_URL, ATHENAI_TOKEN)
    
    def __call__(self, request):
        # Código ANTES de la vista
        
        # 1. Obtener IP
        ip = self.get_client_ip(request)
        
        # 2. Verificar IP bloqueada
        if self.athenai.check_ip_blocked(ip):
            from django.http import JsonResponse
            return JsonResponse({
                'error': 'IP bloqueada'
            }, status=403)
        
        # 3. Verificar rate limit (solo en rutas API)
        if request.path.startswith('/api/'):
            if not self.athenai.check_rate_limit(ip):
                from django.http import JsonResponse
                return JsonResponse({
                    'error': 'Rate limit excedido'
                }, status=429)
        
        # Procesar request
        start_time = time.time()
        response = self.get_response(request)
        duration = (time.time() - start_time) * 1000
        
        # Código DESPUÉS de la vista (logging)
        self.log_request(request, response, duration)
        
        return response
    
    def get_client_ip(self, request):
        """Obtiene IP del cliente"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR')
    
    def log_request(self, request, response, duration):
        """Registra request en AthenAI"""
        log_data = {
            'ip': self.get_client_ip(request),
            'method': request.method,
            'path': request.path,
            'status_code': response.status_code,
            'response_time': duration,
            'user_agent': request.META.get('HTTP_USER_AGENT'),
            'timestamp': time.time()
        }
        
        # Enviar de forma asíncrona
        import threading
        threading.Thread(
            target=self.athenai.log_request,
            args=(log_data,),
            daemon=True
        ).start()

# ============================================
# INICIAR APLICACIÓN
# ============================================

if __name__ == '__main__':
    print('🚀 Servidor Flask ejecutándose')
    print(f'🛡️ Protegido por AthenAI: {ATHENAI_API_URL}')
    
    # Verificar conexión
    try:
        response = requests.get(f'{ATHENAI_API_URL}/api/health')
        if response.ok:
            print('✅ AthenAI conectado exitosamente')
        else:
            print('⚠️ AthenAI respondió con error')
    except Exception as e:
        print(f'❌ No se pudo conectar con AthenAI: {e}')
    
    app.run(port=8080, debug=True)

"""
INSTRUCCIONES DE USO:

1. Instalar dependencias:
   pip install flask requests

2. Obtener token JWT de AthenAI:
   POST http://localhost:5000/api/auth/login
   Body: {"username": "admin", "password": "admin123"}
   
3. Copiar el token a la variable ATHENAI_TOKEN

4. Ejecutar:
   python ejemplo_middleware_python.py

5. Probar:
   curl http://localhost:8080/api/public/status
   curl http://localhost:8080/api/users
   curl http://localhost:8080/api/athenai/stats

PERSONALIZACIÓN:

- Comentar/descomentar middlewares según necesidad
- Ajustar timeout según latencia
- Cambiar fail-open a fail-closed si necesitas más seguridad
- Agregar más endpoints personalizados
"""
