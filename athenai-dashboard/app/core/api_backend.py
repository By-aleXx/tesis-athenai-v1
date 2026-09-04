"""
AthenAI - API Backend
Flask REST API para servir datos del dashboard

Endpoints:
- GET /api/stats - Estadísticas generales (KPIs)
- GET /api/traffic - Datos de tráfico para gráfico
- GET /api/attacks - Tipos de ataques para gráfico
- GET /api/alerts - Alertas recientes
- GET /api/health - Estado del sistema
"""

from flask import Flask, jsonify, request, g
from flask_cors import CORS
from flask_compress import Compress
from flasgger import Swagger
import boto3
from datetime import datetime, timedelta
import random
import json
import os
import re
import time
import hmac
import secrets
from pathlib import Path
from dotenv import load_dotenv

# Cargar variables de entorno desde .env al inicio
load_dotenv()


def _safe_parse_date(s):
    """Safely parse an ISO date string, returning None on any error."""
    try:
        return datetime.fromisoformat(s).date() if s else None
    except (ValueError, TypeError):
        return None


# Importar middleware y base de datos
from app.security.middleware import TrafficLoggingMiddleware
from app.core.database import init_db, get_traffic_logs, get_traffic_stats

# Importar validadores de entrada
from app.auth.validators import (
    validate_json,
    LoginSchema, RegisterSchema, RefreshTokenSchema,
    BlockIPSchema, WhitelistSchema,
    TrafficSplitSchema, PolicyThresholdSchema,
    AlertsQuerySchema,
    AnalyzeRequestSchema, MLPredictSchema,
)

# Importar AI Engine para predicciones ML
try:
    from app.ml.ai_engine import brain
    print("🧠 AI Engine cargado exitosamente")
except Exception as e:
    print(f"⚠️  No se pudo cargar AI Engine: {e}")
    brain = None

# app/core -> app -> athenai-dashboard (donde viven los HTML/assets y la config)
_DASHBOARD_ROOT = Path(__file__).resolve().parents[2]
# app/core -> app -> athenai-dashboard -> raíz del repo (donde vive training/)
_REPO_ROOT = _DASHBOARD_ROOT.parent

# Cargar threshold calibrado desde resultados de entrenamiento
_THRESHOLD_FILE = _REPO_ROOT / 'training' / 'results' / 'threshold_calibration.json'
if _THRESHOLD_FILE.exists() and brain:
    try:
        with open(_THRESHOLD_FILE) as _f:
            _cal = json.load(_f)
        _threshold = _cal.get('optimal_threshold') or _cal.get('threshold')
        if _threshold is not None:
            brain.threshold = float(_threshold)
            print(f"Threshold calibrado cargado: {_threshold:.4f}")
    except Exception as _e:
        print(f"No se pudo cargar threshold calibrado: {_e}")

# Importar Policy Engine y Response Actions
try:
    from app.security.policy_engine import policy_engine, PolicyAction
    from app.security.response_actions import response_actions
    print("⚖️ Policy Engine y Response Actions cargados exitosamente")
except Exception as e:
    print(f"⚠️  No se pudo cargar Policy/Response: {e}")
    policy_engine = None
    response_actions = None

# Importar IP Blocker, Rate Limiter y Alert System
ip_blocker = None
rate_limiter = None
alert_system = None
try:
    from app.security.ip_blocker import ip_blocker
    from app.security.rate_limiter import rate_limiter
    from app.notifications.alert_system import alert_system
    print("🔒 IP Blocker, Rate Limiter y Alert System cargados exitosamente")
except Exception as e:
    print(f"⚠️  No se pudieron cargar componentes de seguridad: {e}")

# Importar IAM Manager para control de acceso
try:
    from app.auth.iam_manager import iam_manager, require_permission, Permission
    print("🔐 IAM Manager cargado exitosamente")
except Exception as e:
    print(f"⚠️  No se pudo cargar IAM Manager: {e}")
    iam_manager = None
    def require_permission(perm):
        def decorator(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                return jsonify({'error': 'Authentication service unavailable'}), 503
            return wrapped
        return decorator

# Importar Evidence Store, DynamoDB Client y Secrets Manager
try:
    from app.aws.evidence_store import evidence_store
    from app.aws.dynamodb_client import dynamodb_client
    from app.aws.secrets_manager import secrets_manager
    print("📦 Evidence Store, DynamoDB Client y Secrets Manager cargados exitosamente")
except Exception as e:
    print(f"⚠️  No se pudieron cargar componentes de almacenamiento: {e}")
    evidence_store = None
    dynamodb_client = None
    secrets_manager = None

# Importar Mock SageMaker para ML Pipeline
try:
    from app.ml.mock_sagemaker import mock_sagemaker
    print("🤖 Mock SageMaker cargado exitosamente")
except Exception as e:
    print(f"⚠️  No se pudo cargar Mock SageMaker: {e}")
    mock_sagemaker = None

# Importar Auth Service para autenticación JWT
try:
    from app.auth.auth_service import AuthService, require_auth, require_role
    auth_service = AuthService()
    print("🔐 Auth Service cargado exitosamente (usuario admin creado)")
except Exception as e:
    print(f"⚠️  No se pudo cargar Auth Service: {e}")
    auth_service = None

    def require_auth(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            return jsonify({'error': 'Authentication service unavailable'}), 503
        return wrapped

    def require_role(*roles):
        def decorator(f):
            @wraps(f)
            def wrapped(*args, **kwargs):
                return jsonify({'error': 'Authentication service unavailable'}), 503
            return wrapped
        return decorator

# Importar CloudWatch Logger y Metrics Collector
try:
    from app.aws.cloudwatch_logger import cloudwatch_logger
    from app.aws.metrics_collector import metrics_collector
    print("📊 CloudWatch Logger y Metrics Collector cargados exitosamente")
except Exception as e:
    print(f"⚠️  No se pudo cargar CloudWatch: {e}")
    cloudwatch_logger = None
    metrics_collector = None

# Importar System Health Monitor
try:
    from app.core.system_health import system_health_monitor
    print("🏥 System Health Monitor cargado exitosamente")
except Exception as e:
    print(f"⚠️  No se pudo cargar System Health Monitor: {e}")
    system_health_monitor = None

# static_folder=None: deshabilita la ruta /static automática de Flask (que resuelve
# relativa al paquete del módulo, app/core/, y ya no coincide con athenai-dashboard/static/).
# La ruta /static/<path:path> definida más abajo sirve ese contenido explícitamente.
app = Flask(__name__, static_folder=None)
# V-04: CORS restringido a los orígenes definidos en variable de entorno.
# supports_credentials=False (default explícito) — ningún origen puede enviar cookies
# de sesión cruzada; vary_header=True asegura que Vary: Origin se emite siempre.
cors_origins = os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',')
CORS(app, origins=cors_origins, supports_credentials=False, vary_header=True)

# V-08: solo confiar en X-Forwarded-For si hay un proxy de confianza delante.
# TRUSTED_PROXY_HOPS=0 (default) → ignora XFF, usa socket peer siempre.
# TRUSTED_PROXY_HOPS=1 → Nginx/ALB en frente; ProxyFix reescribe remote_addr.
TRUSTED_PROXY_HOPS = int(os.getenv('TRUSTED_PROXY_HOPS', '0'))
if TRUSTED_PROXY_HOPS > 0:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXY_HOPS, x_proto=1, x_host=1)

def _client_ip() -> str:
    """IP real del cliente, inmune a spoofing de X-Forwarded-For."""
    if TRUSTED_PROXY_HOPS > 0:
        return request.remote_addr  # ProxyFix ya lo normalizó
    return request.environ.get('REMOTE_ADDR', '0.0.0.0')

# V-NEW-01: hash dummy pre-computado para igualar el coste de bcrypt
# cuando el usuario no existe (evita timing oracle por early-return).
import bcrypt as _bcrypt_mod
_DUMMY_BCRYPT_HASH = _bcrypt_mod.hashpw(secrets.token_bytes(32), _bcrypt_mod.gensalt(rounds=12))

# Swagger / OpenAPI Documentation → http://localhost:5000/apidocs/
try:
    from app.core.swagger_config import SWAGGER_CONFIG, SWAGGER_TEMPLATE
    swagger = Swagger(app, config=SWAGGER_CONFIG, template=SWAGGER_TEMPLATE)
    print("📖 Swagger UI disponible en: http://localhost:5000/apidocs/")
except Exception as e:
    print(f"⚠️  No se pudo iniciar Swagger: {e}")
    swagger = None

# Configurar Auth Service en app context
if auth_service:
    app.config['AUTH_SERVICE'] = auth_service

# Exponer Redis para JWT blacklist (reutiliza la conexión del ip_blocker)
if ip_blocker and getattr(ip_blocker, 'redis_client', None):
    app.config['REDIS_CLIENT'] = ip_blocker.redis_client

# Configurar CloudWatch en app context
if cloudwatch_logger:
    app.config['CLOUDWATCH_LOGGER'] = cloudwatch_logger
if metrics_collector:
    app.config['METRICS_COLLECTOR'] = metrics_collector

# Inicializar base de datos
init_db()

# Registrar Traffic Logging Middleware (registra TODO el tráfico en la BD)
traffic_logger = TrafficLoggingMiddleware(app)

# Exponer AI Brain al middleware via app.config
app.config['AI_BRAIN'] = brain

# Registrar Security Middleware con ML Detection asíncrona
try:
    from app.security.security_middleware import SecurityMiddleware
    security_mw = SecurityMiddleware(
        app=app,
        ip_blocker=ip_blocker,
        rate_limiter=rate_limiter,
        evidence_store=evidence_store,
        ai_engine=brain,   # AI Engine para ML Detection asíncrona
    )
    print("🔒 Security Middleware con ML Detection asíncrona activado")
except Exception as e:
    print(f"⚠️  No se pudo activar Security Middleware: {e}")
    security_mw = None

# ============================================
# PERFORMANCE OPTIMIZATIONS
# ============================================

# Gzip Compression (70% bandwidth reduction)
# V-16: excluir endpoints de auth para evitar BREACH (compresión + secretos en respuesta)
_AUTH_PATHS_NO_COMPRESS = {
    '/api/auth/login', '/api/auth/refresh', '/api/auth/me', '/api/auth/register'
}
compress = Compress()
compress.init_app(app)
app.config['COMPRESS_MIMETYPES'] = [
    'text/html', 'text/css', 'text/plain',
    'application/json', 'application/javascript',
    'text/xml', 'application/xml'
]
app.config['COMPRESS_LEVEL'] = 6
app.config['COMPRESS_MIN_SIZE'] = 500

@app.after_request
def _disable_compress_on_auth(response):
    """V-16: desactivar compresión en endpoints que devuelven tokens JWT."""
    if request.path in _AUTH_PATHS_NO_COMPRESS:
        response.headers['Cache-Control'] = 'no-store'
        response.direct_passthrough = False
        response.headers.pop('Content-Encoding', None)
    return response

# Performance monitoring middleware
@app.before_request
def before_request():
    """Track request start time"""
    g.start_time = time.time()

@app.after_request
def after_request(response):
    """Performance headers, cache headers y security headers."""
    # Tiempo de respuesta
    if hasattr(g, 'start_time'):
        elapsed = time.time() - g.start_time
        response.headers['X-Response-Time'] = f"{elapsed * 1000:.2f}ms"
        if elapsed > 0.5:
            app.logger.warning(f"Slow request: {request.method} {request.path} took {elapsed:.2f}s")

    # Cache headers — NUNCA cachear errores (un 403 cacheado rompe assets permanentemente)
    _path = request.path
    _static = _path.endswith(('.css', '.js', '.png', '.jpg', '.ico', '.svg', '.woff', '.woff2', '.ttf'))
    if response.status_code >= 400:
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Pragma'] = 'no-cache'
    elif response.status_code < 300 and _static:
        response.headers['Cache-Control'] = 'public, max-age=3600'
    elif _path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

    # V-02: security headers en todas las respuestas
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'no-referrer')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    response.headers.setdefault('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload')
    if response.mimetype == 'text/html':
        response.headers.setdefault(
            'Content-Security-Policy',
            # cdn.tailwindcss.com y fonts.googleapis.com son dependencias CDN explícitas.
            # Para producción: compilar Tailwind localmente y eliminar estas excepciones.
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'none'"
        )
    # Eliminar banner del framework
    response.headers.pop('Server', None)

    return response

# ============================================
# RUTAS PARA SERVIR FRONTEND
# ============================================

@app.route('/')
def index():
    """Serve landing page"""
    from flask import send_file
    return send_file(_DASHBOARD_ROOT / 'landing.html')

@app.route('/landing.html')
def landing_page():
    """Serve landing page"""
    from flask import send_file
    return send_file(_DASHBOARD_ROOT / 'landing.html')

@app.route('/login.html')
def login_page():
    """Serve login page"""
    from flask import send_file
    return send_file(_DASHBOARD_ROOT / 'login.html')

@app.route('/index.html')
def dashboard_page():
    """Serve dashboard page"""
    from flask import send_file
    return send_file(_DASHBOARD_ROOT / 'index.html')

@app.route('/auth.js')
def auth_js():
    """Serve auth service"""
    from flask import send_file
    return send_file(_DASHBOARD_ROOT / 'auth.js', mimetype='application/javascript')

@app.route('/assets/<path:path>')
def serve_assets(path):
    """Serve static assets; 403 for directory traversal attempts"""
    from flask import send_from_directory
    import os as _os
    full = _os.path.join(str(_DASHBOARD_ROOT / 'assets'), path)
    if _os.path.isdir(full) or path.endswith('/'):
        return jsonify({'error': 'Forbidden'}), 403
    return send_from_directory(_DASHBOARD_ROOT / 'assets', path)

@app.route('/static/<path:path>')
def serve_static(path):
    """Serve locally-bundled static files (tailwind, etc.)"""
    from flask import send_from_directory
    import os as _os
    if path.endswith('/'):
        return jsonify({'error': 'Forbidden'}), 403
    return send_from_directory(_DASHBOARD_ROOT / 'static', path)

# Activar middleware de logging de tráfico (DESHABILITADO TEMPORALMENTE)
# traffic_middleware = TrafficLoggingMiddleware(app)  # CAUSA ~700ms DE LATENCIA POR SYNC DB I/O

# ============================================
# WHATSAPP NOTIFICATION ENDPOINTS
# ============================================

try:
    from app.notifications.whatsapp_notifier import get_status as _wa_status, get_qr as _wa_qr, \
        send_message as _wa_send, send_security_alert as _wa_alert, notify_all as _wa_notify_all
    _WA_AVAILABLE = True
except ImportError:
    _WA_AVAILABLE = False

# Números configurados para recibir alertas (persistidos en Redis)
_WA_NUMBERS_KEY = 'athenai:whatsapp:alert_numbers'


def _get_alert_numbers() -> list:
    try:
        rc = ip_blocker.redis_client if ip_blocker else None
        if rc:
            return list(rc.smembers(_WA_NUMBERS_KEY))
        return []
    except Exception:
        return []


@app.route('/api/whatsapp/status', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def whatsapp_status():
    if not _WA_AVAILABLE:
        return jsonify({'available': False, 'error': 'Módulo no disponible'})
    status = _wa_status()
    status['available'] = True
    status['alert_numbers'] = _get_alert_numbers()
    return jsonify(status)


@app.route('/api/whatsapp/qr', methods=['GET'])
@require_auth
@require_role('admin')
def whatsapp_qr():
    if not _WA_AVAILABLE:
        return jsonify({'error': 'Módulo no disponible'}), 503
    return jsonify(_wa_qr())


@app.route('/api/whatsapp/numbers', methods=['GET'])
@require_auth
@require_role('admin', 'analyst')
def whatsapp_get_numbers():
    return jsonify({'numbers': _get_alert_numbers()})


@app.route('/api/whatsapp/numbers', methods=['POST'])
@require_auth
@require_role('admin')
def whatsapp_add_number():
    data = request.get_json() or {}
    number = str(data.get('number', '')).strip().replace('+', '').replace(' ', '')
    if not number.isdigit() or len(number) < 10:
        return jsonify({'error': 'Número inválido — usa formato internacional sin + (ej: 521234567890)'}), 400
    try:
        rc = ip_blocker.redis_client if ip_blocker else None
        if rc:
            rc.sadd(_WA_NUMBERS_KEY, number)
        return jsonify({'success': True, 'number': number, 'numbers': _get_alert_numbers()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/whatsapp/numbers/<number>', methods=['DELETE'])
@require_auth
@require_role('admin')
def whatsapp_remove_number(number):
    number = number.replace('+', '').replace(' ', '')
    try:
        rc = ip_blocker.redis_client if ip_blocker else None
        if rc:
            rc.srem(_WA_NUMBERS_KEY, number)
        return jsonify({'success': True, 'numbers': _get_alert_numbers()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/whatsapp/test', methods=['POST'])
@require_auth
@require_role('admin')
def whatsapp_test():
    if not _WA_AVAILABLE:
        return jsonify({'error': 'Módulo no disponible'}), 503
    data = request.get_json() or {}
    number = str(data.get('number', '')).strip().replace('+', '').replace(' ', '')
    if not number:
        return jsonify({'error': 'Se requiere number'}), 400
    try:
        result = _wa_send(number, '✅ *AthenAI WAF* — Mensaje de prueba\n\nSistema de alertas configurado correctamente.')
        return jsonify({'success': True, 'result': result})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# EMAIL NOTIFICATION ENDPOINTS (Resend)
# ============================================

try:
    from app.notifications.email_notifier import (
        is_available as _email_available,
        get_alert_emails as _get_alert_emails,
        send_test_email as _send_test_email,
        notify_all_emails as _notify_all_emails,
        get_from_address as _get_email_from,
    )
    _EMAIL_AVAILABLE = _email_available()
except ImportError:
    _EMAIL_AVAILABLE = False


@app.route('/api/email/status', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def email_status():
    import os
    configured = bool(os.getenv('RESEND_API_KEY', ''))
    recipients = _get_alert_emails() if _EMAIL_AVAILABLE else []
    return jsonify({
        'available': _EMAIL_AVAILABLE,
        'configured': configured,
        'from': _get_email_from() if _EMAIL_AVAILABLE else None,
        'recipients': recipients,
    })


@app.route('/api/email/recipients', methods=['GET'])
@require_auth
@require_role('admin', 'analyst')
def email_get_recipients():
    return jsonify({'recipients': _get_alert_emails() if _EMAIL_AVAILABLE else []})


@app.route('/api/email/recipients', methods=['POST'])
@require_auth
@require_role('admin')
def email_add_recipient():
    import os, re
    data = request.get_json() or {}
    email = str(data.get('email', '')).strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
        return jsonify({'error': 'Email inválido'}), 400
    current = _get_alert_emails() if _EMAIL_AVAILABLE else []
    if email in current:
        return jsonify({'recipients': current, 'message': 'Ya estaba en la lista'})
    current.append(email)
    os.environ['RESEND_ALERT_EMAIL'] = ','.join(current)
    # Persistir en .env
    try:
        env_path = os.path.join(str(_DASHBOARD_ROOT), '.env')
        with open(env_path, 'r', encoding='utf-8') as f:
            content = f.read()
        import re as _re
        if 'RESEND_ALERT_EMAIL' in content:
            content = _re.sub(r'RESEND_ALERT_EMAIL=.*', f'RESEND_ALERT_EMAIL={",".join(current)}', content)
        else:
            content += f'\nRESEND_ALERT_EMAIL={",".join(current)}\n'
        with open(env_path, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception as _e:
        app.logger.warning(f'No se pudo persistir RESEND_ALERT_EMAIL: {_e}')
    return jsonify({'success': True, 'recipients': current})


@app.route('/api/email/recipients/<path:email>', methods=['DELETE'])
@require_auth
@require_role('admin')
def email_remove_recipient(email):
    import os, re as _re
    email = email.strip().lower()
    current = _get_alert_emails() if _EMAIL_AVAILABLE else []
    updated = [e for e in current if e != email]
    os.environ['RESEND_ALERT_EMAIL'] = ','.join(updated)
    try:
        env_path = os.path.join(str(_DASHBOARD_ROOT), '.env')
        with open(env_path, 'r', encoding='utf-8') as f:
            content = f.read()
        content = _re.sub(r'RESEND_ALERT_EMAIL=.*', f'RESEND_ALERT_EMAIL={",".join(updated)}', content)
        with open(env_path, 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception as _e:
        app.logger.warning(f'No se pudo persistir RESEND_ALERT_EMAIL: {_e}')
    return jsonify({'success': True, 'recipients': updated})


@app.route('/api/email/test', methods=['POST'])
@require_auth
@require_role('admin')
def email_test():
    if not _EMAIL_AVAILABLE:
        return jsonify({'error': 'Resend no disponible. Verifica RESEND_API_KEY en .env'}), 503
    data = request.get_json() or {}
    to = str(data.get('email', '')).strip()
    if not to:
        return jsonify({'error': 'Se requiere email'}), 400
    result = _send_test_email(to)
    return jsonify(result), (200 if result.get('success') else 502)


# ============================================
# AUTHENTICATION ENDPOINTS
# ============================================

# Las rutas /api/auth/* están registradas por auth_service más abajo (líneas ~1150+)
# auth.py legacy fue desactivado — auth_service.py es el único sistema de auth



# Activar Observability Middleware (CloudWatch Logs + Metrics)
try:
    from app.security.observability_middleware import ObservabilityMiddleware
    observability_middleware = ObservabilityMiddleware(
        app=app,
        cloudwatch_logger=cloudwatch_logger,
        metrics_collector=metrics_collector
    )
    print("✅ Observability Middleware activado (CloudWatch Logs + Metrics)")
except Exception as e:
    print(f"⚠️  No se pudo activar Observability Middleware: {e}")
    observability_middleware = None

# Configuración
S3_BUCKET = 'athenai-alertas'
USE_LOCALSTACK = os.getenv('USE_LOCALSTACK', 'true').lower() == 'true'

# Cliente S3
if USE_LOCALSTACK:
    s3_client = boto3.client(
        's3',
        endpoint_url=os.getenv('AWS_ENDPOINT_URL', 'http://localhost:4566'),
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID', 'test'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY', 'test'),
        region_name=os.getenv('AWS_REGION', 'us-east-1')
    )
else:
    s3_client = boto3.client('s3')

# Estado S3 cacheado al arrancar (evita llamadas de red en cada health check)
try:
    import botocore.config as _bc_s3
    _s3_probe = boto3.client(
        's3',
        endpoint_url=s3_client.meta.endpoint_url,
        region_name=s3_client.meta.region_name,
        config=_bc_s3.Config(connect_timeout=1, read_timeout=1, retries={'max_attempts': 0})
    )
    _s3_probe.list_buckets()
    _s3_available = True
except Exception:
    _s3_available = False


def get_alerts_from_s3():
    """Obtiene alertas reales de S3"""
    try:
        # Listar objetos en S3
        response = s3_client.list_objects_v2(
            Bucket=S3_BUCKET,
            Prefix='alerts/',
            MaxKeys=50
        )
        
        alerts = []
        if 'Contents' in response:
            # Obtener las últimas 10 alertas
            for obj in sorted(response['Contents'], key=lambda x: x['LastModified'], reverse=True)[:10]:
                try:
                    # Descargar alerta
                    alert_obj = s3_client.get_object(Bucket=S3_BUCKET, Key=obj['Key'])
                    alert_data = json.loads(alert_obj['Body'].read())
                    
                    # Formatear para el frontend
                    alerts.append({
                        'id': alert_data.get('alert_id', 'unknown'),
                        'time': alert_data.get('timestamp', '').split('T')[1][:8] if 'T' in alert_data.get('timestamp', '') else 'N/A',
                        'type': alert_data.get('attack_classification', alert_data.get('alert_type', 'Unknown')),
                        'severity': alert_data.get('severity', 'medium').lower(),
                        'ip': alert_data.get('source', {}).get('ip_address', 'unknown'),
                        'status': 'blocked' if alert_data.get('severity') == 'HIGH' else 'monitoring'
                    })
                except Exception as e:
                    print(f"Error procesando alerta: {e}")
                    continue
        
        return alerts
    except Exception as e:
        print(f"Error obteniendo alertas de S3: {e}")
        return []



@app.route('/api/home', methods=['GET'])
def get_home():
    """
    Información general del sistema
    ---
    tags:
      - System
    summary: Estado general y servicios activos
    responses:
      200:
        description: Estado operacional del backend
        schema:
          type: object
          properties:
            status:
              type: string
              example: operational
            version:
              type: string
              example: 1.0.0
            services:
              type: object
    """
    """Endpoint de inicio - información general del sistema"""
    try:
        return jsonify({
            'status': 'operational',
            'message': 'AthenAI IDS Backend Running',
            'version': '1.0.0',
            'timestamp': datetime.now().isoformat(),
            'services': {
                'ai_engine': brain is not None,
                'auth': auth_service is not None,
                'database': True,
                'redis': ip_blocker is not None and rate_limiter is not None
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health', methods=['GET'])
def get_health():
    """Health check mínimo público — no expone detalles internos (V-J)."""
    return jsonify({'status': 'ok'}), 200


@app.route('/api/health/full', methods=['GET'])
@require_auth
@require_role('admin')
def get_health_full():
    """Health check completo — solo accesible para administradores."""
    services = {
        'ai_engine':    brain is not None,
        'auth':         auth_service is not None,
        'database':     True,
        'redis':        ip_blocker is not None and rate_limiter is not None,
        'policy_engine': policy_engine is not None,
        's3':           _s3_available,
    }
    overall = 'healthy' if services['database'] else 'unhealthy'
    return jsonify({
        'status': overall,
        'timestamp': datetime.now().isoformat(),
        'services': services,
    }), 200


@app.route('/api/model-info', methods=['GET'])
@require_auth
@require_role('admin', 'analyst')
def get_model_info():
    """
    Información de los modelos ML cargados
    ---
    tags:
      - System
    summary: Retorna información sobre los modelos de ML (XGBoost + Isolation Forest)
    responses:
      200:
        description: Información de los modelos
        schema:
          type: object
          properties:
            xgboost:
              type: object
            isolation_forest:
              type: object
    """
    import os

    xgboost_path = os.path.join(str(_DASHBOARD_ROOT), 'models', 'xgboost.pkl')
    isolation_forest_path = os.path.join(str(_DASHBOARD_ROOT), 'models', 'isolation_forest.pkl')

    xgboost_info = {
        'available': os.path.exists(xgboost_path),
        'loaded': brain is not None,
        'task': 'SQL Injection & XSS Detection',
        'accuracy': '99.96%',
        'type': 'XGBoost (Gradient Boosting)'
    }

    isolation_forest_info = {
        'available': os.path.exists(isolation_forest_path),
        'task': 'Anomaly / Outlier Detection',
        'type': 'Isolation Forest'
    }

    if brain is not None:
        try:
            model_details = brain.get_model_info()
            xgboost_info.update({
                'precision': model_details.get('precision'),
                'recall': model_details.get('recall'),
                'continuous_learning': model_details.get('continuous_learning', False)
            })
        except Exception:
            pass

    return jsonify({
        'xgboost': xgboost_info,
        'isolation_forest': isolation_forest_info,
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/stats', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_stats():
    """Estadísticas generales del sistema"""
    # Contar amenazas de hoy desde Redis threat_events (fuente autoritativa)
    today_threats = 0
    try:
        _rc = getattr(ip_blocker, 'redis_client', None) if ip_blocker else None
        if _rc is None:
            _rc = current_app.config.get('REDIS_CLIENT')
        if _rc:
            from datetime import date as _date
            today_prefix = _date.today().isoformat()
            all_events = _rc.lrange('athenai:threat_events', 0, -1)
            today_threats = sum(
                1 for e in all_events
                if json.loads(e).get('blocked_at', '').startswith(today_prefix)
            )
    except Exception:
        alerts = get_alerts_from_s3()
        today_threats = len(alerts)

    cache_data = {}
    if brain:
        cache_stats = brain.cache_stats
        total_predictions = cache_stats['hits'] + cache_stats['misses']
        hit_rate = (cache_stats['hits'] / max(1, total_predictions)) * 100
        cache_data = {
            'cache_hits': cache_stats['hits'],
            'cache_misses': cache_stats['misses'],
            'cache_hit_rate': round(hit_rate, 1),
            'cache_size': len(brain.prediction_cache)
        }

    # Calcular block_rate: (eventos Redis / total requests SQLite) * 100
    block_rate = None
    try:
        _rc = getattr(ip_blocker, 'redis_client', None) if ip_blocker else None
        if _rc is None:
            _rc = app.config.get('REDIS_CLIENT')
        if _rc:
            all_events = _rc.lrange('athenai:threat_events', 0, -1)
            total_events = len(all_events)
            if total_events > 0:
                try:
                    from app.core.database import SessionLocal as _SL
                    from app.core.models import TrafficLog as _TLog
                    _db = _SL()
                    try:
                        total_requests = _db.query(_TLog).count()
                    finally:
                        _db.close()
                    if total_requests > 0:
                        block_rate = round(min((total_events / total_requests) * 100, 100.0), 1)
                    else:
                        block_rate = 100.0
                except Exception:
                    pass
    except Exception:
        pass

    stats = {
        'threats_today': today_threats,
        'threats_change': None,
        'model_precision': None,
        'avg_latency': None,
        'block_rate': block_rate,
        'system_status': 100,
        'timestamp': datetime.now().isoformat(),
        'cache': cache_data
    }

    return jsonify(stats)


@app.route('/api/traffic', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_traffic():
    """Datos de tráfico reales para gráfico (últimas 24h desde SQLite + Redis threat_events)"""
    try:
        from app.core.database import SessionLocal
        from app.core.models import TrafficLog
        from sqlalchemy import func, case

        now = datetime.utcnow()  # timestamps en BD están en UTC
        cutoff = now - timedelta(hours=24)

        db = SessionLocal()
        try:
            rows = (
                db.query(
                    func.strftime('%Y-%m-%d %H', TrafficLog.timestamp).label('day_hour'),
                    func.count(TrafficLog.id).label('total'),
                    func.sum(case((TrafficLog.ai_prediction == 'malicious', 1), else_=0)).label('threats')
                )
                .filter(TrafficLog.timestamp >= cutoff)
                .group_by(func.strftime('%Y-%m-%d %H', TrafficLog.timestamp))
                .all()
            )
        finally:
            db.close()

        # Construir mapa "YYYY-MM-DD HH" → datos
        hourly = {r.day_hour: {'requests': r.total, 'threats': int(r.threats or 0)} for r in rows}

        # Agregar amenazas de Redis threat_events (bloques WAF previos a Fix 1)
        # Evita doble conteo: solo suma eventos cuyo blocked_at no está ya en SQLite
        try:
            _rc = getattr(ip_blocker, 'redis_client', None) if ip_blocker else None
            if _rc is None:
                _rc = app.config.get('REDIS_CLIENT')
            if _rc:
                raw_events = _rc.lrange('athenai:threat_events', 0, -1)
                for raw in raw_events:
                    try:
                        ev = json.loads(raw if isinstance(raw, str) else raw.decode('utf-8'))
                        blocked_at_str = ev.get('blocked_at', '')
                        if not blocked_at_str:
                            continue
                        blocked_at = datetime.fromisoformat(blocked_at_str)
                        if blocked_at < cutoff:
                            continue
                        # Redis stores local time; normalize to UTC-naive for key comparison
                        key = blocked_at.strftime('%Y-%m-%d %H')
                        if key not in hourly:
                            hourly[key] = {'requests': 0, 'threats': 0}
                        hourly[key]['threats'] += 1
                        hourly[key]['requests'] += 1
                    except Exception:
                        pass
        except Exception as _re:
            app.logger.warning(f"Traffic: no se pudo leer Redis threat_events: {_re}")

        # Rellenar las 24 horas en orden cronológico
        data = []
        for i in range(24):
            slot = now - timedelta(hours=23 - i)
            key = slot.strftime('%Y-%m-%d %H')
            entry = hourly.get(key, {'requests': 0, 'threats': 0})
            data.append({
                'time': f'{slot.hour:02d}:00',
                'requests': entry['requests'],
                'threats': entry['threats'],
            })

        return jsonify(data)

    except Exception as e:
        app.logger.warning(f"Traffic real data error, returning empty hourly structure: {e}")
        now = datetime.now()
        empty_hours = []
        for i in range(23, -1, -1):
            hour = now - timedelta(hours=i)
            empty_hours.append({
                'hour': hour.strftime('%H:%M'),
                'requests': 0,
                'threats': 0,
                'blocked': 0
            })
        return jsonify(empty_hours)


@app.route('/api/attacks', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_attacks():
    """Tipos de ataques detectados — clasificados desde logs reales de SQLite"""
    import re
    try:
        from app.core.database import SessionLocal
        from app.core.models import TrafficLog

        db = SessionLocal()
        try:
            logs = (
                db.query(TrafficLog.path, TrafficLog.query_params, TrafficLog.body)
                .filter(TrafficLog.ai_prediction == 'malicious')
                .all()
            )
        finally:
            db.close()

        if logs:
            counts = {'SQL Injection': 0, 'XSS': 0, 'Brute Force': 0, 'Path Traversal': 0, 'Other': 0}

            sql_re = re.compile(r"(?i)(select\s|union\s|insert\s|drop\s|delete\s|update\s|--|;|\bor\b\s+\d|\bor\b\s+')", re.I)
            xss_re = re.compile(r"(?i)(<script|onerror\s*=|javascript:|alert\s*\(|<img|<svg|onload\s*=)", re.I)
            path_re = re.compile(r"(\.\./|\.\.\\|/etc/|/proc/|/var/|cmd=|exec=)")
            brute_re = re.compile(r"(?i)(password|passwd|pwd|login|auth).*=", re.I)

            for log in logs:
                text = ' '.join(filter(None, [log.path or '', log.query_params or '', log.body or '']))
                if sql_re.search(text):
                    counts['SQL Injection'] += 1
                elif xss_re.search(text):
                    counts['XSS'] += 1
                elif path_re.search(text):
                    counts['Path Traversal'] += 1
                elif brute_re.search(text):
                    counts['Brute Force'] += 1
                else:
                    counts['Other'] += 1

            attack_data = [
                {'type': k, 'count': v}
                for k, v in counts.items()
                if v > 0
            ]
            attack_data.sort(key=lambda x: x['count'], reverse=True)
            return jsonify(attack_data)

    except Exception as e:
        app.logger.warning(f"Attack classification error: {e}")

    # Fallback: alertas de S3
    alerts = get_alerts_from_s3()
    attack_counts = {}
    for alert in alerts:
        t = alert['type']
        attack_counts[t] = attack_counts.get(t, 0) + 1
    if attack_counts:
        return jsonify([{'type': k, 'count': v} for k, v in attack_counts.items()])

    # Fallback: leer desde Redis threat_events (fuente autoritativa del WAF)
    try:
        _rc = getattr(ip_blocker, 'redis_client', None) if ip_blocker else None
        if _rc is None:
            _rc = current_app.config.get('REDIS_CLIENT')
        if _rc:
            raw_events = _rc.lrange('athenai:threat_events', 0, -1)
            redis_counts = {}
            for e in raw_events:
                try:
                    tt = json.loads(e).get('threat_type', 'Other')
                    redis_counts[tt] = redis_counts.get(tt, 0) + 1
                except Exception:
                    pass
            if redis_counts:
                result = [{'type': k, 'count': v} for k, v in redis_counts.items()]
                result.sort(key=lambda x: x['count'], reverse=True)
                return jsonify(result)
    except Exception as _re:
        app.logger.warning(f"Redis attack counts error: {_re}")

    # Sin datos reales disponibles
    return jsonify([
        {'type': 'Sin datos', 'count': 0}
    ])


@app.route('/api/system-health', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_system_health():
    """Get detailed system health metrics"""
    if not system_health_monitor:
        return jsonify({'error': 'System Health Monitor not available'}), 503

    # Inject the already-authenticated Redis client from ip_blocker so the
    # health monitor doesn't need its own (potentially password-less) connection.
    _working_rc = (
        getattr(ip_blocker, 'redis_client', None)
        or current_app.config.get('REDIS_CLIENT')
    )
    if _working_rc is not None and system_health_monitor.redis_client is None:
        system_health_monitor.redis_client = _working_rc

    try:
        metrics = system_health_monitor.get_all_metrics()
        return jsonify(metrics)
    except Exception as e:
        print(f"Error getting system health: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================
# ENDPOINTS DE IP MANAGEMENT
# ============================================

@app.route('/api/blocked-ips', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_blocked_ips():
    """Get all blocked IPs"""
    if not ip_blocker:
        return jsonify({'blocked_ips': [], 'count': 0, 'offline': True})
    
    try:
        blocked_ips = ip_blocker.get_all_blocked_ips()
        return jsonify({'blocked_ips': blocked_ips, 'count': len(blocked_ips)})
    except Exception as e:
        print(f"Error getting blocked IPs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/blocked-ips', methods=['POST'])
@require_auth
@require_permission(Permission.BLOCK_IPS)
@validate_json(BlockIPSchema)
def block_ip_manual():
    """
    Bloquear una IP manualmente
    ---
    tags:
      - IP Management
    summary: Agrega una IP a la lista de bloqueados
    security:
      - BearerAuth: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          $ref: '#/definitions/BlockIPRequest'
    responses:
      200:
        description: IP bloqueada exitosamente
        schema:
          type: object
          properties:
            success:
              type: boolean
            message:
              type: string
              example: IP 192.168.1.100 blocked successfully
      422:
        description: IP con formato inválido o duración fuera de rango
        schema:
          $ref: '#/definitions/ValidationError'
      503:
        description: IP Blocker no disponible
    """
    """Block an IP manually"""
    if not ip_blocker:
        return jsonify({'error': 'IP Blocker no disponible — Redis desconectado'}), 503
    
    try:
        data = request.validated_data
        ip = data['ip']
        reason = data['reason']
        duration = data['duration']
        
        success = ip_blocker.block_ip(ip, duration=duration, reason=reason)
        
        if success:
            return jsonify({'success': True, 'message': f'IP {ip} blocked successfully'})
        else:
            return jsonify({'error': 'Failed to block IP'}), 500
            
    except Exception as e:
        print(f"Error blocking IP: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/blocked-ips/<ip>', methods=['DELETE'])
@require_auth
@require_permission(Permission.BLOCK_IPS)
def unblock_ip_endpoint(ip):
    """Unblock an IP"""
    if not ip_blocker:
        return jsonify({'error': 'IP Blocker not available'}), 503
    
    try:
        success = ip_blocker.unblock_ip(ip)
        
        if success:
            return jsonify({'success': True, 'message': f'IP {ip} unblocked successfully'})
        else:
            return jsonify({'error': 'IP not found or already unblocked'}), 404
            
    except Exception as e:
        print(f"Error unblocking IP: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/whitelist', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_whitelist():
    """Get all whitelisted IPs"""
    if not ip_blocker:
        return jsonify({'whitelist': [], 'count': 0, 'offline': True})
    
    try:
        whitelist = ip_blocker.get_whitelist()
        return jsonify({'whitelist': whitelist, 'count': len(whitelist)})
    except Exception as e:
        print(f"Error getting whitelist: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/whitelist', methods=['POST'])
@require_auth
@require_permission(Permission.MANAGE_WHITELIST)
@validate_json(WhitelistSchema)
def add_to_whitelist():
    """
    Agregar IP a la whitelist
    ---
    tags:
      - IP Management
    summary: Marca una IP como confiable (nunca será bloqueada)
    security:
      - BearerAuth: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          $ref: '#/definitions/WhitelistRequest'
    responses:
      200:
        description: IP agregada a whitelist
      422:
        description: IP con formato inválido
        schema:
          $ref: '#/definitions/ValidationError'
    """
    """Add IP to whitelist"""
    if not ip_blocker:
        return jsonify({'error': 'IP Blocker not available'}), 503
    
    try:
        data = request.validated_data
        ip = data['ip']
        reason = data['reason']
        
        success = ip_blocker.add_to_whitelist(ip, reason=reason)
        
        if success:
            return jsonify({'success': True, 'message': f'IP {ip} added to whitelist'})
        else:
            return jsonify({'error': 'Failed to add IP to whitelist'}), 500
            
    except Exception as e:
        print(f"Error adding to whitelist: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/whitelist/<ip>', methods=['DELETE'])
@require_auth
@require_permission(Permission.MANAGE_WHITELIST)
def remove_from_whitelist_endpoint(ip):
    """Remove IP from whitelist"""
    if not ip_blocker:
        return jsonify({'error': 'IP Blocker not available'}), 503
    
    try:
        success = ip_blocker.remove_from_whitelist(ip)
        
        if success:
            return jsonify({'success': True, 'message': f'IP {ip} removed from whitelist'})
        else:
            return jsonify({'error': 'IP not found in whitelist'}), 404
            
    except Exception as e:
        print(f"Error removing from whitelist: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ip-stats', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_ip_stats():
    """Get IP blocking statistics"""
    if not ip_blocker:
        return jsonify({
            'total_blocked': 0, 'total_whitelisted': 0,
            'blocked_today': 0, 'auto_blocks': 0, 'manual_blocks': 0,
            'active_blocks': 0, 'permanent_blocks': 0,
            'offline': True, 'timestamp': datetime.now().isoformat()
        })
    
    try:
        stats = ip_blocker.get_stats()
        
        # Add additional stats
        blocked_ips = ip_blocker.get_all_blocked_ips()
        whitelist = ip_blocker.get_whitelist()
        
        # Count today's blocks
        today = datetime.now().date()
        blocked_today = sum(1 for ip in blocked_ips
                           if _safe_parse_date(ip.get('blocked_at', '')) == today)
        
        # Count auto vs manual blocks
        auto_blocks = sum(1 for ip in blocked_ips if ip.get('auto_blocked', False))
        manual_blocks = len(blocked_ips) - auto_blocks
        
        enhanced_stats = {
            **stats,
            'total_blocked': len(blocked_ips),
            'total_whitelisted': len(whitelist),
            'blocked_today': blocked_today,
            'auto_blocks': auto_blocks,
            'manual_blocks': manual_blocks,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(enhanced_stats)
        
    except Exception as e:
        print(f"Error getting IP stats: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================
# ENDPOINT DE THREAT DASHBOARD
# ============================================

@app.route('/api/threats/summary', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_threats_summary():
    """
    Resumen de amenazas detectadas y bloqueadas automáticamente
    ---
    tags:
      - Dashboard
    summary: Devuelve breakdown por tipo de amenaza, timeline de 24h, feed reciente y top IPs
    security:
      - BearerAuth: []
    responses:
      200:
        description: Resumen de amenazas
        schema:
          type: object
          properties:
            total_auto_blocked:
              type: integer
              description: Total de IPs bloqueadas automáticamente
              example: 42
            most_common_threat:
              type: string
              description: Tipo de amenaza más frecuente
              example: SQL Injection
            breakdown:
              type: array
              description: Conteo por tipo de amenaza (para donut chart)
              items:
                type: object
                properties:
                  name:
                    type: string
                    example: SQL Injection
                  value:
                    type: integer
                    example: 18
            timeline:
              type: array
              description: Evolución horaria de las últimas 24h
              items:
                type: object
                properties:
                  time:
                    type: string
                    example: "14:00"
                  SQL Injection:
                    type: integer
                  XSS:
                    type: integer
                  Command Injection:
                    type: integer
                  Credential Stuffing:
                    type: integer
                  Impossible Travel:
                    type: integer
                  ML Detection:
                    type: integer
            recent_threats:
              type: array
              description: Últimas 20 amenazas bloqueadas automáticamente
              items:
                type: object
                properties:
                  ip:
                    type: string
                    example: "203.0.113.45"
                  threat_type:
                    type: string
                    example: SQL Injection
                  reason:
                    type: string
                  blocked_at:
                    type: string
                    format: date-time
                  remaining_seconds:
                    type: integer
                  permanent:
                    type: boolean
            top_ips:
              type: array
              description: Top 10 IPs con mayor número de bloqueos automáticos
              items:
                type: object
                properties:
                  ip:
                    type: string
                    example: "198.51.100.7"
                  count:
                    type: integer
                    example: 5
      401:
        description: No autenticado
      403:
        description: Rol insuficiente
      503:
        description: IP Blocker no disponible
    """
    if not ip_blocker:
        return jsonify({
            'total_auto_blocked': 0, 'most_common_threat': None,
            'breakdown': [], 'timeline': [], 'recent_threats': [], 'top_ips': [],
            'offline': True
        })

    try:
        blocked_ips = ip_blocker.get_all_blocked_ips()

        # Combinar con eventos de Redis (incluye IPs whitelisted que enviaron ataques)
        try:
            _rc = getattr(ip_blocker, 'redis_client', None) or current_app.config.get('REDIS_CLIENT')
            if _rc:
                raw_events = _rc.lrange('athenai:threat_events', 0, 999)
                for raw in raw_events:
                    try:
                        ev = json.loads(raw if isinstance(raw, str) else raw.decode('utf-8'))
                        if ev.get('auto_blocked'):
                            blocked_ips.append(ev)
                    except Exception:
                        pass
        except Exception as _e:
            app.logger.warning(f"No se pudieron leer threat_events: {_e}")

        now = datetime.now()
        cutoff_24h = now - timedelta(hours=24)

        # Parsear tipo de amenaza del campo reason
        THREAT_PATTERN = re.compile(r'^\[([^\]]+)\]')
        threat_counts = {}
        timeline_buckets = {}   # "HH:00" → {threat_type: count}
        recent_threats = []     # últimas 20 auto-bloqueadas

        for entry in blocked_ips:
            if not entry.get('auto_blocked'):
                continue

            reason = entry.get('reason', '')
            m = THREAT_PATTERN.match(reason)
            threat_type = m.group(1) if m else 'Unknown'

            # Contar por tipo
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1

            # Timeline últimas 24h
            blocked_at_str = entry.get('blocked_at', '')
            try:
                blocked_at = datetime.fromisoformat(blocked_at_str)
                # Normalizar a UTC si no tiene tzinfo (almacenado sin tz)
                if blocked_at >= cutoff_24h:
                    hour_key = blocked_at.strftime('%H:00')
                    if hour_key not in timeline_buckets:
                        timeline_buckets[hour_key] = {}
                    timeline_buckets[hour_key][threat_type] = \
                        timeline_buckets[hour_key].get(threat_type, 0) + 1
            except (ValueError, TypeError):
                pass

            # Feed reciente
            recent_threats.append({
                'ip': entry.get('ip'),
                'threat_type': threat_type,
                'reason': reason[len(threat_type) + 2:].strip() if m else reason,
                'blocked_at': blocked_at_str,
                'remaining_seconds': entry.get('remaining_seconds'),
                'permanent': entry.get('permanent', False),
            })

        # Ordenar feed por blocked_at desc, tomar últimas 20
        recent_threats.sort(key=lambda x: x.get('blocked_at', ''), reverse=True)
        recent_threats = recent_threats[:20]

        # Construir timeline completa para las últimas 24h (todos los slots)
        timeline = []
        for h in range(24):
            slot_time = (now - timedelta(hours=23 - h))
            key = slot_time.strftime('%H:00')
            entry_data = timeline_buckets.get(key, {})
            timeline.append({
                'time': key,
                'SQL Injection': entry_data.get('SQL Injection', 0),
                'XSS': entry_data.get('XSS', 0),
                'Command Injection': entry_data.get('Command Injection', 0),
                'Credential Stuffing': entry_data.get('Credential Stuffing', 0),
                'Impossible Travel': entry_data.get('Impossible Travel', 0),
                'ML Detection': entry_data.get('ML Async Detection', 0),
            })

        # Breakdown para donut chart
        breakdown = [
            {'name': k, 'value': v}
            for k, v in sorted(threat_counts.items(), key=lambda x: -x[1])
        ]

        # Top IPs con más amenazas (de todos los bloqueados auto)
        ip_counts = {}
        for entry in blocked_ips:
            if entry.get('auto_blocked'):
                ip_counts[entry['ip']] = ip_counts.get(entry['ip'], 0) + 1
        top_ips = [{'ip': k, 'count': v} for k, v in sorted(ip_counts.items(), key=lambda x: -x[1])[:10]]

        total_auto = sum(threat_counts.values())
        most_common = max(threat_counts, key=threat_counts.get) if threat_counts else None

        return jsonify({
            'total_auto_blocked': total_auto,
            'most_common_threat': most_common,
            'breakdown': breakdown,
            'timeline': timeline,
            'recent_threats': recent_threats,
            'top_ips': top_ips,
        })

    except Exception as e:
        app.logger.error(f"Error in threats/summary: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================
# ENDPOINTS DE CONTINUOUS LEARNING
# ============================================

@app.route('/api/continuous-learning/stats', methods=['GET'])
@require_auth
@require_role('admin', 'analyst')
def get_continuous_learning_stats():
    """Get continuous learning statistics and metrics"""
    if not brain:
        return jsonify({'error': 'AI Engine not available'}), 503
    
    try:
        # Get stats from AI Engine
        cl_stats = brain.get_continuous_learning_stats()
        
        # Add timestamp
        cl_stats['timestamp'] = datetime.now().isoformat()
        
        return jsonify(cl_stats)
        
    except Exception as e:
        print(f"Error getting continuous learning stats: {e}")
        # Return default stats if error
        return jsonify({
            'buffer_size': 0,
            'buffer_capacity': 1000,
            'buffer_percentage': 0,
            'total_retrains': 0,
            'last_retrain': None,
            'current_version': 'v1.0.0',
            'model_performance': {
                'f1_score': 0,
                'accuracy': 0,
                'precision': 0,
                'recall': 0
            },
            'drift_status': 'UNKNOWN',
            'drift_features': [],
            'poisoning_filtered': 0,
            'timestamp': datetime.now().isoformat(),
            'error': str(e)
        }), 200


# ============================================
# ENDPOINTS DE A/B TESTING
# ============================================

@app.route('/api/ab-testing/stats', methods=['GET'])
@require_auth
@require_role('admin', 'analyst')
def get_ab_testing_stats():
    """Get A/B testing statistics and comparison"""
    if not brain or not brain.ab_testing_enabled:
        return jsonify({
            'enabled': False,
            'status': 'unavailable',
            'model_a': {'enabled': False, 'name': 'XGBoost (prod)', 'traffic_pct': 100, 'requests': 0, 'accuracy': None},
            'model_b': {'enabled': False, 'name': 'IsolationForest (challenger)', 'traffic_pct': 0, 'requests': 0, 'accuracy': None},
            'message': 'A/B Testing requiere el módulo de entrenamiento ML',
            'timestamp': datetime.now().isoformat()
        }), 200
    
    try:
        # Get stats from A/B test manager
        stats = brain.ab_test_manager.get_stats()
        
        # Add timestamp
        stats['timestamp'] = datetime.now().isoformat()
        
        return jsonify(stats)
        
    except Exception as e:
        print(f"Error getting A/B testing stats: {e}")
        return jsonify({
            'error': str(e),
            'model_a': {'enabled': False},
            'model_b': {'enabled': False},
            'timestamp': datetime.now().isoformat()
        }), 200

@app.route('/api/ab-testing/traffic-split', methods=['POST'])
@require_auth
@require_permission(Permission.MANAGE_AB_TESTING)
@validate_json(TrafficSplitSchema)
def update_traffic_split():
    """Update traffic split percentages"""
    if not brain or not brain.ab_testing_enabled:
        return jsonify({'error': 'A/B Testing no disponible — módulo ML no cargado'}), 200
    
    try:
        data = request.validated_data
        model_a_percentage = data['model_a_percentage']
        
        # Update traffic split
        brain.ab_test_manager.update_traffic_split(model_a_percentage)
        
        return jsonify({
            'success': True,
            'model_a_percentage': model_a_percentage,
            'model_b_percentage': 100 - model_a_percentage,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error updating traffic split: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ab-testing/promote', methods=['POST'])
@require_auth
@require_permission(Permission.MANAGE_AB_TESTING)
def promote_model_b():
    """Promote Model B to production"""
    if not brain or not brain.ab_testing_enabled:
        return jsonify({'error': 'A/B Testing no disponible — módulo ML no cargado'}), 200
    
    try:
        # Promote Model B
        result = brain.ab_test_manager.promote_model_b()
        
        return jsonify({
            'success': True,
            'message': 'Model B promoted to production',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error promoting Model B: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/ab-testing/reset', methods=['POST'])
@require_auth
@require_permission(Permission.MANAGE_AB_TESTING)
def reset_ab_testing():
    """Reset A/B testing metrics"""
    if not brain or not brain.ab_testing_enabled:
        return jsonify({'error': 'A/B Testing no disponible — módulo ML no cargado'}), 200
    
    try:
        # Reset metrics for both models
        brain.ab_test_manager.reset_metrics('model_a')
        brain.ab_test_manager.reset_metrics('model_b')
        
        return jsonify({
            'success': True,
            'message': 'A/B testing metrics reset',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error resetting A/B testing: {e}")
        return jsonify({'error': str(e)}), 500





# ============================================
# ENDPOINTS DE AUTENTICACIÓN
# ============================================

@app.route('/api/auth/register', methods=['POST'])
@validate_json(RegisterSchema)
def auth_register():
    """
    Registro de nuevo usuario
    ---
    tags:
      - Auth
    summary: Crea una nueva cuenta de usuario
    parameters:
      - in: body
        name: body
        required: true
        schema:
          $ref: '#/definitions/RegisterRequest'
    responses:
      201:
        description: Usuario registrado exitosamente
        schema:
          type: object
          properties:
            message:
              type: string
              example: User registered successfully
            user:
              type: object
      400:
        description: Solicitud inválida (error genérico de validación de negocio)
      409:
        description: El username o email ya está en uso
        schema:
          type: object
          properties:
            error:
              type: string
              example: "Username already exists"
      422:
        description: Error de validación de esquema (email inválido, rol incorrecto, etc.)
        schema:
          $ref: '#/definitions/ValidationError'
    """
    """Registro de nuevo usuario"""
    if not auth_service:
        return jsonify({'error': 'Auth service not available'}), 503

    # V-06: registro habilitado/deshabilitado por variable de entorno
    if os.getenv('REGISTRATION_ENABLED', 'true').lower() != 'true':
        return jsonify({'error': 'Registration is currently disabled.'}), 403

    # V-06: rate-limit global de registro por IP (5 cuentas por hora)
    _reg_ip = _client_ip()
    _REG_KEY = f"rl:register:{_reg_ip}"
    _REG_MAX = 5
    _REG_TTL = 3600
    _redis = rate_limiter.redis_client if rate_limiter else None
    if _redis:
        try:
            count = int(_redis.get(_REG_KEY) or 0)
            if count >= _REG_MAX:
                ttl = max(_redis.ttl(_REG_KEY), _REG_TTL)
                resp = jsonify({'error': 'Too many registration attempts. Try again later.'})
                resp.headers['Retry-After'] = str(ttl)
                return resp, 429
        except Exception as _e:
            app.logger.error(f"Register rate-limit check failed: {_e}")

    try:
        data = request.validated_data

        user = auth_service.register_user(
            data['username'], data['password'], data['email'], data['role']
        )

        # Incrementar contador de registros por IP
        if _redis:
            try:
                pipe = _redis.pipeline()
                pipe.incr(_REG_KEY)
                pipe.expire(_REG_KEY, _REG_TTL)
                pipe.execute()
            except Exception:
                pass

        return jsonify({'message': 'User registered successfully', 'user': user}), 201

    except ValueError as e:
        err = str(e)
        # Mensaje genérico para evitar enumeración de usuarios/emails
        if 'already exists' in err or 'could not be completed' in err:
            return jsonify({'error': 'Registration could not be completed.'}), 409
        return jsonify({'error': err}), 400
    except Exception as e:
        app.logger.error(f"Registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500


@app.route('/api/auth/login', methods=['POST'])
@validate_json(LoginSchema)
def auth_login():
    """
    Login de usuario
    ---
    tags:
      - Auth
    summary: Autentica un usuario y retorna tokens JWT
    parameters:
      - in: body
        name: body
        required: true
        schema:
          $ref: '#/definitions/LoginRequest'
    responses:
      200:
        description: Login exitoso
        schema:
          $ref: '#/definitions/LoginResponse'
      401:
        description: Credenciales inválidas
      403:
        description: IP bloqueada por detección de credential stuffing
        schema:
          type: object
          properties:
            error:
              type: string
              example: Forbidden
            threat_type:
              type: string
              example: Credential Stuffing
      422:
        description: Error de validación
        schema:
          $ref: '#/definitions/ValidationError'
      429:
        description: Demasiados intentos fallidos — bloqueado 15 minutos (brute-force protection)
        headers:
          Retry-After:
            type: integer
            description: Segundos hasta que se permite reintentar
    """
    """Login de usuario"""
    if not auth_service:
        return jsonify({'error': 'Auth service not available'}), 503

    # V-08 fix: IP real, sin confiar en XFF sin proxy validado
    source_ip = _client_ip()

    data = request.validated_data
    username = data['username']

    # V-08 + dual rate-limit: clave por IP y por username (evita lockout asimétrico)
    _LOGIN_TTL = 900  # 15 minutos
    _IP_KEY   = f"rl:login:ip:{source_ip}"
    _USER_KEY = f"rl:login:user:{username.lower()}"
    _IP_MAX   = 20   # 20 intentos por IP en 15 min
    _USER_MAX = 5    # 5 intentos por username en 15 min
    _redis = rate_limiter.redis_client if rate_limiter else None
    if _redis:
        try:
            ip_count   = int(_redis.get(_IP_KEY)   or 0)
            user_count = int(_redis.get(_USER_KEY) or 0)
            if ip_count >= _IP_MAX or user_count >= _USER_MAX:
                ttl = max(_redis.ttl(_IP_KEY), _redis.ttl(_USER_KEY), _LOGIN_TTL)
                app.logger.warning(f"Brute-force threshold exceeded for IP {source_ip} / user {username}")
                resp = jsonify({'error': 'Too many login attempts. Try again later.'})
                resp.headers['Retry-After'] = str(ttl)
                return resp, 429
        except Exception as _e:
            app.logger.error(f"Login rate-limit check failed: {_e}")

    try:
        # V-NEW-01: delegar a auth_service que ya aplica bcrypt constante
        result = auth_service.login(username, data['password'])

        # Login exitoso — resetear ambos contadores
        if _redis:
            try:
                _redis.delete(_IP_KEY, _USER_KEY)
            except Exception as _e:
                app.logger.error(f"Failed to reset login counters: {_e}")

        # Detectar impossible travel y registrar intento exitoso
        if security_mw and hasattr(security_mw, 'threat_detector') and security_mw.threat_detector:
            td = security_mw.threat_detector
            user_id = result.get('user', {}).get('user_id', username)
            travel = td.check_impossible_travel(user_id, username, source_ip)
            if travel:
                app.logger.warning(f"Impossible travel post-login: {username} from {source_ip}")
            td.record_login_attempt(source_ip, username, success=True)

        resp = jsonify(result)
        # httpOnly cookie — no accesible por JS, mitiga robo de token via XSS
        resp.set_cookie(
            'athenai_access_token',
            result.get('access_token', ''),
            httponly=True,
            secure=True,
            samesite='Strict',
            max_age=3600,
            path='/'
        )
        return resp, 200

    except ValueError:
        # Login fallido — incrementar ambos contadores en pipeline atómico
        if _redis:
            try:
                pipe = _redis.pipeline()
                pipe.incr(_IP_KEY);   pipe.expire(_IP_KEY,   _LOGIN_TTL)
                pipe.incr(_USER_KEY); pipe.expire(_USER_KEY, _LOGIN_TTL)
                pipe.execute()
            except Exception as _e:
                app.logger.error(f"Failed to increment login counters: {_e}")

        # Registrar para detección de credential stuffing
        if security_mw and hasattr(security_mw, 'threat_detector') and security_mw.threat_detector:
            threat = security_mw.threat_detector.record_login_attempt(
                source_ip, username, success=False
            )
            if threat:
                return jsonify({
                    'error': 'Forbidden',
                    'message': threat['threat_type'] + ' detected — IP blocked',
                    'threat_type': threat['threat_type'],
                }), 403

        # Mensaje genérico — no revelar si el username existe o no
        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        app.logger.error(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500


@app.route('/api/auth/refresh', methods=['POST'])
@validate_json(RefreshTokenSchema)
def auth_refresh():
    """Refresh de access token"""
    if not auth_service:
        return jsonify({'error': 'Auth service not available'}), 503
    
    try:
        data = request.validated_data
        
        result = auth_service.refresh(data['refresh_token'])
        
        return jsonify(result), 200
    
    except Exception as e:
        return jsonify({'error': f'Token refresh failed: {str(e)}'}), 401


@app.route('/api/auth/me', methods=['GET'])
@require_auth
def auth_me():
    """Información del usuario actual"""
    if not auth_service:
        return jsonify({'error': 'Auth service not available'}), 503
    
    try:
        user_id = request.user.get('user_id')
        user = auth_service.get_user_by_id(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({'user': user}), 200
    
    except Exception as e:
        return jsonify({'error': f'Failed to get user info: {str(e)}'}), 500


@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def auth_logout():
    """
    Logout de usuario
    ---
    tags:
      - Auth
    summary: Invalida el JWT activo añadiéndolo a la blacklist de Redis
    security:
      - BearerAuth: []
    responses:
      200:
        description: Sesión cerrada correctamente
        schema:
          type: object
          properties:
            message:
              type: string
              example: Logged out successfully
      401:
        description: Token ausente o inválido
    """
    import hashlib, time as _time
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.split()[-1] if auth_header else ''

    redis_client = app.config.get('REDIS_CLIENT')
    if token and redis_client:
        try:
            import jwt as _jwt
            payload = _jwt.decode(
                token,
                app.config['AUTH_SERVICE'].jwt_secret,
                algorithms=['HS256']
            )
            jti = payload.get('jti') or hashlib.sha256(token.encode()).hexdigest()
            ttl = int(payload.get('exp', 0) - _time.time())
            if ttl > 0:
                redis_client.setex(f'blacklisted_token:{jti}', ttl, '1')
        except Exception as e:
            app.logger.warning(f'Token blacklist failed during logout: {e}')

    return jsonify({'message': 'Logged out successfully'}), 200


# ============================================
# ENDPOINTS DE DATOS (DASHBOARD)
# ============================================

@app.route('/api/alerts', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_alerts():
    """Alertas recientes desde DynamoDB con soporte de filtros y paginación"""
    try:
        # V-NEW-03: validar query params con Marshmallow (evita limit=-1 y valores arbitrarios)
        from marshmallow import ValidationError as _VE
        try:
            q = AlertsQuerySchema().load(request.args)
        except _VE as _err:
            return jsonify({'error': 'Invalid query parameters', 'messages': _err.messages}), 422
        limit  = q['limit']
        offset = q['offset']
        severity_param = q['severity']
        severity_filter = [s.strip() for s in severity_param.split(',') if s.strip()] if severity_param else []
        status_filter = q['status'].strip()

        # Obtener alertas reales de DynamoDB
        if dynamodb_client:
            db_alerts = dynamodb_client.get_alerts(limit=200)
            
            # Transformar al formato esperado por el frontend
            alerts = []
            for alert in db_alerts:
                # Parsear timestamp
                try:
                    timestamp = alert.get('timestamp', '')
                    if 'T' in timestamp:
                        time_str = timestamp.split('T')[1][:8]
                    else:
                        time_str = datetime.fromisoformat(timestamp).strftime('%H:%M:%S')
                except:
                    time_str = 'N/A'
                
                # Determinar status según acción tomada
                action = alert.get('action_taken', 'MONITOR')
                if action == 'BLOCK':
                    status = 'blocked'
                elif action == 'ALERT':
                    status = 'flagged'
                else:
                    status = 'monitoring'
                
                alerts.append({
                    'id': alert.get('alert_id', 'unknown'),
                    'time': time_str,
                    'type': alert.get('attack_type', alert.get('type', 'Unknown')),
                    'severity': alert.get('severity', 'medium').lower(),
                    'ip': alert.get('source_ip', 'unknown'),
                    'status': status,
                    'confidence': alert.get('risk_score', 0),
                    'payload': alert.get('payload'),
                    'details': alert.get('details')
                })
            
            # Ordenar por timestamp (más recientes primero)
            alerts = sorted(alerts, key=lambda x: x.get('id', ''), reverse=True)

            # Aplicar filtros de severidad y estado
            if severity_filter:
                alerts = [a for a in alerts if a['severity'] in severity_filter]
            if status_filter:
                alerts = [a for a in alerts if a['status'] == status_filter]

            total = len(alerts)
            alerts = alerts[offset:offset + limit]

            if total > 0:
                return jsonify({'alerts': alerts, 'total': total, 'limit': limit, 'offset': offset})

        # Fallback: leer eventos reales desde Redis athenai:threat_events
        _rc = getattr(ip_blocker, 'redis_client', None) if ip_blocker else None
        if _rc is None:
            _rc = current_app.config.get('REDIS_CLIENT')

        if _rc:
            try:
                raw_events = _rc.lrange('athenai:threat_events', 0, -1)
                redis_alerts = []
                for idx, raw in enumerate(raw_events):
                    try:
                        ev = json.loads(raw)
                        blocked_at = ev.get('blocked_at', '')
                        if 'T' in blocked_at:
                            time_str = blocked_at.split('T')[1][:8]
                        elif blocked_at:
                            try:
                                time_str = datetime.fromisoformat(blocked_at).strftime('%H:%M:%S')
                            except Exception:
                                time_str = blocked_at[:8] if len(blocked_at) >= 8 else blocked_at
                        else:
                            time_str = 'N/A'

                        is_blocked = ev.get('blocked', ev.get('auto_blocked', False))
                        status = 'blocked' if is_blocked else 'monitoring'
                        redis_alerts.append({
                            'id': f'redis-{idx}',
                            'time': time_str,
                            'type': ev.get('threat_type', 'Unknown'),
                            'severity': (ev.get('severity') or 'high').lower(),
                            'ip': ev.get('ip', 'unknown'),
                            'status': status,
                            'reason': ev.get('reason', ''),
                            'permanent': ev.get('permanent', False),
                        })
                    except Exception:
                        continue

                if severity_filter:
                    redis_alerts = [a for a in redis_alerts if a['severity'] in severity_filter]
                if status_filter:
                    redis_alerts = [a for a in redis_alerts if a['status'] == status_filter]

                total = len(redis_alerts)
                paged = redis_alerts[offset:offset + limit]
                return jsonify({'alerts': paged, 'total': total, 'limit': limit, 'offset': offset})
            except Exception as _re:
                print(f"Error leyendo threat_events de Redis: {_re}")

        # Sin datos reales disponibles — devolver lista vacía (no datos ficticios)
        return jsonify({'alerts': [], 'total': 0, 'limit': limit, 'offset': offset})

    except Exception as e:
        print(f"Error obteniendo alertas: {e}")
        return jsonify({'alerts': [], 'total': 0, 'limit': 50, 'offset': 0}), 500



@app.route('/api/cache-stats', methods=['GET'])
@require_auth
@require_role('admin')
def get_cache_stats():
    """Estadísticas del caché en memoria del AI Engine"""
    try:
        if not brain:
            return jsonify({'error': 'AI Engine not available'}), 503
        
        cache_stats = brain.cache_stats
        total = cache_stats['hits'] + cache_stats['misses']
        hit_rate = (cache_stats['hits'] / max(1, total)) * 100
        
        return jsonify({
            'cache_hits': cache_stats['hits'],
            'cache_misses': cache_stats['misses'],
            'cache_hit_rate': round(hit_rate, 2),
            'cache_size': len(brain.prediction_cache),
            'max_cache_size': brain.max_cache_size,
            'total_predictions': total
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500




@app.route('/api/traffic-logs', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_traffic_logs_endpoint():
    """
    Obtiene logs de tráfico HTTP con filtros opcionales
    
    Query params:
    - limit: Número de resultados (default: 100, max: 1000)
    - offset: Offset para paginación (default: 0)
    - is_test_attack: Filtrar por test attacks (true/false)
    - source_ip: Filtrar por IP específica
    - exclude_localhost: Excluir tráfico de 127.0.0.1 (true/false)
    """
    try:
        # Obtener parámetros de consulta
        limit = min(int(request.args.get('limit', 100)), 1000)
        offset = int(request.args.get('offset', 0))
        
        # Filtro de test attack
        is_test_attack = None
        if request.args.get('is_test_attack'):
            is_test_attack = request.args.get('is_test_attack').lower() == 'true'
        
        # Filtro de IP
        source_ip = request.args.get('source_ip')
        
        # Filtro para excluir localhost
        exclude_localhost = request.args.get('exclude_localhost', 'false').lower() == 'true'
        
        # Obtener logs (filtrando localhost en la consulta SQL si está activado)
        try:
            from app.core.database import SessionLocal
            from app.core.models import TrafficLog as _TL

            _db = SessionLocal()
            try:
                _q = _db.query(_TL)
                if is_test_attack is not None:
                    _q = _q.filter(_TL.is_test_attack == is_test_attack)
                if source_ip:
                    _q = _q.filter(_TL.source_ip == source_ip)
                if exclude_localhost:
                    _q = _q.filter(_TL.source_ip != '127.0.0.1')
                total_count = _q.count()
                logs = _q.order_by(_TL.timestamp.desc()).limit(limit).offset(offset).all()
                logs_data = [log.to_dict() for log in logs]
            finally:
                _db.close()
        except Exception as _db_err:
            app.logger.warning(f"DB no disponible en traffic-logs: {_db_err}")
            return jsonify({'total': 0, 'limit': limit, 'offset': offset, 'logs': [], 'offline': True})
        
        # 🧠 AGREGAR PREDICCIONES DE IA A CADA LOG
        for log in logs_data:
            # Extraer payload para predicción
            payload = ""
            
            # Prioridad: query_params > body > path
            if log.get('query_params'):
                payload = log.get('query_params')
            elif log.get('body'):
                payload = log.get('body')
            elif log.get('path'):
                payload = log.get('path')
            
            # Hacer predicción con AI Engine
            if brain and payload:
                try:
                    label, confidence = brain.predict(payload)
                    log['ai_prediction'] = label  # 'benign' o 'malicious'
                    log['risk_score'] = float(confidence)  # Convertir a Python float para JSON
                except Exception as e:
                    # Fallback en caso de error
                    log['ai_prediction'] = 'malicious' if log.get('is_test_attack') else 'benign'
                    log['risk_score'] = 95.0 if log.get('is_test_attack') else 5.0
            else:
                # Sin AI Engine o sin payload: usar is_test_attack como fallback
                log['ai_prediction'] = 'malicious' if log.get('is_test_attack') else 'benign'
                log['risk_score'] = 95.0 if log.get('is_test_attack') else 5.0
        
        return jsonify({
            'total': total_count,
            'limit': limit,
            'offset': offset,
            'logs': logs_data
        })
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'Error obteniendo logs de tráfico'
        }), 500


@app.route('/api/traffic-logs/export', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def export_traffic_logs():
    """
    Exportar logs de tráfico en formato CSV o JSON
    ---
    tags:
      - Dashboard
    summary: Descarga logs de tráfico HTTP para análisis forense (CSV o JSON)
    security:
      - BearerAuth: []
    parameters:
      - in: query
        name: format
        type: string
        required: false
        default: json
        enum: [csv, json]
        description: Formato de salida del archivo descargado
      - in: query
        name: limit
        type: integer
        required: false
        default: 500
        description: Número máximo de registros a exportar (máx. 5000)
      - in: query
        name: source_ip
        type: string
        required: false
        description: Filtrar registros por IP origen específica
      - in: query
        name: exclude_localhost
        type: boolean
        required: false
        default: false
        description: Si es true, excluye tráfico originado en 127.0.0.1
    responses:
      200:
        description: Archivo descargable con los logs de tráfico
        headers:
          Content-Disposition:
            type: string
            description: "attachment; filename=traffic_logs_<timestamp>.csv|.json"
      401:
        description: No autenticado
      403:
        description: Rol insuficiente
      404:
        description: Sin datos para exportar (solo aplica para CSV vacío)
      500:
        description: Error interno al generar la exportación
    """
    import csv, io
    fmt = request.args.get('format', 'json').lower()
    limit = min(int(request.args.get('limit', 500)), 5000)
    source_ip = request.args.get('source_ip')
    exclude_localhost = request.args.get('exclude_localhost', 'false').lower() == 'true'

    try:
        logs = get_traffic_logs(
            limit=limit,
            offset=0,
            is_test_attack=None,
            source_ip=source_ip,
            exclude_source_ip='127.0.0.1' if exclude_localhost else None
        )
        logs_data = [log.to_dict() for log in logs]
    except Exception as _e:
        app.logger.warning(f"Export: DB no disponible: {_e}")
        logs_data = []

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    if fmt == 'csv':
        if not logs_data:
            return jsonify({'error': 'No data to export'}), 404
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=logs_data[0].keys())
        writer.writeheader()
        writer.writerows(logs_data)
        csv_content = output.getvalue()
        from flask import Response
        return Response(
            csv_content,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename=traffic_logs_{timestamp}.csv'}
        )
    else:
        from flask import Response
        return Response(
            json.dumps({'exported_at': datetime.now().isoformat(), 'total': len(logs_data), 'logs': logs_data}, default=str),
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=traffic_logs_{timestamp}.json'}
        )


@app.route('/api/traffic-stats', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_traffic_stats_endpoint():
    """
    Obtiene estadísticas de tráfico HTTP
    """
    try:
        stats = get_traffic_stats()
        return jsonify(stats)
    except Exception as e:
        app.logger.warning(f"traffic-stats DB error: {e}")
        return jsonify({
            'total_requests': 0, 'total_threats': 0,
            'benign_requests': 0, 'threat_rate': 0.0,
            'offline': True
        })


@app.route('/api/security/analyze', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
@validate_json(AnalyzeRequestSchema)
def analyze_request():
    """
    Analiza una petición HTTP y retorna la decisión de seguridad.

    Body (source_ip se ignora — siempre se usa la IP real del socket):
    {
        "payload": "...",
        "method": "GET",
        "path": "/api/users"
    }
    """
    try:
        data = request.validated_data

        payload = data['payload']
        # V-12a: siempre IP real del socket; V-12b: payload ya validado por schema.
        source_ip = _client_ip()
        method = data['method']
        path = data['path']
        
        # 1. Predicción con AI Engine
        if brain and payload:
            try:
                label, confidence = brain.predict(payload)
                risk_score = float(confidence)
                attack_type = 'malicious' if label == 'malicious' else None
            except Exception as e:
                print(f"Error en predicción ML: {e}")
                risk_score = 50.0
                attack_type = None
        else:
            risk_score = 50.0
            attack_type = None
        
        # 2. Decisión del Policy Engine
        if policy_engine:
            action, metadata = policy_engine.make_decision(
                risk_score=risk_score,
                source_ip=source_ip,
                attack_type=attack_type
            )
            
            # 3. Ejecutar Response Action
            if response_actions:
                request_data = {
                    'source_ip': source_ip,
                    'risk_score': risk_score,
                    'attack_type': attack_type,
                    'method': method,
                    'path': path,
                    'payload': payload
                }
                
                response, status_code = response_actions.execute(
                    action.value,
                    metadata,
                    request_data
                )
                
                # 4. Almacenar en Evidence Store (forensic logging)
                if evidence_store and action.value in ['BLOCK', 'ALERT']:
                    try:
                        evidence_data = {
                            'source_ip': source_ip,
                            'risk_score': risk_score,
                            'attack_type': attack_type,
                            'action_taken': action.value,
                            'method': method,
                            'path': path,
                            'timestamp': datetime.now().isoformat()
                        }
                        evidence_store.store_traffic_log(evidence_data)
                    except Exception as e:
                        print(f"⚠️  Error almacenando evidencia: {e}")
                
                # 5. Almacenar en DynamoDB
                if dynamodb_client:
                    try:
                        # Log de tráfico
                        log_data = {
                            'source_ip': source_ip,
                            'method': method,
                            'path': path,
                            'risk_score': risk_score,
                            'attack_type': attack_type or 'none',
                            'action_taken': action.value,
                            'status_code': status_code
                        }
                        dynamodb_client.insert_traffic_log(log_data)
                        
                        # Si es alerta o bloqueo, registrar en tabla de alertas
                        if action.value in ['BLOCK', 'ALERT']:
                            alert_data = {
                                'type': 'security_event',
                                'severity': metadata.get('severity', 'medium'),
                                'source_ip': source_ip,
                                'risk_score': risk_score,
                                'attack_type': attack_type or 'unknown',
                                'action_taken': action.value
                            }
                            dynamodb_client.insert_alert(alert_data)
                    except Exception as e:
                        print(f"⚠️  Error almacenando en DynamoDB: {e}")
                
                return response, status_code
            else:
                return jsonify({
                    'action': action.value,
                    'risk_score': risk_score,
                    'metadata': metadata
                }), 200
        else:
            return jsonify({
                'error': 'Policy Engine not available',
                'risk_score': risk_score
            }), 500
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'Error analyzing request'
        }), 500



@app.route('/api/victim/analyze', methods=['POST', 'OPTIONS'])
def victim_analyze():
    if request.method == 'OPTIONS':
        resp = app.make_default_options_response()
        resp.headers['Access-Control-Allow-Origin'] = '*'
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
        resp.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
        return resp

    try:
        from app.security.threat_detector import _normalize as _waf_normalize, _SQL_RE, _XSS_RE, _CMD_RE
        data = request.get_json(force=True, silent=True) or {}
        _raw_input = str(data.get('input', ''))[:2000]
        # Dos variantes para cubrir comentarios partiendo keywords (SE/**/LECT) y entre palabras
        _norm_spaced = _waf_normalize(_raw_input, _sql_sep=' ')
        _norm_joined = _waf_normalize(_raw_input, _sql_sep='')
        user_input = _norm_spaced  # para logs; la detección usa ambas
        field = str(data.get('field', 'search'))

        _sqli = re.compile(
            r"(?i)(\bselect\b.+\bfrom\b|\bunion\b.+\bselect\b|\binsert\b.+\binto\b"
            r"|\bdrop\b.+\btable\b|\bdelete\b.+\bfrom\b|\bupdate\b.+\bset\b"
            r"|--|'\s*(or|and)\s*'?\d|1\s*=\s*1|or\s+1\s*=\s*1"
            r"|\bexec\b\s*\(|\bxp_cmdshell\b)",
            re.I | re.S
        )
        _xss = re.compile(
            r"(?i)(<\s*script|onerror\s*=|javascript\s*:|alert\s*\(|"
            r"<\s*img[^>]+onerror|<\s*svg|onload\s*=|<\s*iframe)",
            re.I
        )
        _cmdi = re.compile(
            r"(?i)(;\s*(ls|cat|whoami|id|pwd|rm|curl|wget|bash|sh)\b"
            r"|\|\s*(ls|cat|whoami|id|bash|sh)\b|`[^`]+`|\$\([^)]+\))",
            re.I
        )
        _path = re.compile(r"\.\./|\.\.\\|%2e%2e|%252e", re.I)
        _brute = re.compile(
            r"(?i)(password\s*=\s*'|pass\s*=|admin['\s]|root['\s]|123456|qwerty|letmein)",
            re.I
        )

        threat_type = None
        for _inp in (_norm_spaced, _norm_joined):
            if _sqli.search(_inp):
                threat_type = 'SQL Injection'; break
            elif _xss.search(_inp):
                threat_type = 'XSS'; break
            elif _cmdi.search(_inp):
                threat_type = 'Command Injection'; break
            elif _path.search(_inp):
                threat_type = 'Path Traversal'; break
            elif field == 'login' and _brute.search(_inp):
                threat_type = 'Credential Stuffing'; break

        ml_label = None
        ml_confidence = 0.0
        if brain and user_input:
            try:
                ml_label, ml_confidence = brain.predict(user_input)
            except Exception:
                pass

        detected = bool(threat_type) or ml_label == 'malicious'
        confidence = round(
            ml_confidence if ml_label == 'malicious' else (0.97 if threat_type else 0.0),
            4
        )

        final_threat = threat_type or ('Anomalía ML' if ml_label == 'malicious' else None)

        source_ip = request.remote_addr

        if detected:
            # Bloquear IP si no está en whitelist
            if ip_blocker:
                try:
                    ip_blocker.block_ip(
                        source_ip,
                        duration=3600,
                        reason=f'[{final_threat}] Ataque detectado en POST /api/victim/analyze',
                        auto_blocked=True,
                    )
                except Exception as _be:
                    app.logger.warning(f"block_ip en victim_analyze falló: {_be}")

            # Guardar evento de amenaza en Redis independientemente del whitelist
            try:
                _rc = getattr(ip_blocker, 'redis_client', None) if ip_blocker else None
                if _rc is None:
                    _rc = current_app.config.get('REDIS_CLIENT')
                if _rc:
                    _event = json.dumps({
                        'ip': source_ip,
                        'threat_type': str(final_threat),
                        'reason': f'[{final_threat}] Ataque detectado en POST /api/victim/analyze',
                        'blocked_at': datetime.now().isoformat(),
                        'auto_blocked': True,
                        'permanent': False,
                    })
                    _rc.lpush('athenai:threat_events', _event)
                    _rc.ltrim('athenai:threat_events', 0, 999)
            except Exception as _e:
                app.logger.warning(f"No se pudo guardar threat_event: {_e}")

        resp_data = {
            'detected': detected,
            'blocked': detected,
            'threat_type': final_threat,
            'confidence': confidence,
            'field': field,
            'message': (
                f'Ataque detectado y bloqueado: {final_threat or "Anomalía"}' if detected
                else 'Input limpio — sin amenazas detectadas'
            )
        }

        response = jsonify(resp_data)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response, (403 if detected else 200)

    except Exception as e:
        return jsonify({'error': str(e), 'detected': False}), 500


@app.route('/api/security/stats', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_security_stats():
    """
    Obtiene estadísticas del sistema de seguridad.
    """
    try:
        stats = {
            'policy_engine': {
                'enabled': policy_engine is not None,
                'policies_count': len(policy_engine.get_policies()) if policy_engine else 0
            },
            'response_actions': response_actions.get_stats() if response_actions else {},
            'ai_engine': {
                'enabled': brain is not None
            },
            'ip_blocker': ip_blocker.get_stats() if ip_blocker else {'enabled': False},
            'rate_limiter': rate_limiter.get_stats() if rate_limiter else {'enabled': False},
            'alert_system': alert_system.get_stats() if alert_system else {'enabled': False}
        }
        
        return jsonify(stats)
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'Error getting security stats'
        }), 500




@app.route('/api/security/rate-limiter/check', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
def check_rate_limit_endpoint():
    """
    Verifica el rate limit para un identificador.
    
    Body: {
        "identifier": "192.168.1.100",
        "limit_type": "api"
    }
    """
    try:
        if not rate_limiter:
            return jsonify({'error': 'Rate Limiter not available'}), 503
        
        data = request.get_json()
        identifier = data.get('identifier', request.remote_addr)
        limit_type = data.get('limit_type', 'global')
        
        is_allowed, info = rate_limiter.check_rate_limit(identifier, limit_type)
        
        return jsonify({
            'allowed': is_allowed,
            'info': info
        }), 200 if is_allowed else 429
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ==================== ML ENDPOINTS (Mock SageMaker) ====================

@app.route('/api/ml/models', methods=['GET'])
@require_auth
@require_role('admin', 'analyst')
def list_ml_models():
    """Lista modelos en el registry"""
    try:
        if not mock_sagemaker:
            return jsonify({'error': 'Mock SageMaker no disponible'}), 503
        
        model_name = request.args.get('model_name')
        max_results = int(request.args.get('max_results', 100))
        
        models = mock_sagemaker.list_models(
            model_name=model_name,
            max_results=max_results
        )
        
        return jsonify({
            'models': [
                {
                    'name': m['ModelName'],
                    'version': int(m['Version']),
                    'status': m['Status'],
                    'created': m['CreationTime'],
                    'size': int(m['ModelSize']),
                    'hash': m['ModelHash'][:16] + '...',
                    's3_location': m['S3Location']
                }
                for m in models
            ],
            'count': len(models)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/models/<model_name>', methods=['GET'])
@require_auth
@require_role('admin', 'analyst')
def get_ml_model_info(model_name):
    """Obtiene información de un modelo específico"""
    try:
        if not mock_sagemaker:
            return jsonify({'error': 'Mock SageMaker no disponible'}), 503
        
        version = request.args.get('version', type=int)
        
        models = mock_sagemaker.list_models(model_name=model_name)
        
        if not models:
            return jsonify({'error': f'Modelo {model_name} no encontrado'}), 404
        
        if version:
            model = next((m for m in models if int(m['Version']) == version), None)
            if not model:
                return jsonify({'error': f'Versión {version} no encontrada'}), 404
            return jsonify({'model': model})
        else:
            # Retornar todas las versiones
            return jsonify({
                'model_name': model_name,
                'versions': sorted(models, key=lambda x: int(x['Version']), reverse=True),
                'latest_version': max(int(m['Version']) for m in models)
            })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/performance', methods=['GET'])
@require_auth
@require_role('admin', 'analyst', 'viewer')
def get_ml_performance():
    """Retorna métricas reales de rendimiento de los modelos XGBoost e Isolation Forest"""
    _base = _REPO_ROOT / 'training' / 'results'

    xgb_metrics = {}
    if_metrics = {}
    xgb_trained_at = None
    if_trained_at = None

    try:
        metrics_path = _base / 'metrics.json'
        if metrics_path.exists():
            with open(metrics_path, 'r') as f:
                all_metrics = json.load(f)
            xgb = all_metrics.get('xgboost', {}).get('metrics', {})
            xgb_metrics = {
                'accuracy':  round(xgb.get('accuracy', 0) * 100, 2),
                'precision': round(xgb.get('precision', 0) * 100, 2),
                'recall':    round(xgb.get('recall', 0) * 100, 2),
                'f1_score':  round(xgb.get('f1_score', 0) * 100, 2),
            }
    except (OSError, json.JSONDecodeError, KeyError) as e:
        app.logger.warning(f"Could not load XGBoost metrics: {e}")

    try:
        if_path = _base / 'isolation_forest_metrics.json'
        if if_path.exists():
            with open(if_path, 'r') as f:
                ifm = json.load(f)
            if_metrics = {
                'precision':       round(ifm.get('precision', 0) * 100, 2),
                'recall':          round(ifm.get('recall', 0) * 100, 2),
                'f1_score':        round(ifm.get('f1_score', 0) * 100, 2),
                'precision_at_10': round(ifm.get('precision_at_10', 0) * 100, 2),
            }
            if_trained_at = ifm.get('timestamp')
    except (OSError, json.JSONDecodeError, KeyError) as e:
        app.logger.warning(f"Could not load Isolation Forest metrics: {e}")

    rf_metrics = {}
    try:
        metrics_path = _base / 'metrics.json'
        if metrics_path.exists():
            with open(metrics_path, 'r') as f:
                all_metrics = json.load(f)
            rf = all_metrics.get('random_forest', {}).get('metrics', {})
            rf_metrics = {
                'accuracy':  round(rf.get('accuracy', 0) * 100, 2),
                'precision': round(rf.get('precision', 0) * 100, 2),
                'recall':    round(rf.get('recall', 0) * 100, 2),
                'f1_score':  round(rf.get('f1_score', 0) * 100, 2),
                'auc_roc':   round(rf.get('auc_roc', 0) * 100, 2),
            }
    except (OSError, json.JSONDecodeError, KeyError) as e:
        app.logger.warning(f"Could not load Random Forest metrics: {e}")

    cross_dataset = {}
    try:
        cd_path = _base / 'cross_dataset_results.json'
        if cd_path.exists():
            with open(cd_path, 'r') as f:
                cd = json.load(f)
            cross_dataset = {
                'experiments': cd.get('experiments', []),
                'summary': cd.get('summary', {}),
            }
    except (OSError, json.JSONDecodeError, KeyError) as e:
        app.logger.warning(f"Could not load cross-dataset results: {e}")

    # Calcular tasa de detección real del WAF desde Redis
    waf_detection_rate = None
    try:
        if ip_blocker:
            blocked = ip_blocker.get_all_blocked_ips()
            auto_blocked = [b for b in blocked if b.get('auto_blocked')]
            if auto_blocked:
                waf_detection_rate = round(len(auto_blocked) / max(len(blocked), 1) * 100, 1)
    except Exception:
        pass

    return jsonify({
        'xgboost': {
            'metrics': xgb_metrics if xgb_metrics else {
                'accuracy': waf_detection_rate, 'precision': None,
                'recall': None, 'f1_score': None
            },
            'trained_at': xgb_trained_at,
            'status': 'active' if xgb_metrics else 'unavailable',
            'note': 'Modelo no entrenado — usando detección por firma WAF' if not xgb_metrics else None,
        },
        'isolation_forest': {
            'metrics': if_metrics,
            'trained_at': if_trained_at,
            'status': 'active' if if_metrics else 'unavailable',
        },
        'random_forest': {
            'metrics': rf_metrics,
            'status': 'experimental' if rf_metrics else 'unavailable',
        },
        'cross_dataset': cross_dataset,
        'waf_signature': {
            'status': 'active',
            'detection_rate': waf_detection_rate,
            'note': 'Detección basada en reglas de firma (activa)'
        }
    })


@app.route('/api/ml/training-jobs', methods=['GET'])
@require_auth
@require_role('admin', 'analyst')
def list_training_jobs():
    """Lista training jobs"""
    try:
        if not mock_sagemaker:
            return jsonify({'error': 'Mock SageMaker no disponible'}), 503
        
        max_results = int(request.args.get('max_results', 100))
        
        jobs = mock_sagemaker.list_training_jobs(max_results=max_results)
        
        return jsonify({
            'training_jobs': [
                {
                    'name': j['TrainingJobName'],
                    'status': j['Status'],
                    'created': j['CreationTime'],
                    'training_time': float(j.get('TrainingTime', 0)),
                    'model_name': j.get('ModelName'),
                    'hyperparameters': j.get('Hyperparameters', {})
                }
                for j in jobs
            ],
            'count': len(jobs)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/endpoints', methods=['GET'])
@require_auth
@require_role('admin', 'analyst')
def list_ml_endpoints():
    """Lista endpoints de inferencia"""
    try:
        if not mock_sagemaker:
            return jsonify({'error': 'Mock SageMaker no disponible'}), 503
        
        max_results = int(request.args.get('max_results', 100))
        
        endpoints = mock_sagemaker.list_endpoints(max_results=max_results)
        
        return jsonify({
            'endpoints': [
                {
                    'name': ep['EndpointName'],
                    'model': ep['ModelName'],
                    'version': ep.get('ModelVersion'),
                    'status': ep['Status'],
                    'created': ep['CreationTime'],
                    'invocations': int(ep.get('InvocationCount', 0))
                }
                for ep in endpoints
            ],
            'count': len(endpoints)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/predict', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
@validate_json(MLPredictSchema)
def ml_predict():
    """Realiza predicción usando un endpoint de ML (allowlist de endpoints en MLPredictSchema)."""
    try:
        if not mock_sagemaker:
            return jsonify({'error': 'Mock SageMaker no disponible'}), 503

        data = request.validated_data
        # V-12c: endpoint_name ya validado contra el allowlist por MLPredictSchema.
        endpoint_name = data['endpoint_name']
        features = data['features']

        prediction = mock_sagemaker.invoke_endpoint(
            endpoint_name=endpoint_name,
            data=features
        )

        return jsonify({
            'endpoint': endpoint_name,
            'prediction': prediction.tolist() if hasattr(prediction, 'tolist') else list(prediction),
            'timestamp': datetime.now().isoformat()
        })

    except ValueError as e:
        return jsonify({'error': str(e)}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/predict/threat', methods=['POST'])
@require_auth
@require_role('admin', 'analyst')
def predict_threat():
    """
    Endpoint especializado para predicción de amenazas.
    Usa el modelo threat-detector-prod si existe.
    """
    try:
        if not mock_sagemaker:
            return jsonify({'error': 'Mock SageMaker no disponible'}), 503
        
        data = request.json
        
        if not data:
            return jsonify({'error': 'Se requieren datos de tráfico'}), 400
        
        # Extraer features del tráfico
        features = [
            data.get('request_count', 0),
            data.get('error_rate', 0.0),
            data.get('avg_response_time', 0),
            data.get('unique_ips', 1)
        ]
        
        # Intentar usar endpoint de producción
        try:
            prediction = mock_sagemaker.invoke_endpoint(
                endpoint_name='threat-detector-prod',
                data=features
            )
            
            confidence = float(prediction[0])
            is_threat = confidence > 0.5
            
            return jsonify({
                'is_threat': is_threat,
                'confidence': confidence,
                'model': 'threat-detector-prod',
                'features': {
                    'request_count': features[0],
                    'error_rate': features[1],
                    'avg_response_time': features[2],
                    'unique_ips': features[3]
                },
                'timestamp': datetime.now().isoformat()
            })
            
        except ValueError:
            # Endpoint no existe
            return jsonify({
                'error': 'Endpoint threat-detector-prod no encontrado',
                'suggestion': 'Entrena un modelo primero usando /api/ml/train/threat-detector'
            }), 404
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/ml/stats', methods=['GET'])
@require_auth
@require_role('admin', 'analyst')
def ml_stats():
    """Estadísticas del sistema ML"""
    try:
        if not mock_sagemaker:
            return jsonify({'error': 'Mock SageMaker no disponible'}), 503
        
        models = mock_sagemaker.list_models()
        training_jobs = mock_sagemaker.list_training_jobs()
        endpoints = mock_sagemaker.list_endpoints()
        
        # Calcular estadísticas
        total_invocations = sum(int(ep.get('InvocationCount', 0)) for ep in endpoints)
        
        completed_jobs = [j for j in training_jobs if j['Status'] == 'Completed']
        failed_jobs = [j for j in training_jobs if j['Status'] == 'Failed']
        
        active_endpoints = [ep for ep in endpoints if ep['Status'] == 'InService']
        
        return jsonify({
            'models': {
                'total': len(models),
                'unique': len(set(m['ModelName'] for m in models))
            },
            'training_jobs': {
                'total': len(training_jobs),
                'completed': len(completed_jobs),
                'failed': len(failed_jobs),
                'success_rate': (len(completed_jobs) / len(training_jobs) * 100) if training_jobs else 0
            },
            'endpoints': {
                'total': len(endpoints),
                'active': len(active_endpoints),
                'total_invocations': total_invocations
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================
# ENDPOINTS DE BACKUP
# ============================================

@app.route('/api/backup/manual', methods=['POST'])
@require_auth
@require_role('admin')
def manual_backup():
    """Ejecuta un backup manual"""
    try:
        from app.aws.backup_service import backup_service
        from app.aws.backup_scheduler import BackupScheduler
        
        if not backup_service:
            return jsonify({'error': 'Backup service not available'}), 503
        
        data = request.get_json() or {}
        backup_type = data.get('backup_type', 'daily')
        
        if backup_type not in ['daily', 'weekly', 'monthly']:
            return jsonify({'error': 'Invalid backup_type. Must be: daily, weekly, monthly'}), 400
        
        # Ejecutar backup
        scheduler = BackupScheduler(backup_service)
        success = scheduler.run_manual_backup(backup_type)
        
        if success:
            return jsonify({
                'message': f'Backup {backup_type} completado exitosamente',
                'backup_type': backup_type,
                'timestamp': datetime.utcnow().isoformat()
            }), 200
        else:
            return jsonify({'error': 'Backup failed'}), 500
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/backup/list', methods=['GET'])
@require_auth
@require_role('admin', 'analyst')
def list_backups():
    """Lista backups disponibles"""
    try:
        from app.aws.backup_service import backup_service
        
        if not backup_service:
            return jsonify({'error': 'Backup service not available'}), 503
        
        backup_type = request.args.get('backup_type')
        resource_type = request.args.get('resource_type')
        
        backups = backup_service.list_backups(backup_type, resource_type)
        
        return jsonify({
            'backups': backups,
            'count': len(backups)
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/backup/restore', methods=['POST'])
@require_auth
@require_role('admin')
def restore_backup():
    """Restaura un backup"""
    try:
        from app.aws.backup_service import backup_service
        
        if not backup_service:
            return jsonify({'error': 'Backup service not available'}), 503
        
        data = request.get_json()
        
        if not data or 's3_key' not in data:
            return jsonify({'error': 'Missing s3_key'}), 400
        
        s3_key = data['s3_key']
        target_table = data.get('target_table')
        overwrite = data.get('overwrite', False)
        
        success = backup_service.restore_dynamodb_table(s3_key, target_table, overwrite)
        
        if success:
            return jsonify({
                'message': 'Backup restaurado exitosamente',
                's3_key': s3_key,
                'target_table': target_table or 'original'
            }), 200
        else:
            return jsonify({'error': 'Restore failed'}), 500
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# V-10: error handlers JSON — evitan que Flask devuelva HTML con banner del framework
@app.errorhandler(400)
def bad_request(_):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(401)
def unauthorized(_):
    return jsonify({'error': 'Unauthorized'}), 401

@app.errorhandler(403)
def forbidden(_):
    return jsonify({'error': 'Forbidden'}), 403

@app.errorhandler(404)
def not_found(_):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(429)
def too_many_requests(_):
    return jsonify({'error': 'Too many requests'}), 429

@app.errorhandler(500)
def internal_error(exc):
    app.logger.error(f"Internal server error: {exc}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    print("="*80)
    print("ATHENAI API BACKEND")
    print("="*80)
    print(f"\n🚀 Servidor iniciando en 0.0.0.0:5000 (acepta conexiones de cualquier IP)")
    print(f"📊 Modo: {'LocalStack' if USE_LOCALSTACK else 'AWS'}")
    print(f"🪣 S3 Bucket: {S3_BUCKET}")
    print("\n🌐 Accesible desde:")
    print("  • http://localhost:5000 (conexión local)")
    print("  • http://127.0.0.1:5000 (loopback)")
    print("  • http://<IP-de-esta-máquina>:5000 (red local/externa)")
    print("\n📡 Endpoints disponibles:")
    print("  GET /api/home          - Información general del sistema")
    print("  GET /api/stats         - Estadísticas generales")
    print("  GET /api/traffic       - Datos de tráfico")
    print("  GET /api/attacks       - Tipos de ataques")
    print("  GET /api/alerts        - Alertas recientes")
    print("  GET /api/health        - Estado del sistema")
    print("  GET /api/model-info    - Información de modelos ML")
    print("  GET /api/traffic-logs  - Logs de tráfico HTTP (con filtros)")
    print("  GET /api/traffic-stats - Estadísticas de tráfico HTTP")
    print("  POST /api/security/analyze - Analizar petición con Policy Engine")
    print("  GET /api/security/stats    - Estadísticas de seguridad")
    print("\n🤖 ML Endpoints (Mock SageMaker):")
    print("  GET /api/ml/models           - Listar modelos")
    print("  GET /api/ml/models/<name>    - Info de modelo")
    print("  GET /api/ml/training-jobs    - Listar training jobs")
    print("  GET /api/ml/endpoints        - Listar endpoints")
    print("  POST /api/ml/predict         - Predicción genérica")
    print("  POST /api/ml/predict/threat  - Predicción de amenazas")
    print("  GET /api/ml/stats            - Estadísticas ML")
    print("\n🔒 Sistema de logging de tráfico activado")
    print("⚖️ Policy Engine y Response Actions activados")
    print(f"🎯 IP de pruebas autorizadas: {os.getenv('AUTHORIZED_TEST_IP', 'No configurada')}")
    print("\n" + "="*80 + "\n")
    
    debug_mode = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000, threaded=True)
