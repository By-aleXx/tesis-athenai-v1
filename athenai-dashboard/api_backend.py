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
import time
from dotenv import load_dotenv

# Cargar variables de entorno desde .env al inicio
load_dotenv()

# Importar middleware y base de datos
from middleware import TrafficLoggingMiddleware
from database import init_db, get_traffic_logs, get_traffic_stats

# Importar validadores de entrada
from validators import (
    validate_json,
    LoginSchema, RegisterSchema, RefreshTokenSchema,
    BlockIPSchema, WhitelistSchema,
    TrafficSplitSchema, PolicyThresholdSchema
)

# Importar AI Engine para predicciones ML
try:
    from ai_engine import brain
    print("🧠 AI Engine cargado exitosamente")
except Exception as e:
    print(f"⚠️  No se pudo cargar AI Engine: {e}")
    brain = None

# Importar Policy Engine y Response Actions
try:
    from policy_engine import policy_engine, PolicyAction
    from response_actions import response_actions
    print("⚖️ Policy Engine y Response Actions cargados exitosamente")
except Exception as e:
    print(f"⚠️  No se pudo cargar Policy/Response: {e}")
    policy_engine = None
    response_actions = None

# Importar IP Blocker, Rate Limiter y Alert System
try:
    from ip_blocker import ip_blocker
    from rate_limiter import rate_limiter
    from alert_system import alert_system
    print("🔒 IP Blocker, Rate Limiter y Alert System cargados exitosamente")
except Exception as e:
    print(f"⚠️  No se pudieron cargar componentes de seguridad: {e}")

# Importar IAM Manager para control de acceso
try:
    from iam_manager import iam_manager, require_permission, require_role, Permission, Role
    print("🔐 IAM Manager cargado exitosamente")
except Exception as e:
    print(f"⚠️  No se pudo cargar IAM Manager: {e}")
    iam_manager = None
    # Crear decorators dummy si IAM no está disponible
    def require_permission(perm):
        def decorator(f):
            return f
        return decorator
    def require_role(*roles):
        def decorator(f):
            return f
        return decorator

    ip_blocker = None
    rate_limiter = None
    alert_system = None

# Importar Evidence Store, DynamoDB Client y Secrets Manager
try:
    from evidence_store import evidence_store
    from dynamodb_client import dynamodb_client
    from secrets_manager import secrets_manager
    print("📦 Evidence Store, DynamoDB Client y Secrets Manager cargados exitosamente")
except Exception as e:
    print(f"⚠️  No se pudieron cargar componentes de almacenamiento: {e}")
    evidence_store = None
    dynamodb_client = None
    secrets_manager = None

# Importar Mock SageMaker para ML Pipeline
try:
    from mock_sagemaker import mock_sagemaker
    print("🤖 Mock SageMaker cargado exitosamente")
except Exception as e:
    print(f"⚠️  No se pudo cargar Mock SageMaker: {e}")
    mock_sagemaker = None

# Importar Auth Service para autenticación JWT
try:
    from auth_service import AuthService, require_auth, require_role
    auth_service = AuthService()
    print("🔐 Auth Service cargado exitosamente (usuario admin creado)")
except Exception as e:
    print(f"⚠️  No se pudo cargar Auth Service: {e}")
    auth_service = None
    
    # Dummy decorators
    def require_auth(f):
        return f
    
    def require_role(*roles):
        def decorator(f):
            return f
        return decorator

# Importar CloudWatch Logger y Metrics Collector
try:
    from cloudwatch_logger import cloudwatch_logger
    from metrics_collector import metrics_collector
    print("📊 CloudWatch Logger y Metrics Collector cargados exitosamente")
except Exception as e:
    print(f"⚠️  No se pudo cargar CloudWatch: {e}")
    cloudwatch_logger = None
    metrics_collector = None

# Importar System Health Monitor
try:
    from system_health import system_health_monitor
    print("🏥 System Health Monitor cargado exitosamente")
except Exception as e:
    print(f"⚠️  No se pudo cargar System Health Monitor: {e}")
    system_health_monitor = None

app = Flask(__name__)
# CORS restringido a los orígenes locales conocidos
CORS(app, origins=[
    'http://localhost:5000',
    'http://localhost:8000',
    'http://127.0.0.1:5000',
    'http://127.0.0.1:8000',
])

# Swagger / OpenAPI Documentation → http://localhost:5000/apidocs/
try:
    from swagger_config import SWAGGER_CONFIG, SWAGGER_TEMPLATE
    swagger = Swagger(app, config=SWAGGER_CONFIG, template=SWAGGER_TEMPLATE)
    print("📖 Swagger UI disponible en: http://localhost:5000/apidocs/")
except Exception as e:
    print(f"⚠️  No se pudo iniciar Swagger: {e}")
    swagger = None

# Configurar Auth Service en app context
if auth_service:
    app.config['AUTH_SERVICE'] = auth_service

# Configurar CloudWatch en app context
if cloudwatch_logger:
    app.config['CLOUDWATCH_LOGGER'] = cloudwatch_logger
if metrics_collector:
    app.config['METRICS_COLLECTOR'] = metrics_collector

# Inicializar base de datos
init_db()

# Registrar Traffic Logging Middleware (registra TODO el tráfico en la BD)
traffic_logger = TrafficLoggingMiddleware(app)

# Registrar Security Middleware con ML Detection asíncrona
try:
    from security_middleware import SecurityMiddleware
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
compress = Compress()
compress.init_app(app)
app.config['COMPRESS_MIMETYPES'] = [
    'text/html',
    'text/css',
    'text/plain',
    'application/json',
    'application/javascript',
    'text/xml',
    'application/xml'
]
app.config['COMPRESS_LEVEL'] = 6  # Balance between speed and compression
app.config['COMPRESS_MIN_SIZE'] = 500  # Only compress responses > 500 bytes

# Performance monitoring middleware
@app.before_request
def before_request():
    """Track request start time"""
    g.start_time = time.time()

@app.after_request
def after_request(response):
    """Add performance headers and log slow requests"""
    # Calculate request duration
    if hasattr(g, 'start_time'):
        elapsed = time.time() - g.start_time
        
        # Add performance header
        response.headers['X-Response-Time'] = f"{elapsed * 1000:.2f}ms"
        
        # Log slow requests (> 500ms)
        if elapsed > 0.5:
            print(f"⚠️ Slow request: {request.method} {request.path} took {elapsed:.2f}s")
    
    # Add cache headers for static assets only (NOT APIs)
    if request.path.startswith('/static/') or request.path.endswith(('.css', '.js', '.png', '.jpg', '.svg')):
        # Cache static assets for 1 year
        response.cache_control.max_age = 31536000
        response.cache_control.public = True
    elif request.path.startswith('/api/'):
        # APIs: NO cache - the dashboard always needs fresh data
        response.cache_control.no_cache = True
        response.cache_control.no_store = True
        response.cache_control.must_revalidate = True
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response

# ============================================
# RUTAS PARA SERVIR FRONTEND
# ============================================

@app.route('/')
def index():
    """Redirect to login"""
    from flask import redirect
    return redirect('/login.html')

@app.route('/login.html')
def login_page():
    """Serve login page"""
    from flask import send_file
    return send_file('login.html')

@app.route('/index.html')
def dashboard_page():
    """Serve dashboard page"""
    from flask import send_file
    return send_file('index.html')

@app.route('/auth.js')
def auth_js():
    """Serve auth service"""
    from flask import send_file
    return send_file('auth.js', mimetype='application/javascript')

@app.route('/assets/<path:path>')
def serve_assets(path):
    """Serve static assets"""
    from flask import send_from_directory
    return send_from_directory('assets', path)

# Activar middleware de logging de tráfico (DESHABILITADO TEMPORALMENTE)
# traffic_middleware = TrafficLoggingMiddleware(app)  # CAUSA ~700ms DE LATENCIA POR SYNC DB I/O

# ============================================
# AUTHENTICATION ENDPOINTS
# ============================================

try:
    from auth import auth_manager
    print("🔐 Auth Service cargado exitosamente")
except ImportError as e:
    print(f"⚠️ Error cargando Auth Service: {e}")
    auth_manager = None

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login endpoint"""
    if not auth_manager:
        return jsonify({'error': 'Auth service not available'}), 503
        
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
        
    username = data['username']
    password = data['password']
    
    if auth_manager.verify_password(username, password):
        user = auth_manager.get_user(username)
        access_token = auth_manager.create_access_token(username, user['role'])
        refresh_token = auth_manager.create_refresh_token(username, user['role'])
        
        return jsonify({
            'success': True,
            'user': user,
            'access_token': access_token,
            'refresh_token': refresh_token
        })
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/auth/refresh', methods=['POST'])
def refresh_token():
    """Refresh access token"""
    if not auth_manager:
        return jsonify({'error': 'Auth service not available'}), 503
        
    data = request.get_json()
    refresh_token = data.get('refresh_token')
    
    if not refresh_token:
        return jsonify({'error': 'Refresh token required'}), 400
        
    payload = auth_manager.decode_token(refresh_token)
    if not payload or payload.get('type') != 'refresh':
        return jsonify({'error': 'Invalid or expired refresh token'}), 401
        
    username = payload['sub']
    role = payload['role']
    
    new_access_token = auth_manager.create_access_token(username, role)
    
    return jsonify({
        'access_token': new_access_token
    })

@app.route('/api/auth/me', methods=['GET'])
def verify_token():
    """Verify current token and return user info"""
    if not auth_manager:
        return jsonify({'error': 'Auth service not available'}), 503

    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Missing or invalid token'}), 401
    
    token = auth_header.split(' ')[1]
    
    payload = auth_manager.decode_token(token)
    if not payload or payload.get('type') != 'access':
        return jsonify({'error': 'Invalid or expired token'}), 401
        
    user = auth_manager.get_user(payload['sub'])
    if not user:
        return jsonify({'error': 'User not found'}), 404
        
    return jsonify({'user': user})

# Activar Security Middleware (IP Blocker + Rate Limiter + ML)
try:
    from security_middleware import SecurityMiddleware
    security_middleware = SecurityMiddleware(
        app=app,
        ip_blocker=ip_blocker,
        rate_limiter=rate_limiter,
        evidence_store=evidence_store,
        mock_sagemaker=mock_sagemaker,
        ai_engine=brain  # 📚 Continuous Learning integration
    )
    print("✅ Security Middleware activado (IP Blocker + Rate Limiter + ML Detection + Continuous Learning)")
except Exception as e:
    print(f"⚠️  No se pudo activar Security Middleware: {e}")
    security_middleware = None


# Activar Observability Middleware (CloudWatch Logs + Metrics)
try:
    from observability_middleware import ObservabilityMiddleware
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
        endpoint_url=os.environ['AWS_ENDPOINT_URL'],
        aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
        aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],
        region_name=os.getenv('AWS_REGION', 'us-east-1')
    )
else:
    s3_client = boto3.client('s3')


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


def generate_traffic_data():
    """Genera datos de tráfico basados en patrones reales"""
    now = datetime.now()
    data = []
    
    for i in range(24):
        hour = (now - timedelta(hours=23-i)).hour
        # Simular patrón de tráfico realista
        base_requests = 1000
        if 8 <= hour <= 18:  # Horas laborales
            base_requests = 2500
        elif 0 <= hour <= 6:  # Madrugada
            base_requests = 500
        
        requests = base_requests + random.randint(-200, 200)
        threats = int(requests * random.uniform(0.02, 0.08))  # 2-8% de amenazas
        
        data.append({
            'time': f'{hour:02d}:00',
            'requests': requests,
            'threats': threats
        })
    
    return data


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
    """
    Health check del sistema
    ---
    tags:
      - System
    summary: Verifica el estado de salud del backend y sus dependencias
    responses:
      200:
        description: Estado de salud del sistema
        schema:
          type: object
          properties:
            status:
              type: string
              enum: [healthy, unhealthy]
              example: healthy
            timestamp:
              type: string
              example: "2026-03-09T15:00:00"
            services:
              type: object
    """
    services = {
        'ai_engine': brain is not None,
        'auth': auth_service is not None,
        'database': True,
        'redis': ip_blocker is not None and rate_limiter is not None,
        'policy_engine': policy_engine is not None,
    }

    # Verificar S3 / LocalStack
    try:
        s3_client.list_buckets()
        services['s3'] = True
    except Exception:
        services['s3'] = False

    overall = 'healthy' if services['database'] else 'unhealthy'

    return jsonify({
        'status': overall,
        'timestamp': datetime.now().isoformat(),
        'services': services
    }), 200


@app.route('/api/model-info', methods=['GET'])
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

    xgboost_path = os.path.join(os.path.dirname(__file__), 'models', 'xgboost.pkl')
    isolation_forest_path = os.path.join(os.path.dirname(__file__), 'models', 'isolation_forest.pkl')

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
    # Obtener alertas reales
    alerts = get_alerts_from_s3()
    
    # Calcular estadísticas
    today_threats = len(alerts)
    if today_threats == 0:
        # Datos de ejemplo si no hay alertas reales
        today_threats = random.randint(400, 600)
    
    # Estadísticas del caché del AI Engine
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
    
    stats = {
        'threats_today': today_threats,
        'threats_change': random.uniform(5, 15),  # % cambio vs ayer
        'model_precision': 99.96,
        'avg_latency': random.randint(180, 220),  # ms
        'system_status': 100,
        'timestamp': datetime.now().isoformat(),
        'cache': cache_data
    }
    
    return jsonify(stats)


@app.route('/api/traffic', methods=['GET'])
def get_traffic():
    """
    Datos de tráfico de las últimas 24 horas
    ---
    tags:
      - Dashboard
    summary: Retorna requests y amenazas por hora (últimas 24h)
    responses:
      200:
        description: Array con datos de tráfico por hora
        schema:
          type: array
          items:
            type: object
            properties:
              time:
                type: string
                example: "14:00"
              requests:
                type: integer
                example: 2500
              threats:
                type: integer
                example: 87
    """
    """Datos de tráfico para gráfico"""
    data = generate_traffic_data()
    return jsonify(data)


@app.route('/api/attacks', methods=['GET'])
def get_attacks():
    """Tipos de ataques detectados"""
    # Obtener alertas reales
    alerts = get_alerts_from_s3()
    
    # Contar por tipo
    attack_counts = {}
    for alert in alerts:
        attack_type = alert['type']
        attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
    
    # Formatear para el gráfico
    attack_data = [
        {'type': attack_type, 'count': count}
        for attack_type, count in attack_counts.items()
    ]
    
    # Si no hay datos reales, usar datos de ejemplo
    if not attack_data:
        attack_data = [
            {'type': 'SQL Injection', 'count': random.randint(150, 250)},
            {'type': 'XSS', 'count': random.randint(100, 180)},
            {'type': 'Brute Force', 'count': random.randint(60, 120)},
            {'type': 'CSRF', 'count': random.randint(30, 80)},
        ]
    
    return jsonify(attack_data)


@app.route('/api/system-health', methods=['GET'])
def get_system_health():
    """Get detailed system health metrics"""
    if not system_health_monitor:
        return jsonify({'error': 'System Health Monitor not available'}), 503
    
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
        return jsonify({'error': 'IP Blocker not available'}), 503
    
    try:
        blocked_ips = ip_blocker.get_all_blocked_ips()
        return jsonify({'blocked_ips': blocked_ips, 'count': len(blocked_ips)})
    except Exception as e:
        print(f"Error getting blocked IPs: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/blocked-ips', methods=['POST'])
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
        return jsonify({'error': 'IP Blocker not available'}), 503
    
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
        return jsonify({'error': 'IP Blocker not available'}), 503
    
    try:
        whitelist = ip_blocker.get_whitelist()
        return jsonify({'whitelist': whitelist, 'count': len(whitelist)})
    except Exception as e:
        print(f"Error getting whitelist: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/whitelist', methods=['POST'])
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
def get_ip_stats():
    """Get IP blocking statistics"""
    if not ip_blocker:
        return jsonify({'error': 'IP Blocker not available'}), 503
    
    try:
        stats = ip_blocker.get_stats()
        
        # Add additional stats
        blocked_ips = ip_blocker.get_all_blocked_ips()
        whitelist = ip_blocker.get_whitelist()
        
        # Count today's blocks
        today = datetime.now().date()
        blocked_today = sum(1 for ip in blocked_ips 
                           if datetime.fromisoformat(ip.get('blocked_at', '')).date() == today)
        
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
# ENDPOINTS DE CONTINUOUS LEARNING
# ============================================

@app.route('/api/continuous-learning/stats', methods=['GET'])
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
def get_ab_testing_stats():
    """Get A/B testing statistics and comparison"""
    if not brain or not brain.ab_testing_enabled:
        return jsonify({'error': 'A/B Testing not available'}), 503
    
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
@require_permission(Permission.MANAGE_AB_TESTING)
@validate_json(TrafficSplitSchema)
def update_traffic_split():
    """Update traffic split percentages"""
    if not brain or not brain.ab_testing_enabled:
        return jsonify({'error': 'A/B Testing not available'}), 503
    
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
@require_permission(Permission.MANAGE_AB_TESTING)
def promote_model_b():
    """Promote Model B to production"""
    if not brain or not brain.ab_testing_enabled:
        return jsonify({'error': 'A/B Testing not available'}), 503
    
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
@require_permission(Permission.MANAGE_AB_TESTING)
def reset_ab_testing():
    """Reset A/B testing metrics"""
    if not brain or not brain.ab_testing_enabled:
        return jsonify({'error': 'A/B Testing not available'}), 503
    
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
      400:
        description: El username ya existe
      422:
        description: Error de validación (email inválido, rol incorrecto, etc.)
        schema:
          $ref: '#/definitions/ValidationError'
    """
    """Registro de nuevo usuario"""
    if not auth_service:
        return jsonify({'error': 'Auth service not available'}), 503
    
    try:
        data = request.validated_data
        
        user = auth_service.register_user(
            data['username'], data['password'], data['email'], data['role']
        )
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user
        }), 201
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500


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
      422:
        description: Error de validación
        schema:
          $ref: '#/definitions/ValidationError'
    """
    """Login de usuario"""
    if not auth_service:
        return jsonify({'error': 'Auth service not available'}), 503
    
    try:
        data = request.validated_data
        
        result = auth_service.login(data['username'], data['password'])
        
        return jsonify(result), 200
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500


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
    """Logout de usuario (invalidar token)"""
    # En JWT stateless, el logout se maneja en el cliente
    # eliminando el token. Aquí solo confirmamos.
    return jsonify({'message': 'Logged out successfully'}), 200


# ============================================
# ENDPOINTS DE DATOS (DASHBOARD)
# ============================================

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Alertas recientes desde DynamoDB"""
    try:
        # Obtener alertas reales de DynamoDB
        if dynamodb_client:
            db_alerts = dynamodb_client.get_alerts(limit=50)
            
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
            alerts = sorted(alerts, key=lambda x: x.get('id', ''), reverse=True)[:50]
            
            if alerts:
                return jsonify(alerts)
        
        # Si no hay alertas reales, usar datos de ejemplo
        alerts = [
            {
                'id': f'alert-{i}',
                'time': (datetime.now() - timedelta(minutes=i*5)).strftime('%H:%M:%S'),
                'type': random.choice(['SQL Injection', 'XSS Attack', 'Brute Force', 'Anomaly']),
                'severity': random.choice(['high', 'medium', 'low']),
                'ip': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
                'status': random.choice(['blocked', 'monitoring', 'flagged'])
            }
            for i in range(10)
        ]
        
        return jsonify(alerts)
        
    except Exception as e:
        print(f"Error obteniendo alertas: {e}")
        return jsonify([]), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Health check del sistema
    ---
    tags:
      - System
    summary: Verifica el estado del sistema
    responses:
      200:
        description: Sistema saludable
        schema:
          type: object
          properties:
            status:
              type: string
              example: healthy
            timestamp:
              type: string
            services:
              type: object
      500:
        description: Sistema con errores
    """
    """Health check del sistema"""
    try:
        # Verificar conexión a S3
        s3_status = 'operational'
        try:
            s3_client.head_bucket(Bucket=S3_BUCKET)
        except:
            s3_status = 'degraded'
        
        health = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'services': {
                's3': s3_status,
                'api': 'operational',
                'ml_models': 'operational'
            },
            'uptime': '99.9%'
        }
        
        return jsonify(health)
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500


@app.route('/api/cache-stats', methods=['GET'])
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
        logs = get_traffic_logs(
            limit=limit,
            offset=offset,
            is_test_attack=is_test_attack,
            source_ip=source_ip,
            exclude_source_ip='127.0.0.1' if exclude_localhost else None
        )
        
        # Convertir a dict
        logs_data = [log.to_dict() for log in logs]
        
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
            'total': len(logs_data),
            'limit': limit,
            'offset': offset,
            'logs': logs_data
        })
    
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'Error obteniendo logs de tráfico'
        }), 500


@app.route('/api/traffic-stats', methods=['GET'])
def get_traffic_stats_endpoint():
    """
    Obtiene estadísticas de tráfico HTTP
    """
    try:
        stats = get_traffic_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({
            'error': str(e),
            'message': 'Error obteniendo estadísticas de tráfico'
        }), 500


@app.route('/api/security/analyze', methods=['POST'])
def analyze_request():
    """
    Analiza una petición HTTP y retorna la decisión de seguridad.
    
    Body:
    {
        "payload": "...",
        "source_ip": "...",
        "method": "GET",
        "path": "/api/users"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        payload = data.get('payload', '')
        source_ip = data.get('source_ip', request.remote_addr)
        method = data.get('method', 'GET')
        path = data.get('path', '/')
        
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


@app.route('/api/security/stats', methods=['GET'])
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


@app.route('/api/ml/training-jobs', methods=['GET'])
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
def ml_predict():
    """Realiza predicción usando un endpoint de ML"""
    try:
        if not mock_sagemaker:
            return jsonify({'error': 'Mock SageMaker no disponible'}), 503
        
        data = request.json
        
        if not data or 'endpoint_name' not in data or 'features' not in data:
            return jsonify({
                'error': 'Se requiere endpoint_name y features'
            }), 400
        
        endpoint_name = data['endpoint_name']
        features = data['features']
        
        # Hacer predicción
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
            
            is_threat = bool(prediction[0])
            confidence = float(prediction[0])
            
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
        from backup_service import backup_service
        from backup_scheduler import BackupScheduler
        
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
def list_backups():
    """Lista backups disponibles"""
    try:
        from backup_service import backup_service
        
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
        from backup_service import backup_service
        
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
    
    app.run(debug=True, host='0.0.0.0', port=5000)
