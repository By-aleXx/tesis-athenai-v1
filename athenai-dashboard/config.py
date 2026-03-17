"""
AthenAI - Configuration File

Configuración centralizada para todos los componentes del sistema.
Soporta tanto infraestructura local como remota.

Autor: AthenAI Team
Fecha: 2026-02-11
"""

import os
from typing import Dict, Any
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

# ============================================================================
# CONFIGURACIÓN DE INFRAESTRUCTURA
# ============================================================================

# CORRECCIÓN #1: MIGRACIÓN A ARQUITECTURA DISTRIBUIDA CON TAILSCALE
# ⚠️  IMPORTANTE: Los servicios YA NO están en localhost
# LocalStack (DynamoDB/S3) y Redis ahora están en servidor remoto

# Infraestructura Remota (Dinosaurio Server)
USE_LOCALSTACK = True
REMOTE_SERVER_IP = os.environ['REMOTE_SERVER_IP']

# AWS / LocalStack Configuration
AWS_ENDPOINT_URL = os.environ['AWS_ENDPOINT_URL']
DYNAMODB_ENDPOINT = os.environ['AWS_ENDPOINT_URL']
S3_ENDPOINT = os.environ['AWS_ENDPOINT_URL']
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']
AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']

# Redis Configuration
REDIS_HOST = os.environ['REDIS_HOST']
REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD') or None
REDIS_DB = 0

# ============================================================================
# CONFIGURACIÓN DE SERVICIOS AWS
# ============================================================================

# S3 Configuration
S3_BUCKET_EVIDENCE = "athenai-evidence"
S3_BUCKET_ALERTS = "athenai-alertas"

# DynamoDB Configuration
DYNAMODB_TABLE_TRAFFIC_LOGS = "athenai_traffic_logs"
DYNAMODB_TABLE_SECURITY_ALERTS = "athenai_security_alerts"
DYNAMODB_TABLE_BLOCKED_IPS = "athenai_blocked_ips"

# Secrets Manager Configuration
SECRETS_PREFIX = "athenai/"

# ============================================================================
# CONFIGURACIÓN DE SEGURIDAD
# ============================================================================

# IP Blocker Configuration
IP_BLOCKER_DEFAULT_DURATION = 3600  # 1 hora en segundos
IP_BLOCKER_WHITELIST = [
    "127.0.0.1",
    "::1",
    REMOTE_SERVER_IP  # Whitelist del servidor remoto
]

# Rate Limiter Configuration
RATE_LIMIT_GLOBAL = 100  # requests por minuto
RATE_LIMIT_API = 60
RATE_LIMIT_SECURITY = 10
RATE_LIMIT_AUTH = 30  # Aumentado de 5 a 30 para desarrollo/testing

# Policy Engine Configuration
POLICY_ENGINE_DEFAULT_THRESHOLD_LOW = 30.0
POLICY_ENGINE_DEFAULT_THRESHOLD_MEDIUM = 60.0
POLICY_ENGINE_DEFAULT_THRESHOLD_HIGH = 80.0

# ============================================================================
# CONFIGURACIÓN DE ALERTAS
# ============================================================================

# Alert System Configuration
ALERT_EMAIL_ENABLED = True
ALERT_SMS_ENABLED = True
ALERT_SLACK_ENABLED = True

# Email Configuration (SES)
ALERT_EMAIL_FROM = "security@athenai.com"
ALERT_EMAIL_TO = ["admin@athenai.com"]

# SMS Configuration (SNS)
ALERT_SMS_PHONE_NUMBERS = ["+1234567890"]

# Slack Configuration
ALERT_SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# ============================================================================
# CONFIGURACIÓN DE LOGGING
# ============================================================================

# Evidence Store Configuration
EVIDENCE_STORE_ENABLED = True
EVIDENCE_STORE_HASH_ALGORITHM = "sha256"
EVIDENCE_STORE_HMAC_ENABLED = True

# Logging Configuration
LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# ============================================================================
# CONFIGURACIÓN DE FLASK
# ============================================================================

# Flask Configuration
FLASK_HOST = "0.0.0.0"
FLASK_PORT = 5000
FLASK_DEBUG = True
FLASK_ENV = "development"

# CORS Configuration
CORS_ORIGINS = ["*"]  # En producción, especificar dominios permitidos

# ============================================================================
# FUNCIONES DE UTILIDAD
# ============================================================================

def get_aws_config() -> Dict[str, Any]:
    """
    Retorna la configuración de AWS/LocalStack.
    
    Returns:
        Dict con configuración de AWS
    """
    from botocore.config import Config as BotocoreConfig
    
    boto_config = BotocoreConfig(
        connect_timeout=5,   # máximo 5s de espera para conectar
        read_timeout=10,     # máximo 10s de espera para leer respuesta
        retries={'max_attempts': 1}  # sin reintentos adicionales
    )
    
    config = {
        "region_name": AWS_REGION,
        "aws_access_key_id": AWS_ACCESS_KEY_ID,
        "aws_secret_access_key": AWS_SECRET_ACCESS_KEY,
        "config": boto_config
    }
    
    if USE_LOCALSTACK:
        config["endpoint_url"] = AWS_ENDPOINT_URL
    
    return config


def get_redis_config() -> Dict[str, Any]:
    """
    Retorna la configuración de Redis.
    
    Returns:
        Dict con configuración de Redis
    """
    config = {
        "host": REDIS_HOST,
        "port": REDIS_PORT,
        "db": REDIS_DB,
        "decode_responses": True,
        "socket_timeout": 2,          # 2s: startup rápido si Tailscale no responde
        "socket_connect_timeout": 2,  # 2s: evita bloquear el arranque del backend
        "socket_keepalive": True,     # Mantener conexión viva con Tailscale
        "retry_on_timeout": True,     # Reintentar en caso de timeout
        "health_check_interval": 30   # Reconexión automática cada 30s si se cae
    }
    
    if REDIS_PASSWORD:
        config["password"] = REDIS_PASSWORD
    
    return config


def get_s3_buckets() -> Dict[str, str]:
    """
    Retorna los nombres de los buckets S3.
    
    Returns:
        Dict con nombres de buckets
    """
    return {
        "evidence": S3_BUCKET_EVIDENCE,
        "alerts": S3_BUCKET_ALERTS
    }


def get_dynamodb_tables() -> Dict[str, str]:
    """
    Retorna los nombres de las tablas DynamoDB.
    
    Returns:
        Dict con nombres de tablas
    """
    return {
        "traffic_logs": DYNAMODB_TABLE_TRAFFIC_LOGS,
        "security_alerts": DYNAMODB_TABLE_SECURITY_ALERTS,
        "blocked_ips": DYNAMODB_TABLE_BLOCKED_IPS
    }


def get_rate_limits() -> Dict[str, int]:
    """
    Retorna los límites de tasa configurados.
    
    Returns:
        Dict con límites de tasa
    """
    return {
        "global": RATE_LIMIT_GLOBAL,
        "api": RATE_LIMIT_API,
        "security": RATE_LIMIT_SECURITY,
        "auth": RATE_LIMIT_AUTH
    }


def print_config():
    """Imprime la configuración actual del sistema"""
    print("=" * 80)
    print("ATHENAI - CONFIGURACIÓN DEL SISTEMA")
    print("=" * 80)
    print(f"\n🌐 INFRAESTRUCTURA:")
    print(f"  Servidor Remoto: {REMOTE_SERVER_IP}")
    print(f"  LocalStack: {AWS_ENDPOINT_URL}")
    print(f"  Redis: {REDIS_HOST}:{REDIS_PORT}")
    
    print(f"\n☁️  AWS SERVICES:")
    print(f"  Región: {AWS_REGION}")
    print(f"  S3 Buckets: {S3_BUCKET_EVIDENCE}, {S3_BUCKET_ALERTS}")
    print(f"  DynamoDB Tables: {len(get_dynamodb_tables())} tablas")
    
    print(f"\n🔒 SEGURIDAD:")
    print(f"  IP Blocker: Habilitado")
    print(f"  Rate Limiter: {RATE_LIMIT_GLOBAL} req/min (global)")
    print(f"  Evidence Store: {'Habilitado' if EVIDENCE_STORE_ENABLED else 'Deshabilitado'}")
    
    print(f"\n🚨 ALERTAS:")
    print(f"  Email: {'✅' if ALERT_EMAIL_ENABLED else '❌'}")
    print(f"  SMS: {'✅' if ALERT_SMS_ENABLED else '❌'}")
    print(f"  Slack: {'✅' if ALERT_SLACK_ENABLED else '❌'}")
    
    print(f"\n🌍 FLASK:")
    print(f"  Host: {FLASK_HOST}")
    print(f"  Port: {FLASK_PORT}")
    print(f"  Debug: {FLASK_DEBUG}")
    print("=" * 80)


if __name__ == "__main__":
    print_config()
