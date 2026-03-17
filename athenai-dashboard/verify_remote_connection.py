#!/usr/bin/env python3
"""
Script de verificación de conectividad al servidor remoto
Verifica LocalStack, Redis y servicios AWS
"""

import boto3
import redis
import sys
from config import REMOTE_SERVER_IP, AWS_ENDPOINT_URL, REDIS_HOST, REDIS_PORT, get_aws_config

print("")
print("=" * 80)
print("  🌐 VERIFICACIÓN DE CONEXIÓN AL SERVIDOR REMOTO")
print("=" * 80)
print("")
print(f"  Servidor Principal: {REMOTE_SERVER_IP}")
print("")

# ============================================
# 1. VERIFICAR LOCALSTACK
# ============================================

print("📦 1. VERIFICANDO LOCALSTACK...")
print(f"   Endpoint: {AWS_ENDPOINT_URL}")

try:
    # Probar conexión con boto3
    aws_config = get_aws_config()
    
    # Test S3
    s3 = boto3.client('s3', **aws_config)
    buckets = s3.list_buckets()
    print(f"   ✅ S3 Conectado - {len(buckets['Buckets'])} buckets encontrados")
    
    # Test DynamoDB
    dynamodb = boto3.client('dynamodb', **aws_config)
    tables = dynamodb.list_tables()
    print(f"   ✅ DynamoDB Conectado - {len(tables['TableNames'])} tablas encontradas")
    
    # Test SNS
    sns = boto3.client('sns', **aws_config)
    topics = sns.list_topics()
    print(f"   ✅ SNS Conectado")
    
    localstack_ok = True
    
except Exception as e:
    print(f"   ❌ Error conectando a LocalStack: {e}")
    localstack_ok = False

print("")

# ============================================
# 2. VERIFICAR REDIS
# ============================================

print("🔴 2. VERIFICANDO REDIS...")
print(f"   Endpoint: {REDIS_HOST}:{REDIS_PORT}")

try:
    r = redis.Redis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        db=0,
        socket_timeout=5,
        socket_connect_timeout=5
    )
    
    # Test ping
    r.ping()
    print(f"   ✅ Redis Conectado")
    
    # Obtener info
    info = r.info('server')
    redis_version = info.get('redis_version', 'N/A')
    print(f"   ℹ️  Redis Version: {redis_version}")
    
    redis_ok = True
    
except Exception as e:
    print(f"   ❌ Error conectando a Redis: {e}")
    redis_ok = False

print("")

# ============================================
# 3. RESUMEN
# ============================================

print("=" * 80)
print("  📊 RESUMEN DE VERIFICACIÓN")
print("=" * 80)
print("")

if localstack_ok and redis_ok:
    print("  ✅ TODAS LAS CONEXIONES EXITOSAS")
    print("")
    print("  El sistema está configurado correctamente para usar:")
    print(f"  • Servidor Remoto: {REMOTE_SERVER_IP}")
    print(f"  • LocalStack: {AWS_ENDPOINT_URL}")
    print(f"  • Redis: {REDIS_HOST}:{REDIS_PORT}")
    print("")
    print("  AthenAI está listo para recibir tráfico usando infraestructura remota.")
    exit_code = 0
    
elif localstack_ok and not redis_ok:
    print("  ⚠️  ADVERTENCIA: Redis no accesible")
    print("")
    print("  • LocalStack: ✅ Funcionando")
    print("  • Redis: ❌ No accesible")
    print("")
    print("  El sistema funcionará parcialmente. Rate limiting no estará disponible.")
    exit_code = 1
    
elif not localstack_ok and redis_ok:
    print("  ⚠️  ADVERTENCIA: LocalStack no accesible")
    print("")
    print("  • LocalStack: ❌ No accesible")
    print("  • Redis: ✅ Funcionando")
    print("")
    print("  El sistema funcionará parcialmente. Almacenamiento en AWS no disponible.")
    exit_code = 1
    
else:
    print("  ❌ ERROR: No se pudo conectar al servidor remoto")
    print("")
    print("  • LocalStack: ❌ No accesible")
    print("  • Redis: ❌ No accesible")
    print("")
    print("  Verifica:")
    print(f"  1. ¿El servidor {REMOTE_SERVER_IP} está encendido?")
    print("  2. ¿Hay conectividad de red?")
    print("  3. ¿Los puertos 4566 y 6379 están abiertos?")
    exit_code = 2

print("")
print("=" * 80)
print("")

sys.exit(exit_code)
