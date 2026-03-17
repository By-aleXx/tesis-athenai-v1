#!/bin/bash
# AthenAI - Script de Limpieza de Entorno de Pruebas
# Limpia alertas de S3 y reinicia el entorno para nuevas pruebas

set -e

echo "================================================================================"
echo "AthenAI - Limpieza de Entorno de Pruebas"
echo "================================================================================"
echo ""

BUCKET_NAME="athenai-alertas"
STREAM_NAME="athenai-logs"

# Verificar LocalStack
echo "📡 Verificando LocalStack..."
if ! curl -s http://localhost:4566/_localstack/health > /dev/null; then
    echo "❌ LocalStack no está corriendo"
    exit 1
fi
echo "✓ LocalStack está corriendo"
echo ""

# Limpiar bucket S3
echo "🗑️  Limpiando alertas en S3..."
awslocal s3 rm s3://${BUCKET_NAME}/alerts/ --recursive 2>/dev/null || echo "  No hay alertas para limpiar"
echo "✓ Bucket S3 limpiado"
echo ""

# Limpiar shards de Kinesis (opcional - eliminar y recrear stream)
echo "🌊 Reiniciando Kinesis stream..."
awslocal kinesis delete-stream --stream-name ${STREAM_NAME} 2>/dev/null || echo "  Stream no existe"
sleep 2
awslocal kinesis create-stream --stream-name ${STREAM_NAME} --shard-count 1 2>/dev/null || echo "  Stream ya existe"
echo "✓ Kinesis stream reiniciado"
echo ""

echo "================================================================================"
echo "✅ ENTORNO LIMPIO Y LISTO PARA NUEVAS PRUEBAS"
echo "================================================================================"
echo ""
echo "Ejecuta las pruebas con: python test_pipeline.py"
echo ""
