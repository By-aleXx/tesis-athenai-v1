#!/bin/bash

# AthenAI - Script de Deployment Optimizado en LocalStack
# Versión ligera sin dependencias pesadas innecesarias

set -e

echo "================================================================================"
echo "ATHENAI - DEPLOYMENT OPTIMIZADO EN LOCALSTACK"
echo "Sistema Híbrido de Detección (XGBoost + Isolation Forest)"
echo "================================================================================"
echo ""

# Configuración
FUNCTION_NAME="athenai-detector"
STREAM_NAME="athenai-logs"
BUCKET_NAME="athenai-alertas"
REGION="us-east-1"
ENDPOINT="http://localhost:4566"

# Esperar a que LocalStack esté listo
echo "⏳ Esperando a que LocalStack esté listo..."
sleep 5

# Verificar que LocalStack está corriendo
if ! curl -s $ENDPOINT/_localstack/health > /dev/null; then
    echo "❌ Error: LocalStack no está corriendo"
    exit 1
fi

echo "✓ LocalStack está listo"
echo ""

# Limpiar deployment anterior
echo "🧹 Limpiando deployment anterior..."
rm -rf lambda_package_lite
rm -f lambda_deployment_lite.zip

# Crear directorio de paquete
echo "📦 Creando paquete Lambda optimizado..."
mkdir -p lambda_package_lite/models

# Copiar función Lambda
echo "  📄 Copiando lambda_function_hybrid.py..."
cp lambda_function_hybrid.py lambda_package_lite/lambda_function.py

# Copiar modelos
echo "  🤖 Copiando modelos ML..."
cp training/models/xgboost.pkl lambda_package_lite/models/
cp training/models/feature_engineer.pkl lambda_package_lite/models/
cp training/models/isolation_forest.pkl lambda_package_lite/models/
cp training/models/auth_scaler.pkl lambda_package_lite/models/
echo "    ✓ 4 modelos copiados"

# Instalar solo dependencias esenciales (sin tests, docs, etc.)
echo ""
echo "📚 Instalando dependencias optimizadas..."
pip install -q -t lambda_package_lite/ \
    --no-cache-dir \
    --no-compile \
    scikit-learn==1.3.0 \
    xgboost==1.7.6 \
    joblib==1.3.1 \
    numpy==1.24.3 \
    pandas==2.0.3 \
    2>&1 | head -5

echo "  ✓ Dependencias instaladas"

# Limpiar archivos innecesarios para reducir tamaño
echo ""
echo "🧹 Optimizando tamaño del paquete..."
cd lambda_package_lite

# Eliminar tests, docs, ejemplos
find . -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "test" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "doc" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "docs" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "examples" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true
find . -name "*.pyo" -delete 2>/dev/null || true
find . -name "*.so" -type f ! -name "*cpython*" -delete 2>/dev/null || true

echo "  ✓ Archivos innecesarios eliminados"

# Crear ZIP
echo ""
echo "📦 Creando archivo ZIP..."
zip -r -q ../lambda_deployment_lite.zip .
cd ..

ZIP_SIZE=$(du -h lambda_deployment_lite.zip | cut -f1)
echo "  ✓ lambda_deployment_lite.zip creado ($ZIP_SIZE)"

# Verificar tamaño
ZIP_BYTES=$(stat -f%z lambda_deployment_lite.zip 2>/dev/null || stat -c%s lambda_deployment_lite.zip)
MAX_SIZE=$((50 * 1024 * 1024))  # 50 MB

if [ $ZIP_BYTES -gt $MAX_SIZE ]; then
    echo "  ⚠️  Advertencia: Paquete muy grande ($ZIP_SIZE > 50MB)"
    echo "     LocalStack puede aceptarlo, pero AWS Lambda no"
fi

# Crear bucket S3
echo ""
echo "🪣 Creando bucket S3..."
awslocal s3 mb s3://$BUCKET_NAME --region $REGION 2>/dev/null || echo "  ℹ️  Bucket ya existe"
echo "  ✓ Bucket: s3://$BUCKET_NAME"

# Crear Kinesis Data Stream
echo ""
echo "🌊 Creando Kinesis Data Stream..."
awslocal kinesis create-stream \
    --stream-name $STREAM_NAME \
    --shard-count 1 \
    --region $REGION 2>/dev/null || echo "  ℹ️  Stream ya existe"

sleep 3
echo "  ✓ Stream: $STREAM_NAME"

# Crear rol IAM
echo ""
echo "👤 Creando rol IAM..."
ROLE_ARN="arn:aws:iam::000000000000:role/lambda-execution-role"
echo "  ✓ Rol: $ROLE_ARN"

# Eliminar función Lambda si existe
echo ""
echo "🗑️  Eliminando función Lambda anterior..."
awslocal lambda delete-function \
    --function-name $FUNCTION_NAME \
    --region $REGION 2>/dev/null || echo "  ℹ️  Función no existía"

# Crear función Lambda
echo ""
echo "🚀 Desplegando función Lambda..."
awslocal lambda create-function \
    --function-name $FUNCTION_NAME \
    --runtime python3.9 \
    --role $ROLE_ARN \
    --handler lambda_function.lambda_handler \
    --zip-file fileb://lambda_deployment_lite.zip \
    --timeout 60 \
    --memory-size 1024 \
    --region $REGION \
    --environment "Variables={ALERT_BUCKET=$BUCKET_NAME}" \
    > /dev/null

echo "  ✓ Función creada: $FUNCTION_NAME"
echo "  ✓ Runtime: python3.9"
echo "  ✓ Memory: 1024 MB"
echo "  ✓ Timeout: 60s"

# Obtener ARN del stream
STREAM_ARN=$(awslocal kinesis describe-stream \
    --stream-name $STREAM_NAME \
    --region $REGION \
    --query 'StreamDescription.StreamARN' \
    --output text)

# Crear event source mapping
echo ""
echo "🔗 Conectando Kinesis con Lambda..."
awslocal lambda create-event-source-mapping \
    --function-name $FUNCTION_NAME \
    --event-source-arn $STREAM_ARN \
    --starting-position LATEST \
    --region $REGION \
    > /dev/null

echo "  ✓ Event source mapping creado"

# Resumen
echo ""
echo "================================================================================"
echo "✅ DEPLOYMENT COMPLETADO"
echo "================================================================================"
echo ""
echo "📊 Recursos creados:"
echo "  • Lambda Function: $FUNCTION_NAME ($ZIP_SIZE)"
echo "  • Kinesis Stream:  $STREAM_NAME"
echo "  • S3 Bucket:       $BUCKET_NAME"
echo ""
echo "🧪 Para probar el sistema:"
echo "  ./send_test_logs.sh"
echo ""
echo "🔍 Ver resultados:"
echo "  awslocal s3 ls s3://$BUCKET_NAME/alerts/ --recursive"
echo ""
echo "================================================================================"
