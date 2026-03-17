#!/bin/bash

# ============================================================================
# AthenAI - Script de Deployment en LocalStack
# ============================================================================

set -e  # Salir si hay errores

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
LOCALSTACK_ENDPOINT="http://localhost:4566"
AWS_REGION="us-east-1"
BUCKET_NAME="athenai-alertas"
STREAM_NAME="athenai-logs"
FUNCTION_NAME="athenai-detector"
LAMBDA_ROLE="arn:aws:iam::000000000000:role/lambda-role"

echo -e "${BLUE}============================================================================${NC}"
echo -e "${BLUE}AthenAI - Deployment en LocalStack${NC}"
echo -e "${BLUE}============================================================================${NC}\n"

# Configurar AWS CLI para LocalStack
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=$AWS_REGION

# ============================================================================
# 1. CREAR BUCKET S3
# ============================================================================
echo -e "${YELLOW}[1/6] Creando bucket S3: ${BUCKET_NAME}${NC}"

if aws --endpoint-url=$LOCALSTACK_ENDPOINT s3 ls s3://$BUCKET_NAME 2>/dev/null; then
    echo -e "${GREEN}✓ Bucket ya existe${NC}"
else
    aws --endpoint-url=$LOCALSTACK_ENDPOINT s3 mb s3://$BUCKET_NAME
    echo -e "${GREEN}✓ Bucket creado exitosamente${NC}"
fi

# ============================================================================
# 2. CREAR KINESIS DATA STREAM
# ============================================================================
echo -e "\n${YELLOW}[2/6] Creando Kinesis Data Stream: ${STREAM_NAME}${NC}"

if aws --endpoint-url=$LOCALSTACK_ENDPOINT kinesis describe-stream --stream-name $STREAM_NAME 2>/dev/null; then
    echo -e "${GREEN}✓ Stream ya existe${NC}"
else
    aws --endpoint-url=$LOCALSTACK_ENDPOINT kinesis create-stream \
        --stream-name $STREAM_NAME \
        --shard-count 1
    
    echo -e "${GREEN}✓ Stream creado exitosamente${NC}"
    
    # Esperar a que el stream esté activo
    echo -e "${YELLOW}  Esperando a que el stream esté activo...${NC}"
    sleep 3
fi

# ============================================================================
# 3. EMPAQUETAR LAMBDA FUNCTION
# ============================================================================
echo -e "\n${YELLOW}[3/6] Empaquetando función Lambda${NC}"

# Crear directorio temporal para el paquete
rm -rf lambda_package
mkdir -p lambda_package

# Copiar el código de la función
cp lambda_function.py lambda_package/

# Crear archivo ZIP
cd lambda_package
zip -q lambda_function.zip lambda_function.py
cd ..

echo -e "${GREEN}✓ Función empaquetada: lambda_package/lambda_function.zip${NC}"

# ============================================================================
# 4. CREAR ROL IAM (LocalStack no lo requiere pero lo creamos por consistencia)
# ============================================================================
echo -e "\n${YELLOW}[4/6] Configurando rol IAM${NC}"

# En LocalStack, los roles son simulados, pero los creamos para mantener consistencia
aws --endpoint-url=$LOCALSTACK_ENDPOINT iam create-role \
    --role-name lambda-role \
    --assume-role-policy-document '{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole"
        }]
    }' 2>/dev/null || echo -e "${GREEN}✓ Rol ya existe${NC}"

echo -e "${GREEN}✓ Rol IAM configurado${NC}"

# ============================================================================
# 5. DESPLEGAR LAMBDA FUNCTION
# ============================================================================
echo -e "\n${YELLOW}[5/6] Desplegando función Lambda: ${FUNCTION_NAME}${NC}"

# Verificar si la función ya existe
if aws --endpoint-url=$LOCALSTACK_ENDPOINT lambda get-function --function-name $FUNCTION_NAME 2>/dev/null; then
    echo -e "${YELLOW}  Función ya existe, actualizando código...${NC}"
    
    aws --endpoint-url=$LOCALSTACK_ENDPOINT lambda update-function-code \
        --function-name $FUNCTION_NAME \
        --zip-file fileb://lambda_package/lambda_function.zip
    
    echo -e "${GREEN}✓ Código actualizado${NC}"
else
    echo -e "${YELLOW}  Creando nueva función Lambda...${NC}"
    
    aws --endpoint-url=$LOCALSTACK_ENDPOINT lambda create-function \
        --function-name $FUNCTION_NAME \
        --runtime python3.9 \
        --role $LAMBDA_ROLE \
        --handler lambda_function.lambda_handler \
        --zip-file fileb://lambda_package/lambda_function.zip \
        --timeout 60 \
        --memory-size 256 \
        --environment "Variables={ALERT_BUCKET=$BUCKET_NAME}"
    
    echo -e "${GREEN}✓ Función Lambda creada${NC}"
fi

# ============================================================================
# 6. CONFIGURAR TRIGGER KINESIS -> LAMBDA
# ============================================================================
echo -e "\n${YELLOW}[6/6] Configurando trigger Kinesis -> Lambda${NC}"

# Obtener ARN del stream
STREAM_ARN=$(aws --endpoint-url=$LOCALSTACK_ENDPOINT kinesis describe-stream \
    --stream-name $STREAM_NAME \
    --query 'StreamDescription.StreamARN' \
    --output text)

echo -e "${BLUE}  Stream ARN: ${STREAM_ARN}${NC}"

# Crear event source mapping
aws --endpoint-url=$LOCALSTACK_ENDPOINT lambda create-event-source-mapping \
    --function-name $FUNCTION_NAME \
    --event-source-arn $STREAM_ARN \
    --starting-position LATEST \
    --batch-size 10 2>/dev/null || echo -e "${GREEN}✓ Trigger ya existe${NC}"

echo -e "${GREEN}✓ Trigger configurado${NC}"

# ============================================================================
# RESUMEN
# ============================================================================
echo -e "\n${BLUE}============================================================================${NC}"
echo -e "${GREEN}✓ DEPLOYMENT COMPLETADO EXITOSAMENTE${NC}"
echo -e "${BLUE}============================================================================${NC}\n"

echo -e "${YELLOW}Recursos creados:${NC}"
echo -e "  • S3 Bucket:        ${GREEN}${BUCKET_NAME}${NC}"
echo -e "  • Kinesis Stream:   ${GREEN}${STREAM_NAME}${NC}"
echo -e "  • Lambda Function:  ${GREEN}${FUNCTION_NAME}${NC}"

echo -e "\n${YELLOW}Endpoints de LocalStack:${NC}"
echo -e "  • General:          ${BLUE}${LOCALSTACK_ENDPOINT}${NC}"
echo -e "  • S3:               ${BLUE}${LOCALSTACK_ENDPOINT}/${BUCKET_NAME}${NC}"

echo -e "\n${YELLOW}Próximos pasos:${NC}"
echo -e "  1. Ejecutar: ${BLUE}./test_pipeline.sh${NC} para probar el sistema"
echo -e "  2. Ver logs: ${BLUE}awslocal logs tail /aws/lambda/${FUNCTION_NAME} --follow${NC}"
echo -e "  3. Ver alertas: ${BLUE}awslocal s3 ls s3://${BUCKET_NAME}/alerts/ --recursive${NC}"

echo -e "\n${BLUE}============================================================================${NC}\n"
