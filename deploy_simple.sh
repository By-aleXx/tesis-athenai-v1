#!/bin/bash

# ============================================================================
# AthenAI - Script de Deployment Simplificado (Sin Kinesis)
# Para LocalStack con limitaciones de Kinesis
# ============================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuración
LOCALSTACK_ENDPOINT="http://localhost:4566"
AWS_REGION="us-east-1"
BUCKET_NAME="athenai-alertas"
FUNCTION_NAME="athenai-detector"
LAMBDA_ROLE="arn:aws:iam::000000000000:role/lambda-role"

echo -e "${BLUE}============================================================================${NC}"
echo -e "${BLUE}AthenAI - Deployment Simplificado en LocalStack${NC}"
echo -e "${BLUE}============================================================================${NC}\n"

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=$AWS_REGION

# ============================================================================
# 1. VERIFICAR/CREAR BUCKET S3
# ============================================================================
echo -e "${YELLOW}[1/4] Verificando bucket S3: ${BUCKET_NAME}${NC}"

if aws --endpoint-url=$LOCALSTACK_ENDPOINT s3 ls s3://$BUCKET_NAME 2>/dev/null; then
    echo -e "${GREEN}✓ Bucket ya existe${NC}"
else
    aws --endpoint-url=$LOCALSTACK_ENDPOINT s3 mb s3://$BUCKET_NAME
    echo -e "${GREEN}✓ Bucket creado${NC}"
fi

# ============================================================================
# 2. EMPAQUETAR LAMBDA
# ============================================================================
echo -e "\n${YELLOW}[2/4] Empaquetando función Lambda${NC}"

rm -rf lambda_package
mkdir -p lambda_package
cp lambda_function.py lambda_package/
cd lambda_package
zip -q lambda_function.zip lambda_function.py
cd ..

echo -e "${GREEN}✓ Función empaquetada${NC}"

# ============================================================================
# 3. CREAR ROL IAM
# ============================================================================
echo -e "\n${YELLOW}[3/4] Configurando rol IAM${NC}"

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

# ============================================================================
# 4. DESPLEGAR LAMBDA
# ============================================================================
echo -e "\n${YELLOW}[4/4] Desplegando función Lambda${NC}"

if aws --endpoint-url=$LOCALSTACK_ENDPOINT lambda get-function --function-name $FUNCTION_NAME 2>/dev/null; then
    echo -e "${YELLOW}  Actualizando código...${NC}"
    aws --endpoint-url=$LOCALSTACK_ENDPOINT lambda update-function-code \
        --function-name $FUNCTION_NAME \
        --zip-file fileb://lambda_package/lambda_function.zip > /dev/null
    echo -e "${GREEN}✓ Código actualizado${NC}"
else
    echo -e "${YELLOW}  Creando función...${NC}"
    aws --endpoint-url=$LOCALSTACK_ENDPOINT lambda create-function \
        --function-name $FUNCTION_NAME \
        --runtime python3.9 \
        --role $LAMBDA_ROLE \
        --handler lambda_function.lambda_handler \
        --zip-file fileb://lambda_package/lambda_function.zip \
        --timeout 60 \
        --memory-size 256 \
        --environment "Variables={ALERT_BUCKET=$BUCKET_NAME}" > /dev/null
    echo -e "${GREEN}✓ Función creada${NC}"
fi

# ============================================================================
# RESUMEN
# ============================================================================
echo -e "\n${BLUE}============================================================================${NC}"
echo -e "${GREEN}✓ DEPLOYMENT COMPLETADO${NC}"
echo -e "${BLUE}============================================================================${NC}\n"

echo -e "${YELLOW}Recursos desplegados:${NC}"
echo -e "  • S3 Bucket:        ${GREEN}${BUCKET_NAME}${NC}"
echo -e "  • Lambda Function:  ${GREEN}${FUNCTION_NAME}${NC}"

echo -e "\n${YELLOW}Nota:${NC} Kinesis no está disponible en esta versión de LocalStack."
echo -e "       Usaremos invocación directa de Lambda para pruebas.\n"

echo -e "${YELLOW}Próximo paso:${NC}"
echo -e "  Ejecutar: ${BLUE}./test_lambda_direct.sh${NC} para probar el sistema\n"

echo -e "${BLUE}============================================================================${NC}\n"
