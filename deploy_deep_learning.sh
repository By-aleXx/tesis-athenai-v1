#!/bin/bash
# AthenAI - Script de Deployment Optimizado para LocalStack
# DevOps Engineer: Deployment automatizado con limpieza y verificación

set -e  # Salir si hay errores

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración
FUNCTION_NAME="athenai-detector"
BUCKET_NAME="athenai-alertas"
STREAM_NAME="athenai-logs"
REGION="us-east-1"
ROLE_ARN="arn:aws:iam::000000000000:role/lambda-role"

echo -e "${BLUE}================================================================================${NC}"
echo -e "${BLUE}                  AthenAI - Deployment en LocalStack${NC}"
echo -e "${BLUE}================================================================================${NC}"
echo ""

# ============================================================================
# PASO 0: Verificar LocalStack
# ============================================================================
echo -e "${YELLOW}📡 Verificando LocalStack...${NC}"
if ! curl -s http://localhost:4566/_localstack/health > /dev/null 2>&1; then
    echo -e "${RED}❌ LocalStack no está corriendo${NC}"
    echo -e "${YELLOW}   Inicia LocalStack con: docker run -d -p 4566:4566 localstack/localstack${NC}"
    exit 1
fi
echo -e "${GREEN}✓ LocalStack está corriendo${NC}"
echo ""

# ============================================================================
# PASO 1: LIMPIEZA DE RECURSOS EXISTENTES
# ============================================================================
echo -e "${YELLOW}🗑️  PASO 1: Limpiando recursos existentes...${NC}"
echo ""

# Eliminar Event Source Mapping (si existe)
echo -e "  → Eliminando Event Source Mappings..."
MAPPINGS=$(awslocal lambda list-event-source-mappings \
    --function-name ${FUNCTION_NAME} \
    --region ${REGION} 2>/dev/null | jq -r '.EventSourceMappings[].UUID' || echo "")

if [ ! -z "$MAPPINGS" ]; then
    for UUID in $MAPPINGS; do
        awslocal lambda delete-event-source-mapping \
            --uuid $UUID \
            --region ${REGION} 2>/dev/null || true
        echo -e "    ${GREEN}✓${NC} Mapping eliminado: $UUID"
    done
else
    echo -e "    ${BLUE}ℹ${NC} No hay mappings para eliminar"
fi

sleep 2

# Eliminar función Lambda
echo -e "  → Eliminando función Lambda..."
awslocal lambda delete-function \
    --function-name ${FUNCTION_NAME} \
    --region ${REGION} 2>/dev/null && echo -e "    ${GREEN}✓${NC} Lambda eliminada" || echo -e "    ${BLUE}ℹ${NC} Lambda no existe"

sleep 2

# Eliminar Kinesis Stream
echo -e "  → Eliminando Kinesis Stream..."
awslocal kinesis delete-stream \
    --stream-name ${STREAM_NAME} \
    --region ${REGION} 2>/dev/null && echo -e "    ${GREEN}✓${NC} Stream eliminado" || echo -e "    ${BLUE}ℹ${NC} Stream no existe"

sleep 2

# Eliminar objetos de S3 y bucket
echo -e "  → Eliminando bucket S3..."
awslocal s3 rm s3://${BUCKET_NAME} --recursive 2>/dev/null || true
awslocal s3 rb s3://${BUCKET_NAME} 2>/dev/null && echo -e "    ${GREEN}✓${NC} Bucket eliminado" || echo -e "    ${BLUE}ℹ${NC} Bucket no existe"

sleep 2

echo -e "${GREEN}✓ Limpieza completada${NC}"
echo ""

# ============================================================================
# PASO 2: CREAR BUCKET S3
# ============================================================================
echo -e "${YELLOW}📦 PASO 2: Creando bucket S3...${NC}"
awslocal s3 mb s3://${BUCKET_NAME} --region ${REGION}
echo -e "${GREEN}✓ Bucket creado: s3://${BUCKET_NAME}${NC}"
echo ""

sleep 2

# ============================================================================
# PASO 3: CREAR KINESIS DATA STREAM
# ============================================================================
echo -e "${YELLOW}🌊 PASO 3: Creando Kinesis Data Stream...${NC}"
awslocal kinesis create-stream \
    --stream-name ${STREAM_NAME} \
    --shard-count 1 \
    --region ${REGION}

echo -e "${GREEN}✓ Stream creado: ${STREAM_NAME}${NC}"
echo ""

sleep 2

# Esperar a que el stream esté activo
echo -e "${YELLOW}⏳ Esperando que el stream esté activo...${NC}"
for i in {1..10}; do
    STATUS=$(awslocal kinesis describe-stream \
        --stream-name ${STREAM_NAME} \
        --region ${REGION} | jq -r '.StreamDescription.StreamStatus')
    
    if [ "$STATUS" == "ACTIVE" ]; then
        echo -e "${GREEN}✓ Stream está activo${NC}"
        break
    fi
    
    echo -e "  Intento $i/10: Status = $STATUS"
    sleep 2
done
echo ""

# ============================================================================
# PASO 4: EMPAQUETAR FUNCIÓN LAMBDA
# ============================================================================
echo -e "${YELLOW}📦 PASO 4: Empaquetando función Lambda...${NC}"

# Limpiar ZIP anterior
rm -f function.zip

# Crear ZIP con solo lambda_function.py
zip -q function.zip lambda_function.py

# Verificar que se creó
if [ -f "function.zip" ]; then
    SIZE=$(du -h function.zip | cut -f1)
    echo -e "${GREEN}✓ Paquete creado: function.zip (${SIZE})${NC}"
else
    echo -e "${RED}❌ Error creando paquete${NC}"
    exit 1
fi
echo ""

sleep 2

# ============================================================================
# PASO 5: CREAR FUNCIÓN LAMBDA
# ============================================================================
echo -e "${YELLOW}🚀 PASO 5: Creando función Lambda...${NC}"

awslocal lambda create-function \
    --function-name ${FUNCTION_NAME} \
    --runtime python3.9 \
    --role ${ROLE_ARN} \
    --handler lambda_function.lambda_handler \
    --zip-file fileb://function.zip \
    --timeout 60 \
    --memory-size 1024 \
    --region ${REGION} \
    --environment "Variables={ALERT_BUCKET=${BUCKET_NAME}}" \
    > /dev/null

echo -e "${GREEN}✓ Función Lambda creada: ${FUNCTION_NAME}${NC}"
echo ""

sleep 2

# Esperar a que la función esté activa
echo -e "${YELLOW}⏳ Esperando que la función esté activa...${NC}"
for i in {1..10}; do
    STATE=$(awslocal lambda get-function \
        --function-name ${FUNCTION_NAME} \
        --region ${REGION} 2>/dev/null | jq -r '.Configuration.State' || echo "Pending")
    
    if [ "$STATE" == "Active" ]; then
        echo -e "${GREEN}✓ Función está activa${NC}"
        break
    fi
    
    echo -e "  Intento $i/10: State = $STATE"
    sleep 2
done
echo ""

# ============================================================================
# PASO 6: CONECTAR KINESIS A LAMBDA (Event Source Mapping)
# ============================================================================
echo -e "${YELLOW}� PASO 6: Conectando Kinesis a Lambda...${NC}"

# Obtener ARN del stream
STREAM_ARN=$(awslocal kinesis describe-stream \
    --stream-name ${STREAM_NAME} \
    --region ${REGION} | jq -r '.StreamDescription.StreamARN')

echo -e "  Stream ARN: ${STREAM_ARN}"

# Crear Event Source Mapping
awslocal lambda create-event-source-mapping \
    --function-name ${FUNCTION_NAME} \
    --event-source-arn ${STREAM_ARN} \
    --batch-size 10 \
    --starting-position LATEST \
    --region ${REGION} \
    > /dev/null

echo -e "${GREEN}✓ Event Source Mapping creado${NC}"
echo ""

sleep 2

# ============================================================================
# PASO 7: VERIFICACIÓN FINAL
# ============================================================================
echo -e "${YELLOW}🔍 PASO 7: Verificando recursos creados...${NC}"
echo ""

# Verificar S3
echo -e "${BLUE}📦 Bucket S3:${NC}"
awslocal s3 ls | grep ${BUCKET_NAME} && echo -e "  ${GREEN}✓${NC} ${BUCKET_NAME}" || echo -e "  ${RED}✗${NC} No encontrado"
echo ""

# Verificar Kinesis
echo -e "${BLUE}🌊 Kinesis Stream:${NC}"
awslocal kinesis list-streams --region ${REGION} | jq -r '.StreamNames[]' | grep ${STREAM_NAME} && echo -e "  ${GREEN}✓${NC} ${STREAM_NAME}" || echo -e "  ${RED}✗${NC} No encontrado"
echo ""

# Verificar Lambda
echo -e "${BLUE}🚀 Función Lambda:${NC}"
LAMBDA_STATE=$(awslocal lambda get-function --function-name ${FUNCTION_NAME} --region ${REGION} 2>/dev/null | jq -r '.Configuration.State' || echo "NotFound")
if [ "$LAMBDA_STATE" == "Active" ]; then
    echo -e "  ${GREEN}✓${NC} ${FUNCTION_NAME} (State: ${LAMBDA_STATE})"
else
    echo -e "  ${RED}✗${NC} ${FUNCTION_NAME} (State: ${LAMBDA_STATE})"
fi
echo ""

# Verificar Event Source Mapping
echo -e "${BLUE}🔗 Event Source Mapping:${NC}"
MAPPING_COUNT=$(awslocal lambda list-event-source-mappings \
    --function-name ${FUNCTION_NAME} \
    --region ${REGION} 2>/dev/null | jq '.EventSourceMappings | length' || echo "0")

if [ "$MAPPING_COUNT" -gt 0 ]; then
    MAPPING_STATE=$(awslocal lambda list-event-source-mappings \
        --function-name ${FUNCTION_NAME} \
        --region ${REGION} | jq -r '.EventSourceMappings[0].State')
    echo -e "  ${GREEN}✓${NC} Kinesis → Lambda (State: ${MAPPING_STATE})"
else
    echo -e "  ${RED}✗${NC} No hay mappings configurados"
fi
echo ""

# ============================================================================
# RESUMEN FINAL
# ============================================================================
echo -e "${BLUE}================================================================================${NC}"
echo -e "${GREEN}✅ DEPLOYMENT COMPLETADO EXITOSAMENTE${NC}"
echo -e "${BLUE}================================================================================${NC}"
echo ""
echo -e "${BLUE}Recursos creados:${NC}"
echo -e "  • S3 Bucket:      ${BUCKET_NAME}"
echo -e "  • Kinesis Stream: ${STREAM_NAME}"
echo -e "  • Lambda:         ${FUNCTION_NAME}"
echo -e "  • Trigger:        Kinesis → Lambda"
echo ""
echo -e "${YELLOW}Próximos pasos:${NC}"
echo -e "  1. Probar con: ${GREEN}python3 test_pipeline.py${NC}"
echo -e "  2. Ver logs:   ${GREEN}awslocal logs tail /aws/lambda/${FUNCTION_NAME} --follow${NC}"
echo -e "  3. Ver alertas: ${GREEN}awslocal s3 ls s3://${BUCKET_NAME}/alerts/ --recursive${NC}"
echo ""
echo -e "${BLUE}================================================================================${NC}"
