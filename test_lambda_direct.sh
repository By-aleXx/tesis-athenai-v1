#!/bin/bash

# ============================================================================
# AthenAI - Prueba Directa de Lambda (Sin Kinesis)
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
FUNCTION_NAME="athenai-detector"
BUCKET_NAME="athenai-alertas"

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=$AWS_REGION

echo -e "${BLUE}============================================================================${NC}"
echo -e "${BLUE}AthenAI - Prueba Directa de Lambda${NC}"
echo -e "${BLUE}============================================================================${NC}\n"

# ============================================================================
# CREAR EVENTO SIMULADO DE KINESIS
# ============================================================================

# Logs de prueba
LOG1="192.168.1.100 - - [20/Jan/2026:15:30:45 +0000] \"GET /products?id=1 HTTP/1.1\" 200 1234"
LOG2="192.168.1.101 - - [20/Jan/2026:15:31:12 +0000] \"GET /login?user=admin' OR '1'='1 HTTP/1.1\" 200 5678"
LOG3="192.168.1.102 - - [20/Jan/2026:15:31:45 +0000] \"POST /search?q=laptop HTTP/1.1\" 200 2345"
LOG4="192.168.1.103 - - [20/Jan/2026:15:32:10 +0000] \"GET /api/users?id=1 UNION SELECT * FROM passwords-- HTTP/1.1\" 200 3456"

# Codificar logs en base64
LOG1_B64=$(echo -n "$LOG1" | base64)
LOG2_B64=$(echo -n "$LOG2" | base64)
LOG3_B64=$(echo -n "$LOG3" | base64)
LOG4_B64=$(echo -n "$LOG4" | base64)

# Crear evento de Kinesis simulado
cat > test_event.json <<EOF
{
  "Records": [
    {
      "kinesis": {
        "data": "$LOG1_B64",
        "partitionKey": "test-1"
      }
    },
    {
      "kinesis": {
        "data": "$LOG2_B64",
        "partitionKey": "test-2"
      }
    },
    {
      "kinesis": {
        "data": "$LOG3_B64",
        "partitionKey": "test-3"
      }
    },
    {
      "kinesis": {
        "data": "$LOG4_B64",
        "partitionKey": "test-4"
      }
    }
  ]
}
EOF

echo -e "${YELLOW}Evento de prueba creado con 4 logs:${NC}"
echo -e "  1. ${GREEN}Legítimo${NC}:  GET /products?id=1"
echo -e "  2. ${RED}Malicioso${NC}: admin' OR '1'='1 (Boolean-based Blind)"
echo -e "  3. ${GREEN}Legítimo${NC}:  POST /search?q=laptop"
echo -e "  4. ${RED}Malicioso${NC}: UNION SELECT (UNION-based Injection)"

# ============================================================================
# INVOCAR LAMBDA
# ============================================================================

echo -e "\n${YELLOW}Invocando función Lambda...${NC}\n"

aws --endpoint-url=$LOCALSTACK_ENDPOINT lambda invoke \
    --function-name $FUNCTION_NAME \
    --payload file://test_event.json \
    --cli-binary-format raw-in-base64-out \
    response.json

echo -e "\n${YELLOW}Respuesta de Lambda:${NC}"
cat response.json | jq '.'

# ============================================================================
# VERIFICAR ALERTAS EN S3
# ============================================================================

echo -e "\n${BLUE}============================================================================${NC}"
echo -e "${BLUE}Verificando alertas en S3${NC}"
echo -e "${BLUE}============================================================================${NC}\n"

sleep 2  # Dar tiempo para que se guarden las alertas

ALERTS=$(aws --endpoint-url=$LOCALSTACK_ENDPOINT s3 ls s3://$BUCKET_NAME/alerts/ --recursive 2>/dev/null || echo "")

if [ -z "$ALERTS" ]; then
    echo -e "${RED}✗ No se encontraron alertas${NC}"
    echo -e "${YELLOW}  Verificando logs de Lambda...${NC}\n"
    
    # Intentar obtener logs
    aws --endpoint-url=$LOCALSTACK_ENDPOINT logs tail /aws/lambda/$FUNCTION_NAME 2>/dev/null || \
        echo -e "${YELLOW}  No se pudieron obtener logs de CloudWatch${NC}"
else
    echo -e "${GREEN}✓ Alertas encontradas:${NC}\n"
    echo "$ALERTS"
    
    ALERT_COUNT=$(echo "$ALERTS" | wc -l)
    echo -e "\n${GREEN}Total de alertas: ${ALERT_COUNT}${NC}"
    
    # Mostrar primera alerta
    echo -e "\n${YELLOW}Contenido de la primera alerta:${NC}\n"
    FIRST_ALERT=$(echo "$ALERTS" | head -n 1 | awk '{print $4}')
    aws --endpoint-url=$LOCALSTACK_ENDPOINT s3 cp s3://$BUCKET_NAME/$FIRST_ALERT - | jq '.'
fi

# ============================================================================
# RESUMEN
# ============================================================================

echo -e "\n${BLUE}============================================================================${NC}"
echo -e "${BLUE}RESUMEN${NC}"
echo -e "${BLUE}============================================================================${NC}\n"

echo -e "${YELLOW}Logs procesados:${NC}      4"
echo -e "${YELLOW}Logs maliciosos:${NC}      2 (esperados)"
echo -e "${YELLOW}Logs legítimos:${NC}       2"

if [ ! -z "$ALERTS" ]; then
    echo -e "${YELLOW}Alertas generadas:${NC}    ${GREEN}${ALERT_COUNT}${NC}"
    
    if [ "$ALERT_COUNT" -eq 2 ]; then
        echo -e "\n${GREEN}✓✓✓ SISTEMA FUNCIONANDO PERFECTAMENTE ✓✓✓${NC}"
    else
        echo -e "\n${YELLOW}⚠ Se esperaban 2 alertas, se generaron ${ALERT_COUNT}${NC}"
    fi
else
    echo -e "${YELLOW}Alertas generadas:${NC}    ${RED}0${NC}"
    echo -e "\n${RED}✗ Revisar configuración${NC}"
fi

echo -e "\n${YELLOW}Comandos útiles:${NC}"
echo -e "  • Listar alertas:     ${BLUE}aws --endpoint-url=$LOCALSTACK_ENDPOINT s3 ls s3://${BUCKET_NAME}/alerts/ --recursive${NC}"
echo -e "  • Ver alerta:         ${BLUE}aws --endpoint-url=$LOCALSTACK_ENDPOINT s3 cp s3://${BUCKET_NAME}/alerts/[path] -${NC}"
echo -e "  • Limpiar alertas:    ${BLUE}aws --endpoint-url=$LOCALSTACK_ENDPOINT s3 rm s3://${BUCKET_NAME}/alerts/ --recursive${NC}"
echo -e "  • Re-ejecutar prueba: ${BLUE}./test_lambda_direct.sh${NC}"

echo -e "\n${BLUE}============================================================================${NC}\n"

# Limpiar archivos temporales
rm -f test_event.json response.json
