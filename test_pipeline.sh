#!/bin/bash

# ============================================================================
# AthenAI - Script de Prueba del Pipeline Completo
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
STREAM_NAME="athenai-logs"
BUCKET_NAME="athenai-alertas"

export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=$AWS_REGION

echo -e "${BLUE}============================================================================${NC}"
echo -e "${BLUE}AthenAI - Prueba del Pipeline de Detección${NC}"
echo -e "${BLUE}============================================================================${NC}\n"

# ============================================================================
# LOGS DE PRUEBA
# ============================================================================

# Array de logs de prueba (algunos maliciosos, otros legítimos)
declare -a TEST_LOGS=(
    # Log legítimo 1
    "192.168.1.100 - - [20/Jan/2026:15:30:45 +0000] \"GET /products?id=1 HTTP/1.1\" 200 1234"
    
    # Log malicioso 1: Boolean-based Blind SQL Injection
    "192.168.1.101 - - [20/Jan/2026:15:31:12 +0000] \"GET /login?user=admin' OR '1'='1 HTTP/1.1\" 200 5678"
    
    # Log legítimo 2
    "192.168.1.102 - - [20/Jan/2026:15:31:45 +0000] \"POST /search?q=laptop HTTP/1.1\" 200 2345"
    
    # Log malicioso 2: UNION-based SQL Injection
    "192.168.1.103 - - [20/Jan/2026:15:32:10 +0000] \"GET /api/users?id=1 UNION SELECT * FROM passwords-- HTTP/1.1\" 200 3456"
    
    # Log legítimo 3
    "192.168.1.104 - - [20/Jan/2026:15:32:30 +0000] \"GET /about HTTP/1.1\" 200 4567"
    
    # Log malicioso 3: Time-based Blind SQL Injection
    "192.168.1.105 - - [20/Jan/2026:15:33:00 +0000] \"GET /products?id=1; SELECT SLEEP(5)-- HTTP/1.1\" 200 5678"
    
    # Log malicioso 4: Stacked Queries
    "192.168.1.106 - - [20/Jan/2026:15:33:30 +0000] \"POST /update?id=1; DROP TABLE users-- HTTP/1.1\" 200 6789"
)

echo -e "${YELLOW}Enviando ${#TEST_LOGS[@]} logs de prueba al stream de Kinesis...${NC}\n"

# ============================================================================
# ENVIAR LOGS A KINESIS
# ============================================================================

for i in "${!TEST_LOGS[@]}"; do
    log="${TEST_LOGS[$i]}"
    
    echo -e "${BLUE}[$((i+1))/${#TEST_LOGS[@]}]${NC} Enviando log..."
    echo -e "  ${log:0:80}..."
    
    # Enviar log a Kinesis
    aws --endpoint-url=$LOCALSTACK_ENDPOINT kinesis put-record \
        --stream-name $STREAM_NAME \
        --partition-key "test-$i" \
        --data "$log" \
        --output json > /dev/null
    
    echo -e "${GREEN}  ✓ Enviado${NC}\n"
    
    # Pequeña pausa para no saturar
    sleep 1
done

echo -e "${GREEN}✓ Todos los logs enviados exitosamente${NC}\n"

# ============================================================================
# ESPERAR PROCESAMIENTO
# ============================================================================

echo -e "${YELLOW}Esperando procesamiento de Lambda (10 segundos)...${NC}"
sleep 10

# ============================================================================
# VERIFICAR ALERTAS EN S3
# ============================================================================

echo -e "\n${BLUE}============================================================================${NC}"
echo -e "${BLUE}Verificando alertas generadas en S3${NC}"
echo -e "${BLUE}============================================================================${NC}\n"

# Listar alertas
ALERTS=$(aws --endpoint-url=$LOCALSTACK_ENDPOINT s3 ls s3://$BUCKET_NAME/alerts/ --recursive)

if [ -z "$ALERTS" ]; then
    echo -e "${RED}✗ No se encontraron alertas en S3${NC}"
    echo -e "${YELLOW}  Esto puede significar:${NC}"
    echo -e "${YELLOW}  1. La Lambda no se ejecutó correctamente${NC}"
    echo -e "${YELLOW}  2. No se detectaron amenazas (poco probable con estos logs)${NC}"
    echo -e "${YELLOW}  3. Hay un problema con el trigger Kinesis->Lambda${NC}"
    echo -e "\n${YELLOW}Verifica los logs de Lambda:${NC}"
    echo -e "${BLUE}  awslocal logs tail /aws/lambda/athenai-detector --follow${NC}\n"
else
    echo -e "${GREEN}✓ Alertas encontradas:${NC}\n"
    echo "$ALERTS"
    
    # Contar alertas
    ALERT_COUNT=$(echo "$ALERTS" | wc -l)
    echo -e "\n${GREEN}Total de alertas generadas: ${ALERT_COUNT}${NC}"
    
    # Mostrar contenido de la primera alerta
    echo -e "\n${YELLOW}Mostrando contenido de la primera alerta:${NC}\n"
    
    FIRST_ALERT=$(echo "$ALERTS" | head -n 1 | awk '{print $4}')
    
    aws --endpoint-url=$LOCALSTACK_ENDPOINT s3 cp \
        s3://$BUCKET_NAME/$FIRST_ALERT - | jq '.'
fi

# ============================================================================
# RESUMEN
# ============================================================================

echo -e "\n${BLUE}============================================================================${NC}"
echo -e "${BLUE}RESUMEN DE LA PRUEBA${NC}"
echo -e "${BLUE}============================================================================${NC}\n"

echo -e "${YELLOW}Logs enviados:${NC}        ${#TEST_LOGS[@]}"
echo -e "${YELLOW}Logs maliciosos:${NC}      4 (SQL Injection detectables)"
echo -e "${YELLOW}Logs legítimos:${NC}       3"

if [ ! -z "$ALERTS" ]; then
    echo -e "${YELLOW}Alertas generadas:${NC}    ${GREEN}${ALERT_COUNT}${NC}"
    echo -e "\n${GREEN}✓ PIPELINE FUNCIONANDO CORRECTAMENTE${NC}"
else
    echo -e "${YELLOW}Alertas generadas:${NC}    ${RED}0${NC}"
    echo -e "\n${RED}✗ REVISAR CONFIGURACIÓN${NC}"
fi

echo -e "\n${YELLOW}Comandos útiles:${NC}"
echo -e "  • Ver logs Lambda:    ${BLUE}awslocal logs tail /aws/lambda/athenai-detector --follow${NC}"
echo -e "  • Listar alertas:     ${BLUE}awslocal s3 ls s3://${BUCKET_NAME}/alerts/ --recursive${NC}"
echo -e "  • Ver alerta:         ${BLUE}awslocal s3 cp s3://${BUCKET_NAME}/alerts/YYYY/MM/DD/alert-xxx.json -${NC}"
echo -e "  • Limpiar alertas:    ${BLUE}awslocal s3 rm s3://${BUCKET_NAME}/alerts/ --recursive${NC}"

echo -e "\n${BLUE}============================================================================${NC}\n"
