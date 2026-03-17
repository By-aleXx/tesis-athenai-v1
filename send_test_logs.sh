#!/bin/bash

# AthenAI - Script para enviar logs de prueba a Kinesis
# Versión corregida con encoding base64 apropiado

set -e

STREAM_NAME="athenai-logs"
REGION="us-east-1"

echo "================================================================================"
echo "ATHENAI - ENVÍO DE LOGS DE PRUEBA A KINESIS"
echo "================================================================================"
echo ""

# Función para enviar log
send_log() {
    local data="$1"
    local description="$2"
    
    echo "📤 $description"
    
    # Codificar en base64
    local encoded=$(echo -n "$data" | base64)
    
    awslocal kinesis put-record \
        --stream-name $STREAM_NAME \
        --partition-key "test-$(date +%s)" \
        --data "$encoded" \
        --region $REGION \
        > /dev/null
    
    echo "   ✓ Enviado"
    echo ""
    sleep 2
}

echo "🧪 Enviando logs de prueba..."
echo ""

# 1. Tráfico normal
send_log '{"http_method":"GET","url_path":"/products?id=1","ip_address":"192.168.1.100","raw_log":"GET /products?id=1 HTTP/1.1"}' \
    "1️⃣  Tráfico Web Normal"

# 2. SQL Injection - UNION SELECT
send_log '{"http_method":"GET","url_path":"/api/users?id=1 UNION SELECT * FROM passwords--","ip_address":"203.0.113.50","raw_log":"GET /api/users?id=1 UNION SELECT * FROM passwords-- HTTP/1.1"}' \
    "2️⃣  SQL Injection (UNION SELECT)"

# 3. Boolean-based SQLi
send_log '{"http_method":"GET","url_path":"/login?user=admin OR 1=1","ip_address":"198.51.100.10","raw_log":"GET /login?user=admin OR 1=1 HTTP/1.1"}' \
    "3️⃣  Boolean-based SQL Injection"

# 4. Login normal
send_log '{"username":"john.doe","ip_address":"192.168.1.100","failed_attempts_count":0,"time_since_last_login":7200,"login_hour":14,"is_weekend":0,"unusual_location":0,"geo_distance_km":5,"session_duration_avg":1800}' \
    "4️⃣  Login Normal"

# 5. Brute Force Attack
send_log '{"username":"admin","ip_address":"203.0.113.50","failed_attempts_count":25,"time_since_last_login":60,"login_hour":3,"is_weekend":1,"unusual_location":1,"geo_distance_km":5000,"session_duration_avg":30}' \
    "5️⃣  Brute Force Attack"

# 6. XSS Attack
send_log '{"http_method":"POST","url_path":"/comment?text=<script>alert(XSS)</script>","ip_address":"198.51.100.25","raw_log":"POST /comment?text=<script>alert(XSS)</script> HTTP/1.1"}' \
    "6️⃣  XSS Attack"

# 7. Time-based SQLi
send_log '{"http_method":"GET","url_path":"/search?q=test AND SLEEP(5)--","ip_address":"203.0.113.75","raw_log":"GET /search?q=test AND SLEEP(5)-- HTTP/1.1"}' \
    "7️⃣  Time-based SQL Injection"

echo "================================================================================"
echo "✅ LOGS ENVIADOS"
echo "================================================================================"
echo ""
echo "📊 Total: 7 logs enviados a Kinesis"
echo ""
echo "⏳ Esperando procesamiento (10 segundos)..."
sleep 10
echo ""
echo "🔍 Verificando alertas generadas..."
echo ""

# Ver alertas en S3
ALERT_COUNT=$(awslocal s3 ls s3://athenai-alertas/alerts/ --recursive 2>/dev/null | wc -l)
echo "📊 Alertas generadas: $ALERT_COUNT"
echo ""

if [ $ALERT_COUNT -gt 0 ]; then
    echo "📄 Listado de alertas:"
    awslocal s3 ls s3://athenai-alertas/alerts/ --recursive
    echo ""
    
    # Descargar y mostrar una alerta de ejemplo
    FIRST_ALERT=$(awslocal s3 ls s3://athenai-alertas/alerts/ --recursive | head -1 | awk '{print $4}')
    if [ ! -z "$FIRST_ALERT" ]; then
        echo "📋 Ejemplo de alerta:"
        awslocal s3 cp s3://athenai-alertas/$FIRST_ALERT - 2>/dev/null | jq '.' 2>/dev/null || \
        awslocal s3 cp s3://athenai-alertas/$FIRST_ALERT - 2>/dev/null
    fi
else
    echo "⚠️  No se generaron alertas. Verifica los logs de Lambda:"
    echo "   awslocal logs tail /aws/lambda/athenai-detector --follow"
fi

echo ""
echo "================================================================================"
