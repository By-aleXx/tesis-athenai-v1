# ===============================================================================
# SCRIPT PARA CONSULTAR LOGS DEL SERVIDOR REMOTO (100.108.127.116)
# AthenAI - Sistema de Detección de Intrusiones
# ===============================================================================

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("traffic", "alerts", "s3", "redis", "all")]
    [string]$Tipo = "all",
    
    [Parameter(Mandatory=$false)]
    [int]$Limite = 10
)

$REMOTE_SERVER = "100.108.127.116"
$LOCALSTACK_PORT = "4566"
$REDIS_PORT = "6379"

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  CONSULTA DE LOGS DEL SERVIDOR REMOTO - AthenAI IDS" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "🌐 Servidor Remoto: $REMOTE_SERVER" -ForegroundColor Yellow
Write-Host "📊 Tipo de consulta: $Tipo" -ForegroundColor Yellow
Write-Host ""

# ===============================================================================
# 1. LOGS DE TRÁFICO EN DYNAMODB
# ===============================================================================
if ($Tipo -eq "traffic" -or $Tipo -eq "all") {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host "📋 LOGS DE TRÁFICO (DynamoDB)" -ForegroundColor Green
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host ""
    
    try {
        $trafficLogs = aws dynamodb scan `
            --table-name athenai_traffic_logs `
            --endpoint-url "http://${REMOTE_SERVER}:${LOCALSTACK_PORT}" `
            --max-items $Limite `
            --output json 2>&1 | ConvertFrom-Json
        
        if ($trafficLogs.Items) {
            Write-Host "✅ Encontrados $($trafficLogs.Items.Count) registros de tráfico:" -ForegroundColor Green
            Write-Host ""
            
            foreach ($log in $trafficLogs.Items) {
                $timestamp = $log.timestamp.S
                $ip = $log.ip_address.S
                $method = $log.method.S
                $path = $log.path.S
                $status = $log.status_code.N
                
                $statusColor = if ($status -lt 400) { "Green" } elseif ($status -lt 500) { "Yellow" } else { "Red" }
                
                Write-Host "  [$timestamp]" -ForegroundColor DarkGray -NoNewline
                Write-Host " $ip" -ForegroundColor Cyan -NoNewline
                Write-Host " $method" -ForegroundColor White -NoNewline
                Write-Host " $path" -ForegroundColor Yellow -NoNewline
                Write-Host " [$status]" -ForegroundColor $statusColor
            }
            Write-Host ""
        } else {
            Write-Host "ℹ️  No hay logs de tráfico disponibles" -ForegroundColor Yellow
            Write-Host ""
        }
    } catch {
        Write-Host "❌ Error consultando logs de tráfico: $_" -ForegroundColor Red
        Write-Host "   Verifica que AWS CLI esté instalado y LocalStack esté corriendo" -ForegroundColor DarkGray
        Write-Host ""
    }
}

# ===============================================================================
# 2. ALERTAS DE SEGURIDAD EN DYNAMODB
# ===============================================================================
if ($Tipo -eq "alerts" -or $Tipo -eq "all") {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host "🚨 ALERTAS DE SEGURIDAD (DynamoDB)" -ForegroundColor Green
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host ""
    
    try {
        $alerts = aws dynamodb scan `
            --table-name athenai_security_alerts `
            --endpoint-url "http://${REMOTE_SERVER}:${LOCALSTACK_PORT}" `
            --max-items $Limite `
            --output json 2>&1 | ConvertFrom-Json
        
        if ($alerts.Items) {
            Write-Host "✅ Encontradas $($alerts.Items.Count) alertas de seguridad:" -ForegroundColor Green
            Write-Host ""
            
            foreach ($alert in $alerts.Items) {
                $timestamp = $alert.timestamp.S
                $severity = $alert.severity.S
                $message = $alert.message.S
                
                $severityColor = switch ($severity) {
                    "critical" { "Red" }
                    "high" { "Magenta" }
                    "medium" { "Yellow" }
                    default { "White" }
                }
                
                Write-Host "  [$timestamp]" -ForegroundColor DarkGray -NoNewline
                Write-Host " [$severity]" -ForegroundColor $severityColor -NoNewline
                Write-Host " $message" -ForegroundColor White
            }
            Write-Host ""
        } else {
            Write-Host "ℹ️  No hay alertas de seguridad" -ForegroundColor Yellow
            Write-Host ""
        }
    } catch {
        Write-Host "❌ Error consultando alertas: $_" -ForegroundColor Red
        Write-Host ""
    }
}

# ===============================================================================
# 3. EVIDENCIAS EN S3
# ===============================================================================
if ($Tipo -eq "s3" -or $Tipo -eq "all") {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host "📦 EVIDENCIAS EN S3" -ForegroundColor Green
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host ""
    
    try {
        $s3Objects = aws s3 ls s3://athenai-evidence/ `
            --endpoint-url "http://${REMOTE_SERVER}:${LOCALSTACK_PORT}" `
            --recursive 2>&1
        
        if ($s3Objects) {
            Write-Host "✅ Evidencias almacenadas en S3:" -ForegroundColor Green
            Write-Host ""
            Write-Host $s3Objects
            Write-Host ""
        } else {
            Write-Host "ℹ️  No hay evidencias almacenadas" -ForegroundColor Yellow
            Write-Host ""
        }
    } catch {
        Write-Host "❌ Error consultando S3: $_" -ForegroundColor Red
        Write-Host ""
    }
}

# ===============================================================================
# 4. REDIS (IPs BLOQUEADAS)
# ===============================================================================
if ($Tipo -eq "redis" -or $Tipo -eq "all") {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host "🔴 REDIS - IPs BLOQUEADAS" -ForegroundColor Green
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host ""
    
    try {
        # Verificar si redis-cli está disponible
        $redisInstalled = Get-Command redis-cli -ErrorAction SilentlyContinue
        
        if ($redisInstalled) {
            $blockedIPs = redis-cli -h $REMOTE_SERVER -p $REDIS_PORT SMEMBERS blocked_ips 2>&1
            
            if ($blockedIPs) {
                Write-Host "✅ IPs bloqueadas actualmente:" -ForegroundColor Green
                Write-Host ""
                foreach ($ip in $blockedIPs) {
                    Write-Host "  🚫 $ip" -ForegroundColor Red
                }
                Write-Host ""
            } else {
                Write-Host "ℹ️  No hay IPs bloqueadas actualmente" -ForegroundColor Yellow
                Write-Host ""
            }
        } else {
            Write-Host "⚠️  redis-cli no está instalado" -ForegroundColor Yellow
            Write-Host "   Instala Redis CLI para consultar IPs bloqueadas" -ForegroundColor DarkGray
            Write-Host ""
        }
    } catch {
        Write-Host "❌ Error consultando Redis: $_" -ForegroundColor Red
        Write-Host ""
    }
}

# ===============================================================================
# RESUMEN Y AYUDA
# ===============================================================================
Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "💡 COMANDOS DISPONIBLES:" -ForegroundColor Yellow
Write-Host ""
Write-Host "   .\ver_logs_remotos.ps1 -Tipo traffic         # Solo logs de tráfico" -ForegroundColor White
Write-Host "   .\ver_logs_remotos.ps1 -Tipo alerts          # Solo alertas de seguridad" -ForegroundColor White
Write-Host "   .\ver_logs_remotos.ps1 -Tipo s3              # Solo evidencias S3" -ForegroundColor White
Write-Host "   .\ver_logs_remotos.ps1 -Tipo redis           # Solo IPs bloqueadas" -ForegroundColor White
Write-Host "   .\ver_logs_remotos.ps1 -Tipo all -Limite 20  # Todos los logs (20 items)" -ForegroundColor White
Write-Host ""
Write-Host "🔍 LOGS EN TIEMPO REAL:" -ForegroundColor Yellow
Write-Host "   • Presiona Ctrl+`` en VS Code para ver el terminal de Python" -ForegroundColor White
Write-Host "   • Endpoint API: http://localhost:5000/api/traffic-logs" -ForegroundColor White
Write-Host ""
