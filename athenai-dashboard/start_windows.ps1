# AthenAI Dashboard - Script de Inicio para Windows
# Autor: AthenAI Team
# Fecha: 2026-02-18

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "ATHENAI DASHBOARD - INICIO (Windows)" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Navegar al directorio correcto
Set-Location -Path $PSScriptRoot



# Activar entorno virtual
Write-Host "🔧 Activando entorno virtual..." -ForegroundColor Yellow
if (Test-Path "venv_win\Scripts\Activate.ps1") {
    & ".\venv_win\Scripts\Activate.ps1"
    Write-Host "   ✓ Entorno virtual activado" -ForegroundColor Green
} else {
    Write-Host "   ❌ ERROR: Entorno virtual no encontrado" -ForegroundColor Red
    Write-Host "   Ejecuta: python -m venv venv_win" -ForegroundColor Yellow
    exit 1
}

# Verificar dependencias
Write-Host ""
Write-Host "📦 Verificando dependencias..." -ForegroundColor Yellow
try {
    python -c "import flask, boto3, redis, sklearn" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   ✓ Dependencias verificadas" -ForegroundColor Green
    } else {
        Write-Host "   ⚠️  Instalando dependencias faltantes..." -ForegroundColor Yellow
        pip install -r requirements.txt -q
    }
} catch {
    Write-Host "   ⚠️  Instalando dependencias..." -ForegroundColor Yellow
    pip install -r requirements.txt -q
}

# Verificar modelos ML
Write-Host ""
Write-Host "🤖 Verificando modelos de ML..." -ForegroundColor Yellow
$modelsPath = "..\models"
if ((Test-Path "$modelsPath\xgboost.pkl") -and (Test-Path "$modelsPath\isolation_forest.pkl")) {
    Write-Host "   ✓ Modelos de ML encontrados" -ForegroundColor Green
} else {
    Write-Host "   ⚠️  ADVERTENCIA: Algunos modelos de ML no están disponibles" -ForegroundColor Yellow
    Write-Host "   El sistema funcionará con detección basada en patrones" -ForegroundColor Yellow
}

# Verificar base de datos
Write-Host ""
Write-Host "🗄️  Verificando base de datos..." -ForegroundColor Yellow
if (Test-Path "traffic_logs.db") {
    Write-Host "   ✓ Base de datos existe" -ForegroundColor Green
} else {
    Write-Host "   ℹ️  Base de datos se creará automáticamente" -ForegroundColor Cyan
}

# Iniciar backend API
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host "🚀 INICIANDO API BACKEND..." -ForegroundColor Green
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📡 API URL: http://localhost:5000" -ForegroundColor Cyan
Write-Host "📊 Dashboard: http://localhost:5000/index.html" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  Presiona Ctrl+C para detener el servidor" -ForegroundColor Yellow
Write-Host ""
Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host ""

# Ejecutar el backend
try {
    python api_backend.py
} catch {
    Write-Host ""
    Write-Host "❌ ERROR: No se pudo iniciar el backend" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
