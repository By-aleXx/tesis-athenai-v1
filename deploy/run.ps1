# AthenAI - Lanzador principal (Windows)
# Uso: .\run.ps1
# Opcional: .\run.ps1 --build   (reconstruir imagen)
#           .\run.ps1 --down    (detener y eliminar contenedores)

param(
    [switch]$Build,
    [switch]$Down,
    [switch]$Logs
)

$ProjectDir = Join-Path (Split-Path $PSScriptRoot -Parent) "athenai-dashboard"

if (-not (Get-Command "docker" -ErrorAction SilentlyContinue)) {
    Write-Error "Docker no esta instalado o no esta en el PATH. Instala Docker Desktop."
    exit 1
}

Set-Location $ProjectDir

if ($Down) {
    Write-Host "Deteniendo contenedores..." -ForegroundColor Yellow
    docker compose down
    exit 0
}

if ($Logs) {
    docker compose logs -f
    exit 0
}

if ($Build) {
    Write-Host "Construyendo imagen y levantando servicios..." -ForegroundColor Cyan
    docker compose up --build
} else {
    Write-Host "Levantando servicios (usa -Build para reconstruir la imagen)..." -ForegroundColor Cyan
    docker compose up
}
