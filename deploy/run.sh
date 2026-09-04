#!/bin/bash
# AthenAI - Lanzador principal (Linux/Mac)
# Uso: ./run.sh
# Opcional: ./run.sh --build   (reconstruir imagen)
#           ./run.sh --down    (detener contenedores)
#           ./run.sh --logs    (ver logs en tiempo real)

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/../athenai-dashboard" && pwd)"

if ! command -v docker &> /dev/null; then
    echo "Error: Docker no esta instalado." >&2
    exit 1
fi

cd "$PROJECT_DIR"

case "${1:-}" in
    --down)
        echo "Deteniendo contenedores..."
        docker compose down
        ;;
    --logs)
        docker compose logs -f
        ;;
    --build)
        echo "Construyendo imagen y levantando servicios..."
        docker compose up --build
        ;;
    *)
        echo "Levantando servicios (usa --build para reconstruir la imagen)..."
        docker compose up
        ;;
esac
