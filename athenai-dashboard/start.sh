#!/bin/bash

# AthenAI Dashboard - Script de Inicio
# Inicia el backend API y abre el dashboard en el navegador

echo "================================================================================"
echo "ATHENAI DASHBOARD - INICIO"
echo "================================================================================"
echo ""

# Verificar si Flask está instalado
if ! python3 -c "import flask" 2>/dev/null; then
    echo "📦 Instalando dependencias..."
    pip install -r requirements.txt --break-system-packages
    echo ""
fi

# Iniciar backend en background
echo "🚀 Iniciando API Backend..."
python3 api_backend.py &
BACKEND_PID=$!

echo "   Backend PID: $BACKEND_PID"
echo "   API URL: http://localhost:5000"
echo ""

# Esperar a que el backend esté listo
echo "⏳ Esperando a que el backend esté listo..."
sleep 3

# Verificar que el backend esté corriendo
if curl -s http://localhost:5000/api/health > /dev/null 2>&1; then
    echo "   ✓ Backend listo"
else
    echo "   ⚠️  Backend puede no estar listo aún"
fi

echo ""
echo "================================================================================"
echo "✅ DASHBOARD INICIADO"
echo "================================================================================"
echo ""
echo "📊 Dashboard URL: file://$(pwd)/index.html"
echo "📡 API Backend:   http://localhost:5000"
echo ""
echo "🌐 Abre el dashboard en tu navegador:"
echo "   firefox index.html"
echo "   # o"
echo "   google-chrome index.html"
echo ""
echo "🛑 Para detener el backend:"
echo "   kill $BACKEND_PID"
echo ""
echo "================================================================================"

# Guardar PID para poder detenerlo después
echo $BACKEND_PID > .backend.pid
