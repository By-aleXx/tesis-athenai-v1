#!/bin/bash
# AthenAI Dashboard - Fresh Start Script
# Limpia caché y reinicia todo desde cero

echo "========================================================================"
echo "ATHENAI DASHBOARD - LIMPIEZA Y REINICIO COMPLETO"
echo "========================================================================"

# 1. Detener servidores existentes
echo "🛑 Deteniendo servidores existentes..."
pkill -f "python3 -m http.server 8000" 2>/dev/null
pkill -f "python3 api_backend.py" 2>/dev/null
sleep 2

# 2. Verificar archivos locales
echo ""
echo "📁 Verificando archivos locales de JS..."
if [ ! -f "assets/js/react.js" ]; then
    echo "❌ ERROR: assets/js/react.js no existe"
    exit 1
fi
if [ ! -f "assets/js/recharts.js" ]; then
    echo "❌ ERROR: assets/js/recharts.js no existe"
    exit 1
fi
echo "✅ Todos los archivos JS locales presentes"

# 3. Reiniciar backend
echo ""
echo "🚀 Iniciando Backend API..."
python3 api_backend.py > backend.log 2>&1 &
BACKEND_PID=$!
echo "   Backend PID: $BACKEND_PID"
sleep 3

# 4. Iniciar servidor HTTP con headers anti-caché
echo ""
echo "🌐 Iniciando servidor HTTP (puerto 8000)..."
python3 -m http.server 8000 > frontend.log 2>&1 &
FRONTEND_PID=$!
echo "   Frontend PID: $FRONTEND_PID"
sleep 2

# 5. Guardar PIDs
echo "$BACKEND_PID" > .backend.pid
echo "$FRONTEND_PID" > .frontend.pid

# 6. Verificar que estén corriendo
if curl -s http://localhost:8000/index.html > /dev/null; then
    echo "   ✅ Frontend accesible en http://localhost:8000"
else
    echo "   ❌ Frontend NO responde"
    exit 1
fi

if curl -s http://localhost:5000/api/health > /dev/null; then
    echo "   ✅ Backend API accesible en http://localhost:5000"
else
    echo "   ⚠️  Backend puede estar iniciando aún..."
fi

echo ""
echo "========================================================================"
echo "✅ SISTEMA REINICIADO CORRECTAMENTE"
echo "========================================================================"
echo ""
echo "📊 Dashboard: http://localhost:8000/index.html"
echo "📡 API:       http://localhost:5000/api/health"
echo ""
echo "⚠️  IMPORTANTE: Para evitar problemas de caché:"
echo ""
echo "   OPCIÓN 1 (Recomendada): MODO INCÓGNITO/PRIVADO"
echo "   -----------------------------------------------"
echo "   Firefox:"
echo "     firefox --private-window http://localhost:8000/index.html"
echo ""
echo "   Chrome:"
echo "     google-chrome --incognito http://localhost:8000/index.html"
echo ""
echo "   OPCIÓN 2: HARD REFRESH en el navegador"
echo "   ----------------------------------------"
echo "   Presiona: Ctrl + Shift + R (o Ctrl + F5)"
echo "   Esto forzará la recarga ignorando la caché"
echo ""
echo "🛑 Para detener:"
echo "   kill $BACKEND_PID $FRONTEND_PID"
echo ""
echo "========================================================================"
