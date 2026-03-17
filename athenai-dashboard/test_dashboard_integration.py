import requests
import sys
import time
from urllib.parse import urljoin

FRONTEND_URL = "http://localhost:8000/index.html"
BACKEND_URL = "http://localhost:5000/api/"

def log(msg, status="INFO"):
    symbols = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️"}
    print(f"{symbols.get(status, '')} {msg}")

def check_service(url, name):
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            log(f"{name} está accesible ({url})", "SUCCESS")
            return True
        else:
            log(f"{name} devolvió código {response.status_code}", "ERROR")
            return False
    except requests.exceptions.ConnectionError:
        log(f"{name} no está corriendo en {url}", "ERROR")
        return False

def test_frontend_content():
    try:
        response = requests.get(FRONTEND_URL)
        content = response.text
        
        # Verificaciones críticas para evitar pantalla blanca
        checks = [
            ("React Loaded", "assets/js/react.js"),
            ("ReactDOM Loaded", "assets/js/react-dom.js"),
            ("Babel Loaded", "assets/js/babel.js"),
            ("Recharts Loaded", "assets/js/recharts.js"),
            ("Tailwind Loaded", "cdn.tailwindcss.com"),
            ("Root Div Present", 'id="root"'),
            ("Error Container Present", 'id="error-container"') # Nuevo manejo de errores
        ]
        
        all_passed = True
        for name, marker in checks:
            if marker in content:
                log(f"Frontend contiene: {name}", "SUCCESS")
            else:
                log(f"Falta en Frontend: {name}", "ERROR")
                all_passed = False
                
        # Verificar que NO hay dependencias rotas antiguas
        if "framer-motion" in content:
             log("Advertencia: Referencia a framer-motion encontrada (debería haber sido eliminada)", "WARN")
        else:
             log("Dependencia problemática (framer-motion) eliminada correctamente", "SUCCESS")
             
        return all_passed
    except Exception as e:
        log(f"Error analizando frontend: {e}", "ERROR")
        return False

def test_backend_endpoints():
    endpoints = ["health", "stats", "alerts"]
    all_passed = True
    
    for ep in endpoints:
        url = urljoin(BACKEND_URL, ep)
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200 and resp.headers.get('Content-Type') == 'application/json':
                 log(f"API Endpoint /api/{ep} operativo", "SUCCESS")
            else:
                 log(f"API Endpoint /api/{ep} falló", "ERROR")
                 all_passed = False
        except:
            log(f"API Endpoint /api/{ep} inalcanzable", "ERROR")
            all_passed = False
            
    return all_passed

def main():
    print("="*60)
    print("🧪 ATHENAI DASHBOARD - PRUEBAS DE INTEGRACIÓN")
    print("="*60)
    
    # 1. Verificar servicios activos
    fe_up = check_service(FRONTEND_URL, "Frontend Server")
    be_up = check_service(urljoin(BACKEND_URL, "health"), "Backend API")
    
    if not fe_up:
        print("\n❌ PRUEBA FALLIDA: El servidor del Frontend no está corriendo.")
        print("   Ejecuta: cd athenai-dashboard && python3 -m http.server 8000 &")
        sys.exit(1)

    if not be_up:
        print("\n⚠️  ADVERTENCIA: El Backend no responde. El dashboard mostrará datos vacíos o de error.")
    
    # 2. Verificar Integridad del HTML (Fix de pantalla blanca)
    print("\n🔍 Verificando Integridad del Frontend...")
    content_ok = test_frontend_content()
    
    # 3. Verificar API Data Flow
    print("\n📡 Verificando Flujo de Datos API...")
    if be_up:
        api_ok = test_backend_endpoints()
    else:
        api_ok = False
        log("Saltando pruebas de API porque el backend está caído", "WARN")

    print("\n" + "="*60)
    if content_ok:
        print("✅ RESULTADO: EL FRONTEND ESTÁ CORRECTAMENTE CONFIGURADO")
        if be_up and api_ok:
             print("🚀 ESTADO: SISTEMA 100% OPERATIVO (Frontend + Backend)")
        else:
             print("⚠️  ESTADO: FRONTEND OK, PERO BACKEND CON PROBLEMAS")
    else:
        print("❌ RESULTADO: ERRORES CRÍTICOS EN EL FRONTEND")
        sys.exit(1)

if __name__ == "__main__":
    main()
