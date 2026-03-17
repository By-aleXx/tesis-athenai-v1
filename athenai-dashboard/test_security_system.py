"""
AthenAI - Test de Integración del Sistema de Seguridad

Prueba el flujo completo: AI Engine → Policy Engine → Response Actions

Autor: AthenAI Team
Fecha: 2026-02-11
"""

import requests
import json
from datetime import datetime

# Configuración
API_URL = "http://localhost:5000"
ENDPOINT = f"{API_URL}/api/security/analyze"

# Casos de prueba
test_cases = [
    {
        "name": "Tráfico Legítimo",
        "payload": "SELECT * FROM users WHERE id = 1",
        "source_ip": "192.168.1.100",
        "method": "GET",
        "path": "/api/users/1",
        "expected_action": "ALLOW"
    },
    {
        "name": "SQL Injection Básico",
        "payload": "SELECT * FROM users WHERE id = 1 OR 1=1--",
        "source_ip": "10.0.0.50",
        "method": "GET",
        "path": "/api/users",
        "expected_action": "ALERT o BLOCK"
    },
    {
        "name": "XSS Attack",
        "payload": "<script>alert('XSS')</script>",
        "source_ip": "203.0.113.45",
        "method": "POST",
        "path": "/api/comments",
        "expected_action": "BLOCK"
    },
    {
        "name": "SQL Injection Avanzado",
        "payload": "'; DROP TABLE users; --",
        "source_ip": "198.51.100.10",
        "method": "POST",
        "path": "/api/login",
        "expected_action": "BLOCK"
    },
    {
        "name": "Path Traversal",
        "payload": "../../etc/passwd",
        "source_ip": "172.16.0.100",
        "method": "GET",
        "path": "/api/files",
        "expected_action": "BLOCK"
    }
]


def print_separator():
    print("=" * 100)


def print_test_header(test_num, test_name):
    print(f"\n🧪 Test {test_num}: {test_name}")
    print("-" * 100)


def print_result(response, status_code):
    """Imprime el resultado de la petición"""
    print(f"   📊 Status Code: {status_code}")
    
    if response:
        data = response.json()
        
        # Información principal
        status = data.get('status', 'unknown')
        risk_score = data.get('risk_score', 0)
        
        print(f"   🎯 Status: {status.upper()}")
        print(f"   📈 Risk Score: {risk_score:.2f}")
        
        # Información adicional según el tipo de respuesta
        if 'warning' in data:
            print(f"   ⚠️  Warning: {data['warning']}")
        
        if 'reason' in data:
            print(f"   🚨 Reason: {data['reason']}")
        
        if 'block_info' in data:
            print(f"   🔒 Block Info: {data['block_info']}")
        
        if 'retry_after' in data:
            print(f"   ⏱️  Retry After: {data['retry_after']}s")
        
        # Timestamp
        timestamp = data.get('timestamp', 'N/A')
        print(f"   🕐 Timestamp: {timestamp}")
    else:
        print("   ❌ No response data")


def run_tests():
    """Ejecuta todos los tests"""
    print_separator()
    print("ATHENAI - TEST DE INTEGRACIÓN DEL SISTEMA DE SEGURIDAD")
    print_separator()
    print(f"🌐 API URL: {API_URL}")
    print(f"📍 Endpoint: {ENDPOINT}")
    print(f"📅 Fecha: {datetime.now().isoformat()}")
    print_separator()
    
    # Verificar que el API está disponible
    try:
        health_response = requests.get(f"{API_URL}/api/health", timeout=5)
        if health_response.status_code == 200:
            print("✅ API Backend está disponible")
        else:
            print("⚠️  API Backend respondió pero con error")
    except Exception as e:
        print(f"❌ ERROR: No se puede conectar al API Backend")
        print(f"   Asegúrate de que el servidor está corriendo en {API_URL}")
        print(f"   Error: {e}")
        return
    
    # Ejecutar tests
    results = []
    
    for i, test in enumerate(test_cases, 1):
        print_test_header(i, test['name'])
        
        # Preparar payload
        payload = {
            "payload": test['payload'],
            "source_ip": test['source_ip'],
            "method": test['method'],
            "path": test['path']
        }
        
        print(f"   📤 Request:")
        print(f"      Payload: {test['payload']}")
        print(f"      Source IP: {test['source_ip']}")
        print(f"      Method: {test['method']}")
        print(f"      Path: {test['path']}")
        
        try:
            # Hacer petición
            response = requests.post(
                ENDPOINT,
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            print(f"\n   📥 Response:")
            print_result(response, response.status_code)
            
            # Guardar resultado
            results.append({
                'test': test['name'],
                'status_code': response.status_code,
                'response': response.json(),
                'success': True
            })
            
        except requests.exceptions.Timeout:
            print(f"\n   ⏱️  TIMEOUT: La petición tardó demasiado")
            results.append({
                'test': test['name'],
                'error': 'timeout',
                'success': False
            })
        except Exception as e:
            print(f"\n   ❌ ERROR: {e}")
            results.append({
                'test': test['name'],
                'error': str(e),
                'success': False
            })
    
    # Resumen de resultados
    print_separator()
    print("📊 RESUMEN DE RESULTADOS")
    print_separator()
    
    successful = sum(1 for r in results if r.get('success', False))
    total = len(results)
    
    print(f"\n✅ Tests exitosos: {successful}/{total}")
    print(f"❌ Tests fallidos: {total - successful}/{total}")
    
    # Obtener estadísticas del sistema
    try:
        stats_response = requests.get(f"{API_URL}/api/security/stats", timeout=5)
        if stats_response.status_code == 200:
            stats = stats_response.json()
            
            print("\n📈 ESTADÍSTICAS DEL SISTEMA:")
            print(f"   Policy Engine: {'✅ Habilitado' if stats['policy_engine']['enabled'] else '❌ Deshabilitado'}")
            print(f"   Políticas activas: {stats['policy_engine']['policies_count']}")
            print(f"   AI Engine: {'✅ Habilitado' if stats['ai_engine']['enabled'] else '❌ Deshabilitado'}")
            
            if 'response_actions' in stats and stats['response_actions']:
                ra_stats = stats['response_actions']
                print(f"\n   Response Actions:")
                print(f"      Total acciones: {ra_stats.get('total_actions', 0)}")
                print(f"      Permitidas: {ra_stats.get('allowed', 0)} ({ra_stats.get('percentages', {}).get('allowed', 0):.1f}%)")
                print(f"      Alertadas: {ra_stats.get('alerted', 0)} ({ra_stats.get('percentages', {}).get('alerted', 0):.1f}%)")
                print(f"      Bloqueadas: {ra_stats.get('blocked', 0)} ({ra_stats.get('percentages', {}).get('blocked', 0):.1f}%)")
                print(f"      Rate Limited: {ra_stats.get('rate_limited', 0)} ({ra_stats.get('percentages', {}).get('rate_limited', 0):.1f}%)")
    except Exception as e:
        print(f"\n⚠️  No se pudieron obtener estadísticas: {e}")
    
    print_separator()
    print("✅ Tests completados")
    print_separator()


if __name__ == "__main__":
    run_tests()
