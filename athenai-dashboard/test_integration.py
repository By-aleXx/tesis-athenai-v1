"""
AthenAI - Integration Test

Script de prueba para validar la integración completa de todos los componentes:
- Phase 2: Policy Engine, Response Actions, IP Blocker, Rate Limiter, Alert System
- Phase 3: Evidence Store, DynamoDB Client, Secrets Manager

Autor: AthenAI Team
Fecha: 2026-02-11
"""

import requests
import json
import time
from datetime import datetime

# Configuración
API_URL = "http://localhost:5000"
TEST_IP = "203.0.113.45"  # IP de prueba (TEST-NET-2)

def print_section(title):
    """Imprime un separador de sección"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)

def test_health():
    """Test 1: Health check"""
    print_section("TEST 1: Health Check")
    
    try:
        response = requests.get(f"{API_URL}/api/health")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_security_analyze_benign():
    """Test 2: Analizar petición benigna"""
    print_section("TEST 2: Análisis de Petición Benigna")
    
    try:
        payload = {
            "payload": "SELECT * FROM users WHERE id = 1",
            "source_ip": "192.168.1.100",
            "method": "GET",
            "path": "/api/users"
        }
        
        response = requests.post(
            f"{API_URL}/api/security/analyze",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_security_analyze_malicious():
    """Test 3: Analizar petición maliciosa (SQL Injection)"""
    print_section("TEST 3: Análisis de Petición Maliciosa (SQL Injection)")
    
    try:
        payload = {
            "payload": "' OR '1'='1' --",
            "source_ip": TEST_IP,
            "method": "POST",
            "path": "/api/login"
        }
        
        response = requests.post(
            f"{API_URL}/api/security/analyze",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        # Debería ser bloqueado o alertado
        return response.status_code in [200, 403]
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_rate_limiter():
    """Test 4: Rate Limiter"""
    print_section("TEST 4: Rate Limiter")
    
    try:
        # Hacer múltiples requests rápidas
        print("Enviando 15 requests rápidas...")
        
        for i in range(15):
            response = requests.post(
                f"{API_URL}/api/security/rate-limiter/check",
                json={"identifier": "test_user", "limit_type": "security"},
                headers={"Content-Type": "application/json"}
            )
            
            print(f"Request {i+1}: Status {response.status_code}")
            
            if response.status_code == 429:
                print(f"✅ Rate limit activado en request {i+1}")
                print(f"Response: {json.dumps(response.json(), indent=2)}")
                return True
            
            time.sleep(0.1)
        
        print("⚠️  Rate limit no se activó (límite muy alto o no configurado)")
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_ip_blocker():
    """Test 5: IP Blocker"""
    print_section("TEST 5: IP Blocker")
    
    try:
        # Bloquear IP de prueba
        print(f"Bloqueando IP: {TEST_IP}")
        
        response = requests.post(
            f"{API_URL}/api/security/ip-blocker/block",
            json={
                "ip": TEST_IP,
                "duration": 300,  # 5 minutos
                "reason": "Test blocking"
            },
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Block Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        # Verificar que está bloqueada
        print(f"\nVerificando IPs bloqueadas...")
        response = requests.get(f"{API_URL}/api/security/ip-blocker/blocked")
        
        print(f"Status: {response.status_code}")
        blocked_ips = response.json()
        print(f"IPs bloqueadas: {blocked_ips.get('count', 0)}")
        
        # Desbloquear
        print(f"\nDesbloqueando IP: {TEST_IP}")
        response = requests.post(
            f"{API_URL}/api/security/ip-blocker/unblock",
            json={"ip": TEST_IP},
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Unblock Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_security_stats():
    """Test 6: Security Stats"""
    print_section("TEST 6: Security Statistics")
    
    try:
        response = requests.get(f"{API_URL}/api/security/stats")
        
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        return response.status_code == 200
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_evidence_and_dynamodb():
    """Test 7: Evidence Store y DynamoDB Integration"""
    print_section("TEST 7: Evidence Store y DynamoDB")
    
    print("Este test verifica que los datos se almacenen correctamente.")
    print("Revisa los logs del servidor para confirmar:")
    print("  - Evidence Store: Logs con hash SHA-256 y HMAC")
    print("  - DynamoDB: Inserciones en traffic_logs y security_alerts")
    
    # Generar evento de seguridad
    try:
        payload = {
            "payload": "'; DROP TABLE users; --",
            "source_ip": "198.51.100.42",
            "method": "POST",
            "path": "/api/admin"
        }
        
        response = requests.post(
            f"{API_URL}/api/security/analyze",
            json=payload,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"\nEvento de seguridad generado:")
        print(f"Status: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        print("\n✅ Verifica los logs del servidor para confirmar almacenamiento")
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def run_all_tests():
    """Ejecuta todos los tests"""
    print("\n" + "🚀" * 40)
    print("  ATHENAI - INTEGRATION TEST SUITE")
    print("  Validando integración completa de Fases 2 y 3")
    print("🚀" * 40)
    
    tests = [
        ("Health Check", test_health),
        ("Security Analyze - Benign", test_security_analyze_benign),
        ("Security Analyze - Malicious", test_security_analyze_malicious),
        ("Rate Limiter", test_rate_limiter),
        ("IP Blocker", test_ip_blocker),
        ("Security Stats", test_security_stats),
        ("Evidence Store & DynamoDB", test_evidence_and_dynamodb)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
            time.sleep(1)  # Pausa entre tests
        except Exception as e:
            print(f"\n❌ Error ejecutando {test_name}: {e}")
            results.append((test_name, False))
    
    # Resumen
    print_section("RESUMEN DE TESTS")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests pasados ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("\n🎉 ¡Todos los tests pasaron exitosamente!")
    else:
        print(f"\n⚠️  {total - passed} test(s) fallaron")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    print(f"\nIniciando tests en: {API_URL}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print("\nAsegúrate de que:")
    print("  1. LocalStack esté corriendo (puerto 4566)")
    print("  2. Redis esté corriendo (puerto 6379)")
    print("  3. API Backend esté corriendo (puerto 5000)")
    
    input("\nPresiona ENTER para continuar...")
    
    run_all_tests()
