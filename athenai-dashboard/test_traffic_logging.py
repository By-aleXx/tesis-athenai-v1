#!/usr/bin/env python3
"""
Script de prueba para el sistema de logging de tráfico
Simula requests normales y de pruebas de seguridad
"""

import requests
import json
import os
import time
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Configuración
API_URL = "http://localhost:5000"
NORMAL_IP = "192.168.1.100"
TEST_ATTACK_IP = os.environ['AUTHORIZED_TEST_IP']


def print_section(title):
    """Imprime una sección con formato"""
    print("\n" + "="*80)
    print(f"  {title}")
    print("="*80)


def test_normal_traffic():
    """Simula tráfico normal"""
    print_section("🟢 Prueba 1: Tráfico Normal")
    
    endpoints = [
        "/api/stats",
        "/api/traffic",
        "/api/attacks",
        "/api/alerts",
        "/api/health"
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(f"{API_URL}{endpoint}")
            print(f"✓ {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"✗ {endpoint}: Error - {e}")
        time.sleep(0.5)


def test_attack_simulation():
    """Simula ataques de prueba"""
    print_section("🔴 Prueba 2: Simulación de Ataques (IP Autorizada)")
    
    # Simular diferentes tipos de payloads de ataque
    attack_payloads = [
        {
            "name": "SQL Injection",
            "endpoint": "/api/stats",
            "params": {"id": "1' OR '1'='1"}
        },
        {
            "name": "XSS Attack",
            "endpoint": "/api/alerts",
            "params": {"search": "<script>alert('XSS')</script>"}
        },
        {
            "name": "Path Traversal",
            "endpoint": "/api/traffic",
            "params": {"file": "../../etc/passwd"}
        }
    ]
    
    print(f"⚠️  NOTA: Para que estos requests se marquen como 'test_attack',")
    print(f"   deben provenir de la IP {TEST_ATTACK_IP}")
    print(f"   En este test local, se marcarán como tráfico normal.\n")
    
    for payload in attack_payloads:
        try:
            response = requests.get(
                f"{API_URL}{payload['endpoint']}",
                params=payload['params']
            )
            print(f"✓ {payload['name']}: {response.status_code}")
            print(f"  Payload: {payload['params']}")
        except Exception as e:
            print(f"✗ {payload['name']}: Error - {e}")
        time.sleep(0.5)


def test_post_requests():
    """Simula POST requests con body"""
    print_section("📤 Prueba 3: POST Requests con Body")
    
    test_data = {
        "username": "admin' OR '1'='1",
        "password": "password123",
        "payload": "<script>alert('test')</script>"
    }
    
    try:
        # Simular login malicioso
        response = requests.post(
            f"{API_URL}/api/stats",  # Endpoint de ejemplo
            json=test_data,
            headers={"Content-Type": "application/json"}
        )
        print(f"✓ POST request enviado: {response.status_code}")
        print(f"  Body: {json.dumps(test_data, indent=2)}")
    except Exception as e:
        print(f"✗ Error: {e}")


def view_traffic_logs():
    """Consulta los logs de tráfico"""
    print_section("📊 Prueba 4: Consultar Logs de Tráfico")
    
    try:
        # Obtener todos los logs
        response = requests.get(f"{API_URL}/api/traffic-logs?limit=10")
        data = response.json()
        
        print(f"\n📝 Total de logs: {data['total']}")
        print(f"📄 Mostrando: {len(data['logs'])} registros\n")
        
        for log in data['logs']:
            attack_marker = "🔴 TEST ATTACK" if log['is_test_attack'] else "🟢 Normal"
            print(f"{attack_marker} | {log['timestamp']} | {log['method']} {log['path']}")
            print(f"   IP: {log['source_ip']}")
            if log['query_params']:
                print(f"   Query: {log['query_params']}")
            if log['body']:
                body_preview = log['body'][:100] + "..." if len(log['body']) > 100 else log['body']
                print(f"   Body: {body_preview}")
            print()
        
    except Exception as e:
        print(f"✗ Error obteniendo logs: {e}")


def view_traffic_stats():
    """Consulta estadísticas de tráfico"""
    print_section("📈 Prueba 5: Estadísticas de Tráfico")
    
    try:
        response = requests.get(f"{API_URL}/api/traffic-stats")
        stats = response.json()
        
        print(f"\n📊 Estadísticas:")
        print(f"   Total de requests: {stats['total_requests']}")
        print(f"   Test attacks: {stats['test_attacks']}")
        print(f"   Tráfico normal: {stats['normal_traffic']}")
        print(f"   % Test attacks: {stats['test_attack_percentage']:.2f}%")
        
    except Exception as e:
        print(f"✗ Error obteniendo estadísticas: {e}")


def filter_test_attacks():
    """Filtra solo los test attacks"""
    print_section("🔍 Prueba 6: Filtrar Solo Test Attacks")
    
    try:
        response = requests.get(f"{API_URL}/api/traffic-logs?is_test_attack=true&limit=5")
        data = response.json()
        
        print(f"\n🔴 Test Attacks encontrados: {data['total']}\n")
        
        for log in data['logs']:
            print(f"🔴 {log['timestamp']} | {log['method']} {log['path']}")
            print(f"   IP: {log['source_ip']}")
            print()
        
        if data['total'] == 0:
            print("⚠️  No hay test attacks registrados aún.")
            print("   Para generar test attacks, las requests deben provenir de:")
            print(f"   IP: {TEST_ATTACK_IP}")
        
    except Exception as e:
        print(f"✗ Error filtrando test attacks: {e}")


def main():
    """Ejecuta todas las pruebas"""
    print("\n" + "="*80)
    print("  ATHENAI - TEST DE SISTEMA DE LOGGING DE TRÁFICO")
    print("="*80)
    print(f"\n🎯 API URL: {API_URL}")
    print(f"🔒 IP de pruebas autorizadas: {TEST_ATTACK_IP}")
    print(f"⏰ Timestamp: {datetime.now().isoformat()}")
    
    # Verificar que el servidor esté corriendo
    try:
        response = requests.get(f"{API_URL}/api/health", timeout=2)
        print(f"✅ Servidor disponible: {response.status_code}")
    except Exception as e:
        print(f"\n❌ ERROR: No se puede conectar al servidor")
        print(f"   Asegúrate de que el servidor esté corriendo en {API_URL}")
        print(f"   Ejecuta: python api_backend.py")
        return
    
    # Ejecutar pruebas
    test_normal_traffic()
    test_attack_simulation()
    test_post_requests()
    
    # Esperar un poco para que se procesen los logs
    print("\n⏳ Esperando 2 segundos para que se procesen los logs...")
    time.sleep(2)
    
    # Consultar logs
    view_traffic_logs()
    view_traffic_stats()
    filter_test_attacks()
    
    print_section("✅ Pruebas Completadas")
    print("\n💡 Próximos pasos:")
    print("   1. Revisar la base de datos: traffic_logs.db")
    print(f"   2. Hacer requests desde la IP autorizada ({TEST_ATTACK_IP})")
    print("   3. Verificar que se marquen como 'is_test_attack: true'")
    print("   4. Analizar los payloads capturados en el frontend\n")


if __name__ == "__main__":
    main()
