"""
AthenAI - Prueba Local de Lambda con Isolation Forest
Simula eventos de Kinesis y prueba la función Lambda localmente
"""

import json
import base64
import sys
import os

# Agregar directorio actual al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Importar función Lambda
from lambda_function_ml import lambda_handler

def create_kinesis_event(data_dict):
    """Crea un evento de Kinesis simulado"""
    data_json = json.dumps(data_dict)
    data_encoded = base64.b64encode(data_json.encode('utf-8')).decode('utf-8')
    
    return {
        'Records': [{
            'kinesis': {
                'data': data_encoded
            }
        }]
    }

def main():
    print("\n" + "="*80)
    print("ATHENAI - PRUEBA LOCAL DE LAMBDA CON ISOLATION FOREST")
    print("="*80 + "\n")
    
    # Crear directorio de modelos si no existe
    os.makedirs('models', exist_ok=True)
    
    # Copiar modelos entrenados
    import shutil
    if os.path.exists('training/models/isolation_forest.pkl'):
        shutil.copy('training/models/isolation_forest.pkl', 'models/')
        print("✓ Modelo Isolation Forest copiado")
    
    # El scaler se guarda con el modelo, verificar si existe
    if not os.path.exists('models/auth_scaler.pkl'):
        # Crear un scaler dummy para testing
        print("⚠️  Scaler no encontrado, creando dummy...")
        from sklearn.preprocessing import StandardScaler
        import joblib
        import numpy as np
        
        scaler = StandardScaler()
        # Fit con datos dummy (8 features)
        dummy_data = np.random.randn(100, 8)
        scaler.fit(dummy_data)
        joblib.dump(scaler, 'models/auth_scaler.pkl')
        print("✓ Scaler dummy creado")
    
    print("\n" + "="*80)
    print("CASOS DE PRUEBA")
    print("="*80 + "\n")
    
    # Caso 1: Tráfico web normal
    print("1️⃣  Tráfico Web Normal")
    print("-" * 80)
    event1 = create_kinesis_event({
        'http_method': 'GET',
        'url_path': '/products?id=1',
        'ip_address': '192.168.1.100',
        'raw_log': 'GET /products?id=1 HTTP/1.1'
    })
    
    response1 = lambda_handler(event1, None)
    print(f"\nRespuesta: {json.dumps(json.loads(response1['body']), indent=2)}\n")
    
    # Caso 2: SQL Injection
    print("\n2️⃣  SQL Injection (UNION SELECT)")
    print("-" * 80)
    event2 = create_kinesis_event({
        'http_method': 'GET',
        'url_path': "/api/users?id=1 UNION SELECT * FROM passwords--",
        'ip_address': '203.0.113.50',
        'raw_log': "GET /api/users?id=1 UNION SELECT * FROM passwords-- HTTP/1.1"
    })
    
    response2 = lambda_handler(event2, None)
    print(f"\nRespuesta: {json.dumps(json.loads(response2['body']), indent=2)}\n")
    
    # Caso 3: Login normal
    print("\n3️⃣  Login Normal")
    print("-" * 80)
    event3 = create_kinesis_event({
        'username': 'john.doe',
        'ip_address': '192.168.1.100',
        'failed_attempts_count': 0,
        'time_since_last_login': 3600,
        'login_hour': 14,
        'is_weekend': 0,
        'unusual_location': 0,
        'geo_distance_km': 0,
        'session_duration_avg': 1800
    })
    
    response3 = lambda_handler(event3, None)
    print(f"\nRespuesta: {json.dumps(json.loads(response3['body']), indent=2)}\n")
    
    # Caso 4: Brute Force Attack
    print("\n4️⃣  Brute Force Attack")
    print("-" * 80)
    event4 = create_kinesis_event({
        'username': 'admin',
        'ip_address': '203.0.113.50',
        'failed_attempts_count': 25,  # Muchos intentos fallidos
        'time_since_last_login': 60,  # Muy rápido
        'login_hour': 3,  # Hora inusual
        'is_weekend': 1,
        'unusual_location': 1,  # Ubicación sospechosa
        'geo_distance_km': 5000,  # Lejos de ubicación usual
        'session_duration_avg': 30
    })
    
    response4 = lambda_handler(event4, None)
    print(f"\nRespuesta: {json.dumps(json.loads(response4['body']), indent=2)}\n")
    
    # Caso 5: XSS Attack
    print("\n5️⃣  XSS Attack")
    print("-" * 80)
    event5 = create_kinesis_event({
        'http_method': 'POST',
        'url_path': "/comment?text=<script>alert('XSS')</script>",
        'ip_address': '198.51.100.25',
        'raw_log': "POST /comment?text=<script>alert('XSS')</script> HTTP/1.1"
    })
    
    response5 = lambda_handler(event5, None)
    print(f"\nRespuesta: {json.dumps(json.loads(response5['body']), indent=2)}\n")
    
    print("="*80)
    print("✅ PRUEBAS COMPLETADAS")
    print("="*80 + "\n")

if __name__ == "__main__":
    # Mock boto3 S3 client para testing local
    import unittest.mock as mock
    
    # Mock S3 client
    mock_s3 = mock.MagicMock()
    mock_s3.put_object.return_value = {'ResponseMetadata': {'HTTPStatusCode': 200}}
    
    # Reemplazar en el módulo
    import lambda_function_ml
    lambda_function_ml.s3_client = mock_s3
    
    main()
