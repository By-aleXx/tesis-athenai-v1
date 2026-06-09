"""
Script para generar alertas de prueba en DynamoDB
"""
from dynamodb_client import dynamodb_client
from datetime import datetime, timedelta
import random

# Tipos de ataques
attack_types = ['SQL Injection', 'XSS Attack', 'Brute Force', 'Path Traversal', 
                'Command Injection', 'CSRF', 'DDoS Attempt', 'Anomaly Detection']
severities = ['high', 'medium', 'low']
actions = ['BLOCK', 'ALERT', 'MONITOR']
ips = ['192.168.1.100', '10.0.0.50', '172.16.0.25', '203.0.113.42', 
       '198.51.100.88', '185.220.101.1', '45.134.142.123']

print("\n🚨 GENERANDO ALERTAS DE PRUEBA...\n")

# Insertar 15 alertas de prueba
for i in range(15):
    severity = random.choice(severities)
    action = 'BLOCK' if severity == 'high' else random.choice(['ALERT', 'MONITOR'])
    
    alert = {
        'alert_id': f'test_alert_{i+1}_{int(datetime.now().timestamp()*1000)}',
        'timestamp': (datetime.now() - timedelta(minutes=i*10)).isoformat(),
        'type': 'security_event',
        'severity': severity,
        'source_ip': random.choice(ips),
        'risk_score': round(random.uniform(0.5, 0.99), 2) if severity == 'high' else round(random.uniform(0.2, 0.7), 2),
        'attack_type': random.choice(attack_types),
        'action_taken': action,
        'payload': f'SELECT * FROM users WHERE id={i+1} OR 1=1--' if 'SQL' in random.choice(attack_types) else f'<script>alert({i+1})</script>',
        'details': f'Alerta de prueba generada automáticamente - Evento #{i+1}'
    }
    
    success = dynamodb_client.insert_alert(alert)
    if success:
        print(f"  ✓ Alerta {i+1}/15: {alert['attack_type']} ({severity}) - IP: {alert['source_ip']}")
    else:
        print(f"  ✗ Error insertando alerta {i+1}")

print(f"\n✅ ALERTAS INSERTADAS EN DYNAMODB")
print(f"📊 Recarga el dashboard en: http://localhost:5000/index.html")
print(f"🔄 Las alertas aparecerán en el Centro de Alertas\n")
