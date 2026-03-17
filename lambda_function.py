"""
AthenAI - Función Lambda Simplificada (Sin Dependencias)
Versión para pruebas que simula la detección sin modelos de Deep Learning

NOTA: Esta es una versión simplificada para validar el pipeline.
Para producción, usar la versión completa con DistilBERT e Isolation Forest.
"""

import json
import base64
import boto3
import re
from datetime import datetime
from typing import Dict, List, Any

# Cliente S3
s3_client = boto3.client('s3')
ALERT_BUCKET = 'athenai-alertas'


def decode_kinesis_record(record: Dict) -> str:
    """Decodifica registro de Kinesis"""
    try:
        encoded_data = record['kinesis']['data']
        decoded_bytes = base64.b64decode(encoded_data)
        return decoded_bytes.decode('utf-8')
    except Exception as e:
        print(f"Error decodificando: {str(e)}")
        return ""


def parse_log(log_text: str) -> Dict[str, Any]:
    """Parsea el log"""
    try:
        return json.loads(log_text)
    except json.JSONDecodeError:
        # Log de Apache/Nginx
        pattern = r'(\S+) - - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
        match = re.match(pattern, log_text)
        if match:
            return {
                'ip_address': match.group(1),
                'timestamp': match.group(2),
                'http_method': match.group(3),
                'url_path': match.group(4),
                'raw_log': log_text
            }
        return {'raw_log': log_text}


def classify_log_type(log_data: Dict) -> str:
    """Clasifica el tipo de log"""
    auth_indicators = ['username', 'password', 'login', 'auth']
    if any(key in log_data for key in auth_indicators):
        return 'AUTH_EVENT'
    
    web_indicators = ['url', 'url_path', 'http_method']
    if any(key in log_data for key in web_indicators):
        return 'WEB_TRAFFIC'
    
    return 'UNKNOWN'


def detect_sqli_simple(text: str) -> Dict[str, Any]:
    """Detección simple de SQLi basada en patrones (sin BERT)"""
    text_lower = text.lower()
    
    # Patrones de SQL Injection
    patterns = {
        'UNION SELECT': r'union\s+select',
        'OR 1=1': r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?",
        'COMMENT': r'--|\#|/\*',
        'XSS': r'<script>|javascript:',
    }
    
    detected = []
    for attack_type, pattern in patterns.items():
        if re.search(pattern, text_lower):
            detected.append(attack_type)
    
    is_malicious = len(detected) > 0
    
    return {
        'is_malicious': is_malicious,
        'confidence': 0.95 if is_malicious else 0.05,
        'attack_type': f"SQL Injection - {detected[0]}" if detected else None,
        'patterns': detected
    }


def detect_auth_anomaly_simple(log_data: Dict) -> Dict[str, Any]:
    """Detección simple de anomalías (sin Isolation Forest)"""
    # Heurísticas simples
    failed_attempts = log_data.get('failed_attempts_count', 0)
    user_agent = log_data.get('user_agent', '')
    
    is_anomaly = False
    score = 0.0
    
    # Brute force: muchos intentos fallidos
    if failed_attempts > 10:
        is_anomaly = True
        score = -0.8
    
    # User-Agent sospechoso
    if 'python' in user_agent.lower() or 'curl' in user_agent.lower():
        is_anomaly = True
        score = min(score, -0.6)
    
    return {
        'is_anomaly': is_anomaly,
        'anomaly_score': score if is_anomaly else 0.1,
        'confidence': 0.85 if is_anomaly else 0.15
    }


def create_sqli_alert(log_data: Dict, prediction: Dict) -> Dict:
    """Crea alerta de SQLi/XSS"""
    return {
        'alert_id': f"sqli-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'alert_type': 'WEB_ATTACK',
        'severity': 'HIGH',
        'detection_model': 'Pattern-based (Simplified)',
        'attack_classification': prediction['attack_type'],
        'confidence': prediction['confidence'],
        'source': {
            'ip_address': log_data.get('ip_address', 'unknown'),
            'http_method': log_data.get('http_method', 'unknown'),
            'url_path': log_data.get('url_path', 'unknown')
        },
        'payload': {
            'raw_log': log_data.get('raw_log', ''),
            'detected_patterns': prediction.get('patterns', [])
        },
        'recommended_action': 'BLOCK_IP',
        'requires_investigation': True
    }


def create_auth_alert(log_data: Dict, anomaly_result: Dict) -> Dict:
    """Crea alerta de anomalía de autenticación"""
    return {
        'alert_id': f"auth-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'alert_type': 'AUTH_ANOMALY',
        'severity': 'HIGH' if anomaly_result['anomaly_score'] < -0.7 else 'MEDIUM',
        'detection_model': 'Heuristic-based (Simplified)',
        'anomaly_score': anomaly_result['anomaly_score'],
        'confidence': anomaly_result['confidence'],
        'source': {
            'username': log_data.get('username', 'unknown'),
            'ip_address': log_data.get('ip_address', 'unknown'),
            'user_agent': log_data.get('user_agent', 'unknown')
        },
        'recommended_action': 'REQUIRE_MFA',
        'requires_investigation': True
    }


def save_alert_to_s3(alert: Dict) -> bool:
    """Guarda alerta en S3"""
    try:
        alert_id = alert['alert_id']
        timestamp = datetime.utcnow().strftime('%Y/%m/%d')
        s3_key = f"alerts/{timestamp}/{alert_id}.json"
        
        alert_json = json.dumps(alert, indent=2)
        
        s3_client.put_object(
            Bucket=ALERT_BUCKET,
            Key=s3_key,
            Body=alert_json,
            ContentType='application/json'
        )
        
        print(f"✓ Alerta guardada: s3://{ALERT_BUCKET}/{s3_key}")
        return True
    except Exception as e:
        print(f"✗ Error guardando alerta: {str(e)}")
        return False


def lambda_handler(event: Dict, context: Any) -> Dict:
    """Handler principal"""
    print("="*80)
    print("AthenAI - Sistema Simplificado de Detección")
    print("="*80)
    
    total_records = 0
    malicious_count = 0
    anomaly_count = 0
    alerts_saved = 0
    
    try:
        for record in event['Records']:
            total_records += 1
            
            # Decodificar
            log_text = decode_kinesis_record(record)
            if not log_text:
                continue
            
            print(f"\n[{total_records}] Procesando log...")
            
            # Parsear
            log_data = parse_log(log_text)
            log_type = classify_log_type(log_data)
            
            print(f"  Tipo: {log_type}")
            
            # Procesar según tipo
            if log_type == 'WEB_TRAFFIC':
                text = log_data.get('url_path', log_data.get('raw_log', ''))
                prediction = detect_sqli_simple(text)
                
                if prediction['is_malicious']:
                    malicious_count += 1
                    print(f"  🚨 AMENAZA: {prediction['attack_type']}")
                    
                    alert = create_sqli_alert(log_data, prediction)
                    if save_alert_to_s3(alert):
                        alerts_saved += 1
                else:
                    print(f"  ✓ Tráfico legítimo")
            
            elif log_type == 'AUTH_EVENT':
                anomaly_result = detect_auth_anomaly_simple(log_data)
                
                if anomaly_result['is_anomaly']:
                    anomaly_count += 1
                    print(f"  🚨 ANOMALÍA: Score {anomaly_result['anomaly_score']:.2f}")
                    
                    alert = create_auth_alert(log_data, anomaly_result)
                    if save_alert_to_s3(alert):
                        alerts_saved += 1
                else:
                    print(f"  ✓ Comportamiento normal")
        
        # Resumen
        print("\n" + "="*80)
        print("RESUMEN")
        print("="*80)
        print(f"Total: {total_records}")
        print(f"Amenazas web: {malicious_count}")
        print(f"Anomalías auth: {anomaly_count}")
        print(f"Alertas guardadas: {alerts_saved}")
        print("="*80)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Procesamiento completado',
                'statistics': {
                    'total_records': total_records,
                    'malicious_count': malicious_count,
                    'anomaly_count': anomaly_count,
                    'alerts_saved': alerts_saved
                }
            })
        }
    
    except Exception as e:
        print(f"\n✗ ERROR: {str(e)}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
