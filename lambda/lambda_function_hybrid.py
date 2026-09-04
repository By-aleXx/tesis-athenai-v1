"""
AthenAI - Función Lambda Híbrida Completa
Sistema de Detección con XGBoost + Isolation Forest

Modelos:
- XGBoost: Detección de SQLi/XSS (99.96% accuracy)
- Isolation Forest: Detección de anomalías en autenticación (94% recall)
"""

import json
import base64
import boto3
import re
import joblib
import numpy as np
from datetime import datetime
from typing import Dict, List, Any
import os

# Cliente S3
s3_client = boto3.client('s3')
ALERT_BUCKET = 'athenai-alertas'

# Cargar modelos (lazy loading)
xgboost_model = None
feature_engineer = None
isolation_forest_model = None
auth_scaler = None

def load_models():
    """Carga todos los modelos ML (lazy loading)"""
    global xgboost_model, feature_engineer, isolation_forest_model, auth_scaler
    
    models_loaded = True
    
    # XGBoost para SQLi/XSS
    if xgboost_model is None:
        print("📦 Cargando XGBoost...")
        xgboost_path = 'models/xgboost.pkl'
        fe_path = 'models/feature_engineer.pkl'
        
        if os.path.exists(xgboost_path) and os.path.exists(fe_path):
            xgboost_model = joblib.load(xgboost_path)
            feature_engineer = joblib.load(fe_path)
            print("  ✓ XGBoost cargado")
        else:
            print(f"  ⚠️  XGBoost no encontrado")
            models_loaded = False
    
    # Isolation Forest para Auth
    if isolation_forest_model is None:
        print("📦 Cargando Isolation Forest...")
        if_path = 'models/isolation_forest.pkl'
        scaler_path = 'models/auth_scaler.pkl'
        
        if os.path.exists(if_path) and os.path.exists(scaler_path):
            isolation_forest_model = joblib.load(if_path)
            auth_scaler = joblib.load(scaler_path)
            print("  ✓ Isolation Forest cargado")
        else:
            print(f"  ⚠️  Isolation Forest no encontrado")
            models_loaded = False
    
    return models_loaded


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
    auth_indicators = ['username', 'password', 'login', 'auth', 'failed_attempts_count']
    if any(key in log_data for key in auth_indicators):
        return 'AUTH_EVENT'
    
    web_indicators = ['url', 'url_path', 'http_method']
    if any(key in log_data for key in web_indicators):
        return 'WEB_TRAFFIC'
    
    return 'UNKNOWN'


def detect_sqli_xgboost(text: str) -> Dict[str, Any]:
    """Detección de SQLi/XSS con XGBoost"""
    
    if xgboost_model is None or feature_engineer is None:
        # Fallback a pattern-based
        return detect_sqli_pattern(text)
    
    try:
        import pandas as pd
        
        # Crear DataFrame
        df = pd.DataFrame({'text': [text]})
        
        # Extraer features
        X, _ = feature_engineer.extract_all_features(df)
        
        # Predecir
        prediction = xgboost_model.predict(X)[0]
        
        # Obtener probabilidad
        if hasattr(xgboost_model, 'predict_proba'):
            proba = xgboost_model.predict_proba(X)[0]
            confidence = float(proba[1] if prediction == 1 else proba[0])
        else:
            confidence = 0.99 if prediction == 1 else 0.01
        
        is_malicious = bool(prediction == 1)
        
        # Detectar tipo de ataque
        attack_type = None
        if is_malicious:
            patterns = get_attack_patterns(text)
            if patterns:
                attack_type = f"SQL Injection - {patterns[0]}"
            else:
                attack_type = "SQL Injection / XSS"
        
        return {
            'is_malicious': is_malicious,
            'confidence': confidence,
            'attack_type': attack_type,
            'patterns': get_attack_patterns(text) if is_malicious else [],
            'model': 'XGBoost'
        }
    
    except Exception as e:
        print(f"Error en XGBoost: {e}")
        return detect_sqli_pattern(text)


def detect_sqli_pattern(text: str) -> Dict[str, Any]:
    """Detección de SQLi basada en patrones (fallback)"""
    text_lower = text.lower()
    
    patterns = {
        'UNION SELECT': r'union\s+select',
        'OR 1=1': r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1['\"]?",
        'COMMENT': r'--|#|/\*',
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
        'patterns': detected,
        'model': 'Pattern-based'
    }


def get_attack_patterns(text: str) -> List[str]:
    """Identifica patrones de ataque"""
    text_lower = text.lower()
    patterns = []
    
    if re.search(r'union\s+(all\s+)?select', text_lower):
        patterns.append('UNION-based')
    
    if re.search(r"('\\s*or\\s*'1'\\s*=\\s*'1|'\\s*or\\s*1\\s*=\\s*1)", text_lower):
        patterns.append('Boolean-based')
    
    if re.search(r'(sleep|benchmark|waitfor|pg_sleep)\s*\(', text_lower):
        patterns.append('Time-based')
    
    if re.search(r';\s*(drop|delete|update|insert|exec)', text_lower):
        patterns.append('Stacked Queries')
    
    if re.search(r'<script>|javascript:|onerror=|onload=', text_lower):
        patterns.append('XSS')
    
    return patterns


def extract_auth_features(log_data: Dict) -> np.ndarray:
    """Extrae features para Isolation Forest (8 dimensiones)"""
    features = np.zeros(8)
    
    features[0] = log_data.get('time_since_last_login', 3600)
    features[1] = log_data.get('failed_attempts_count', 0)
    
    try:
        timestamp = log_data.get('timestamp', datetime.utcnow().isoformat())
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        features[2] = dt.hour
        features[5] = dt.weekday()
        features[3] = 1 if dt.weekday() >= 5 else 0
    except:
        features[2] = 12
        features[3] = 0
        features[5] = 0
    
    features[4] = 1 if log_data.get('unusual_location', False) else 0
    features[6] = log_data.get('geo_distance_km', 0)
    features[7] = log_data.get('session_duration_avg', 1800)
    
    return features


def detect_auth_anomaly_ml(log_data: Dict) -> Dict[str, Any]:
    """Detección de anomalías con Isolation Forest"""
    
    if isolation_forest_model is None or auth_scaler is None:
        return detect_auth_anomaly_simple(log_data)
    
    try:
        features = extract_auth_features(log_data)
        features_scaled = auth_scaler.transform([features])
        
        prediction = isolation_forest_model.predict(features_scaled)[0]
        anomaly_score = isolation_forest_model.score_samples(features_scaled)[0]
        
        is_anomaly = (prediction == -1)
        
        if anomaly_score < -0.7:
            severity = 'HIGH'
        elif anomaly_score < -0.5:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': float(anomaly_score),
            'confidence': abs(float(anomaly_score)),
            'severity': severity,
            'model': 'Isolation Forest'
        }
    
    except Exception as e:
        print(f"Error en Isolation Forest: {e}")
        return detect_auth_anomaly_simple(log_data)


def detect_auth_anomaly_simple(log_data: Dict) -> Dict[str, Any]:
    """Detección simple de anomalías (fallback)"""
    failed_attempts = log_data.get('failed_attempts_count', 0)
    user_agent = log_data.get('user_agent', '')
    
    is_anomaly = False
    score = 0.0
    
    if failed_attempts > 10:
        is_anomaly = True
        score = -0.8
    
    if 'python' in user_agent.lower() or 'curl' in user_agent.lower():
        is_anomaly = True
        score = min(score, -0.6)
    
    return {
        'is_anomaly': is_anomaly,
        'anomaly_score': score if is_anomaly else 0.1,
        'confidence': 0.85 if is_anomaly else 0.15,
        'severity': 'HIGH' if score < -0.7 else 'MEDIUM',
        'model': 'Heuristic (Fallback)'
    }


def create_sqli_alert(log_data: Dict, prediction: Dict) -> Dict:
    """Crea alerta de SQLi/XSS"""
    return {
        'alert_id': f"sqli-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'alert_type': 'WEB_ATTACK',
        'severity': 'HIGH',
        'detection_model': prediction.get('model', 'Unknown'),
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
        'severity': anomaly_result.get('severity', 'MEDIUM'),
        'detection_model': anomaly_result.get('model', 'Unknown'),
        'anomaly_score': anomaly_result['anomaly_score'],
        'confidence': anomaly_result['confidence'],
        'source': {
            'username': log_data.get('username', 'unknown'),
            'ip_address': log_data.get('ip_address', 'unknown'),
            'user_agent': log_data.get('user_agent', 'unknown')
        },
        'details': {
            'failed_attempts': log_data.get('failed_attempts_count', 0),
            'geo_distance_km': log_data.get('geo_distance_km', 0),
            'unusual_location': log_data.get('unusual_location', False)
        },
        'recommended_action': 'REQUIRE_MFA' if anomaly_result['severity'] == 'HIGH' else 'MONITOR',
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
    print("AthenAI - Sistema Híbrido de Detección (XGBoost + Isolation Forest)")
    print("="*80)
    
    # Cargar modelos
    load_models()
    
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
                prediction = detect_sqli_xgboost(text)
                
                if prediction['is_malicious']:
                    malicious_count += 1
                    print(f"  🚨 AMENAZA: {prediction['attack_type']}")
                    print(f"     Modelo: {prediction['model']}")
                    print(f"     Confianza: {prediction['confidence']:.2%}")
                    
                    alert = create_sqli_alert(log_data, prediction)
                    if save_alert_to_s3(alert):
                        alerts_saved += 1
                else:
                    print(f"  ✓ Tráfico legítimo")
            
            elif log_type == 'AUTH_EVENT':
                anomaly_result = detect_auth_anomaly_ml(log_data)
                
                if anomaly_result['is_anomaly']:
                    anomaly_count += 1
                    print(f"  🚨 ANOMALÍA: Score {anomaly_result['anomaly_score']:.2f}")
                    print(f"     Modelo: {anomaly_result['model']}")
                    print(f"     Severidad: {anomaly_result['severity']}")
                    
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
        import traceback
        traceback.print_exc()
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
