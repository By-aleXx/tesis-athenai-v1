"""
AthenAI - Sistema Híbrido de Detección de Intrusos
Tesis de Maestría: Deep Learning para Ciberseguridad

Función AWS Lambda que implementa un pipeline híbrido:
1. DistilBERT para detección de SQLi/XSS (análisis semántico)
2. Isolation Forest para detección de anomalías en autenticación

Autor: [Tu Nombre]
Fecha: Enero 2026
"""

import json
import base64
import boto3
import torch
import numpy as np
from datetime import datetime
from typing import Dict, List, Tuple, Any
import re

# Imports de modelos
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import joblib


# ============================================================================
# CONFIGURACIÓN GLOBAL
# ============================================================================

# Cliente S3 para almacenamiento de alertas
s3_client = boto3.client('s3')
ALERT_BUCKET = 'athenai-alertas'

# Paths de modelos (se cargan en /tmp en Lambda)
DISTILBERT_MODEL_PATH = '/tmp/distilbert'
ISOLATION_FOREST_MODEL_PATH = '/tmp/isolation_forest.pkl'

# Modelos globales (se cargan una vez por contenedor Lambda)
distilbert_model = None
distilbert_tokenizer = None
isolation_forest_model = None
isolation_forest_scaler = None
feature_extractor = None

# Device para PyTorch
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')


# ============================================================================
# CARGA DE MODELOS (Cold Start Optimization)
# ============================================================================

def load_models():
    """
    Carga los modelos en memoria (se ejecuta una vez por contenedor Lambda)
    """
    global distilbert_model, distilbert_tokenizer
    global isolation_forest_model, isolation_forest_scaler, feature_extractor
    
    print("🔧 Cargando modelos...")
    
    try:
        # Cargar DistilBERT
        print("  📥 Cargando DistilBERT...")
        distilbert_tokenizer = DistilBertTokenizer.from_pretrained(DISTILBERT_MODEL_PATH)
        distilbert_model = DistilBertForSequenceClassification.from_pretrained(DISTILBERT_MODEL_PATH)
        distilbert_model.to(device)
        distilbert_model.eval()
        print("  ✓ DistilBERT cargado")
        
        # Cargar Isolation Forest
        print("  📥 Cargando Isolation Forest...")
        model_data = joblib.load(ISOLATION_FOREST_MODEL_PATH)
        isolation_forest_model = model_data['model']
        isolation_forest_scaler = model_data['scaler']
        feature_extractor = model_data['feature_extractor']
        print("  ✓ Isolation Forest cargado")
        
        print("✅ Modelos cargados exitosamente")
        
    except Exception as e:
        print(f"❌ Error cargando modelos: {str(e)}")
        raise


# ============================================================================
# ETAPA 1: PREPROCESAMIENTO Y CLASIFICACIÓN DE LOGS
# ============================================================================

def decode_kinesis_record(record: Dict) -> str:
    """
    Decodifica un registro de Kinesis Data Stream
    """
    try:
        encoded_data = record['kinesis']['data']
        decoded_bytes = base64.b64decode(encoded_data)
        decoded_text = decoded_bytes.decode('utf-8')
        return decoded_text
    except Exception as e:
        print(f"Error decodificando registro: {str(e)}")
        return ""


def parse_log(log_text: str) -> Dict[str, Any]:
    """
    Parsea el log y extrae campos estructurados
    
    Formatos soportados:
    - Apache/Nginx access logs
    - JSON logs
    - Custom application logs
    """
    try:
        # Intentar parsear como JSON primero
        log_data = json.loads(log_text)
        return log_data
    except json.JSONDecodeError:
        # Si no es JSON, parsear como log de Apache/Nginx
        # Formato: IP - - [timestamp] "METHOD /path HTTP/1.1" status size
        
        pattern = r'(\S+) - - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
        match = re.match(pattern, log_text)
        
        if match:
            return {
                'ip_address': match.group(1),
                'timestamp': match.group(2),
                'http_method': match.group(3),
                'url_path': match.group(4),
                'http_version': match.group(5),
                'status_code': int(match.group(6)),
                'response_size': int(match.group(7)),
                'raw_log': log_text
            }
        else:
            # Formato desconocido
            return {
                'raw_log': log_text,
                'timestamp': datetime.utcnow().isoformat()
            }


def classify_log_type(log_data: Dict) -> str:
    """
    Clasifica el tipo de log para determinar qué modelo usar
    
    Returns:
        'WEB_TRAFFIC': Tráfico HTTP/HTTPS (usar DistilBERT)
        'AUTH_EVENT': Evento de autenticación (usar Isolation Forest)
        'UNKNOWN': Tipo desconocido (descartar o log genérico)
    """
    
    # Heurísticas para clasificación
    
    # 1. Si tiene campos de autenticación
    auth_indicators = ['username', 'password', 'login', 'auth', 'authentication']
    if any(key in log_data for key in auth_indicators):
        return 'AUTH_EVENT'
    
    # 2. Si tiene campos de tráfico web
    web_indicators = ['url', 'url_path', 'request_body', 'http_method', 'user_agent']
    if any(key in log_data for key in web_indicators):
        return 'WEB_TRAFFIC'
    
    # 3. Si tiene método HTTP
    if 'http_method' in log_data and log_data['http_method'] in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
        return 'WEB_TRAFFIC'
    
    # 4. Tipo explícito en el log
    if 'log_type' in log_data:
        return log_data['log_type'].upper()
    
    # Default: desconocido
    return 'UNKNOWN'


# ============================================================================
# ETAPA 2: PIPELINE DE DISTILBERT (SQLi/XSS)
# ============================================================================

def extract_text_for_bert(log_data: Dict) -> str:
    """
    Extrae el texto relevante del log para análisis con BERT
    
    Prioridad:
    1. URL completa + query params + request body
    2. URL path + query params
    3. Raw log
    """
    
    text_parts = []
    
    # URL path
    if 'url_path' in log_data:
        text_parts.append(log_data['url_path'])
    elif 'url' in log_data:
        text_parts.append(log_data['url'])
    
    # Query parameters
    if 'query_params' in log_data:
        text_parts.append(log_data['query_params'])
    
    # Request body (POST data)
    if 'request_body' in log_data:
        text_parts.append(log_data['request_body'])
    
    # Headers (pueden contener inyecciones)
    if 'headers' in log_data:
        text_parts.append(str(log_data['headers']))
    
    # Si no hay nada, usar raw log
    if not text_parts and 'raw_log' in log_data:
        return log_data['raw_log']
    
    return ' '.join(text_parts)


def bert_inference(text: str) -> Dict[str, Any]:
    """
    Ejecuta inferencia con DistilBERT para detectar SQLi/XSS
    
    Returns:
        {
            'is_malicious': bool,
            'confidence': float,
            'label': str,
            'attack_type': str
        }
    """
    
    # Tokenizar
    inputs = distilbert_tokenizer(
        text,
        add_special_tokens=True,
        max_length=128,
        padding='max_length',
        truncation=True,
        return_tensors='pt'
    )
    
    inputs = {k: v.to(device) for k, v in inputs.items()}
    
    # Predecir
    with torch.no_grad():
        outputs = distilbert_model(**inputs)
        logits = outputs.logits
        proba = torch.softmax(logits, dim=1)
        prediction = torch.argmax(proba, dim=1).item()
        confidence = proba[0, prediction].item()
    
    # Interpretar resultado
    is_malicious = (prediction == 1)
    label = "MALICIOUS" if is_malicious else "NORMAL"
    
    # Determinar tipo de ataque (análisis heurístico adicional)
    attack_type = None
    if is_malicious:
        text_lower = text.lower()
        if 'union' in text_lower and 'select' in text_lower:
            attack_type = 'SQL Injection - UNION-based'
        elif "' or '" in text_lower or '1=1' in text_lower:
            attack_type = 'SQL Injection - Boolean-based'
        elif 'sleep(' in text_lower or 'benchmark(' in text_lower:
            attack_type = 'SQL Injection - Time-based'
        elif '<script>' in text_lower or 'javascript:' in text_lower:
            attack_type = 'Cross-Site Scripting (XSS)'
        else:
            attack_type = 'SQL Injection - Generic'
    
    return {
        'is_malicious': is_malicious,
        'confidence': confidence,
        'label': label,
        'attack_type': attack_type
    }


# ============================================================================
# ETAPA 3: PIPELINE DE ISOLATION FOREST (AUTENTICACIÓN)
# ============================================================================

def isolation_forest_inference(log_data: Dict) -> Dict[str, Any]:
    """
    Ejecuta inferencia con Isolation Forest para detectar anomalías
    
    Returns:
        {
            'is_anomaly': bool,
            'anomaly_score': float,
            'confidence': float
        }
    """
    
    # Extraer features
    features = feature_extractor.extract_features(log_data)
    
    # Normalizar
    features_scaled = isolation_forest_scaler.transform([features])
    
    # Predecir
    prediction = isolation_forest_model.predict(features_scaled)[0]
    anomaly_score = isolation_forest_model.score_samples(features_scaled)[0]
    
    # Interpretar (-1 = anomalía, 1 = normal)
    is_anomaly = (prediction == -1)
    
    # Convertir score a confianza (score más negativo = más anómalo)
    # Score típico: [-1.0, 0.5]
    confidence = abs(anomaly_score) if is_anomaly else (1 - abs(anomaly_score))
    
    return {
        'is_anomaly': is_anomaly,
        'anomaly_score': float(anomaly_score),
        'confidence': float(confidence)
    }


# ============================================================================
# ETAPA 4: GENERACIÓN Y ALMACENAMIENTO DE ALERTAS
# ============================================================================

def create_sqli_alert(log_data: Dict, prediction: Dict) -> Dict:
    """
    Crea alerta para SQLi/XSS detectado por DistilBERT
    """
    alert = {
        'alert_id': f"sqli-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'alert_type': 'WEB_ATTACK',
        'severity': 'HIGH',
        'detection_model': 'DistilBERT',
        'attack_classification': prediction['attack_type'],
        'confidence': prediction['confidence'],
        'source': {
            'ip_address': log_data.get('ip_address', 'unknown'),
            'http_method': log_data.get('http_method', 'unknown'),
            'url_path': log_data.get('url_path', 'unknown'),
            'user_agent': log_data.get('user_agent', 'unknown')
        },
        'payload': {
            'raw_log': log_data.get('raw_log', ''),
            'analyzed_text': extract_text_for_bert(log_data)
        },
        'recommended_action': 'BLOCK_IP' if prediction['confidence'] > 0.95 else 'MONITOR',
        'requires_investigation': True
    }
    
    return alert


def create_auth_alert(log_data: Dict, anomaly_result: Dict) -> Dict:
    """
    Crea alerta para anomalía de autenticación detectada por Isolation Forest
    """
    alert = {
        'alert_id': f"auth-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'alert_type': 'AUTH_ANOMALY',
        'severity': 'MEDIUM' if anomaly_result['anomaly_score'] > -0.5 else 'HIGH',
        'detection_model': 'Isolation Forest',
        'anomaly_score': anomaly_result['anomaly_score'],
        'confidence': anomaly_result['confidence'],
        'source': {
            'username': log_data.get('username', 'unknown'),
            'ip_address': log_data.get('ip_address', 'unknown'),
            'user_agent': log_data.get('user_agent', 'unknown'),
            'geo_location': {
                'lat': log_data.get('geo_lat', 0.0),
                'lon': log_data.get('geo_lon', 0.0)
            }
        },
        'event_details': {
            'success': log_data.get('success', None),
            'timestamp': log_data.get('timestamp', ''),
        },
        'recommended_action': 'REQUIRE_MFA' if anomaly_result['anomaly_score'] < -0.5 else 'MONITOR',
        'requires_investigation': True
    }
    
    return alert


def save_alert_to_s3(alert: Dict) -> bool:
    """
    Guarda la alerta en S3
    """
    try:
        alert_id = alert['alert_id']
        timestamp = datetime.utcnow().strftime('%Y/%m/%d')
        s3_key = f"alerts/{timestamp}/{alert_id}.json"
        
        alert_json = json.dumps(alert, indent=2, ensure_ascii=False)
        
        s3_client.put_object(
            Bucket=ALERT_BUCKET,
            Key=s3_key,
            Body=alert_json,
            ContentType='application/json',
            Metadata={
                'severity': alert['severity'],
                'alert_type': alert['alert_type']
            }
        )
        
        print(f"✓ Alerta guardada: s3://{ALERT_BUCKET}/{s3_key}")
        return True
        
    except Exception as e:
        print(f"✗ Error guardando alerta: {str(e)}")
        return False


# ============================================================================
# FUNCIÓN PRINCIPAL DEL HANDLER LAMBDA
# ============================================================================

def lambda_handler(event: Dict, context: Any) -> Dict:
    """
    Handler principal de la función Lambda
    
    Pipeline Híbrido:
    1. Decodificar logs de Kinesis
    2. Clasificar tipo de log (Web Traffic vs Auth Event)
    3. Ejecutar modelo apropiado (DistilBERT vs Isolation Forest)
    4. Generar y guardar alertas si se detecta amenaza
    """
    
    print("="*80)
    print("AthenAI - Sistema Híbrido de Detección de Intrusos")
    print("="*80)
    
    # Cargar modelos (solo en cold start)
    if distilbert_model is None or isolation_forest_model is None:
        load_models()
    
    # Contadores
    total_records = 0
    web_traffic_count = 0
    auth_event_count = 0
    sqli_detected = 0
    auth_anomalies = 0
    alerts_saved = 0
    
    try:
        for record in event['Records']:
            total_records += 1
            
            # ================================================================
            # ETAPA 1: PREPROCESAMIENTO
            # ================================================================
            print(f"\n[{total_records}] Procesando registro...")
            
            log_text = decode_kinesis_record(record)
            if not log_text:
                print("  ⚠ Registro vacío. Saltando...")
                continue
            
            log_data = parse_log(log_text)
            log_type = classify_log_type(log_data)
            
            print(f"  → Tipo de log: {log_type}")
            
            # ================================================================
            # ETAPA 2: CLASIFICACIÓN Y DETECCIÓN
            # ================================================================
            
            if log_type == 'WEB_TRAFFIC':
                web_traffic_count += 1
                
                # Pipeline DistilBERT
                text = extract_text_for_bert(log_data)
                print(f"  → Analizando con DistilBERT: {text[:80]}...")
                
                prediction = bert_inference(text)
                
                if prediction['is_malicious']:
                    sqli_detected += 1
                    print(f"  🚨 AMENAZA DETECTADA!")
                    print(f"  → Tipo: {prediction['attack_type']}")
                    print(f"  → Confianza: {prediction['confidence']:.2%}")
                    
                    alert = create_sqli_alert(log_data, prediction)
                    if save_alert_to_s3(alert):
                        alerts_saved += 1
                else:
                    print(f"  ✓ Tráfico legítimo (Confianza: {prediction['confidence']:.2%})")
            
            elif log_type == 'AUTH_EVENT':
                auth_event_count += 1
                
                # Pipeline Isolation Forest
                print(f"  → Analizando con Isolation Forest...")
                
                anomaly_result = isolation_forest_inference(log_data)
                
                if anomaly_result['is_anomaly']:
                    auth_anomalies += 1
                    print(f"  🚨 ANOMALÍA DETECTADA!")
                    print(f"  → Score: {anomaly_result['anomaly_score']:.4f}")
                    print(f"  → Confianza: {anomaly_result['confidence']:.2%}")
                    
                    alert = create_auth_alert(log_data, anomaly_result)
                    if save_alert_to_s3(alert):
                        alerts_saved += 1
                else:
                    print(f"  ✓ Comportamiento normal (Score: {anomaly_result['anomaly_score']:.4f})")
            
            else:
                print(f"  ⚠ Tipo de log desconocido. Saltando...")
        
        # ====================================================================
        # RESUMEN DE EJECUCIÓN
        # ====================================================================
        print("\n" + "="*80)
        print("RESUMEN DE PROCESAMIENTO")
        print("="*80)
        print(f"Total de registros:     {total_records}")
        print(f"Tráfico web:            {web_traffic_count}")
        print(f"Eventos de auth:        {auth_event_count}")
        print(f"SQLi/XSS detectados:    {sqli_detected}")
        print(f"Anomalías de auth:      {auth_anomalies}")
        print(f"Alertas guardadas:      {alerts_saved}")
        print("="*80)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Procesamiento completado exitosamente',
                'statistics': {
                    'total_records': total_records,
                    'web_traffic': web_traffic_count,
                    'auth_events': auth_event_count,
                    'sqli_detected': sqli_detected,
                    'auth_anomalies': auth_anomalies,
                    'alerts_saved': alerts_saved
                }
            })
        }
        
    except Exception as e:
        print(f"\n✗ ERROR CRÍTICO: {str(e)}")
        import traceback
        traceback.print_exc()
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Error en el procesamiento',
                'error': str(e)
            })
        }
