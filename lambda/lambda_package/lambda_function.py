"""
AthenAI - Sistema de Detección de Intrusos
Tesis de Maestría: Detección de Inyecciones SQL en Tiempo Real

Módulo: Procesamiento de Logs y Clasificación de Amenazas
Autor: [Tu Nombre]
Fecha: Enero 2026

Este módulo implementa la función AWS Lambda que procesa logs de tráfico web
desde Kinesis Data Stream y detecta patrones de SQL Injection en tiempo real.
"""

import json
import base64
import boto3
import re
from datetime import datetime
from typing import Dict, List, Tuple, Any


# ============================================================================
# CONFIGURACIÓN DE SERVICIOS AWS
# ============================================================================

# Cliente S3 para almacenamiento de alertas
s3_client = boto3.client('s3')

# Nombre del bucket de destino para alertas
ALERT_BUCKET = 'athenai-alertas'


# ============================================================================
# ETAPA 1: PREPROCESAMIENTO DE DATOS
# ============================================================================

def decode_kinesis_record(record: Dict) -> str:
    """
    Decodifica un registro de Kinesis Data Stream.
    
    Metodología (Sección 3.2.1 - Preprocesamiento):
    Los datos llegan codificados en base64 desde Kinesis. Esta función
    realiza la decodificación y conversión a texto plano para su análisis.
    
    Args:
        record: Diccionario con la estructura del registro de Kinesis
        
    Returns:
        str: Texto decodificado del log de tráfico web
    """
    try:
        # Extraer datos codificados del registro
        encoded_data = record['kinesis']['data']
        
        # Decodificar de base64 a bytes
        decoded_bytes = base64.b64decode(encoded_data)
        
        # Convertir bytes a string UTF-8
        decoded_text = decoded_bytes.decode('utf-8')
        
        return decoded_text
    
    except Exception as e:
        print(f"Error decodificando registro: {str(e)}")
        return ""


def extract_log_metadata(log_text: str) -> Dict[str, Any]:
    """
    Extrae metadatos del log para enriquecer las alertas.
    
    Metodología (Sección 3.2.1 - Preprocesamiento):
    Extrae información contextual como IP de origen, timestamp, método HTTP, etc.
    
    Args:
        log_text: Texto del log decodificado
        
    Returns:
        Dict: Metadatos extraídos del log
    """
    metadata = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'raw_log': log_text,
        'source_ip': 'unknown',
        'http_method': 'unknown',
        'url_path': 'unknown'
    }
    
    # Intentar extraer IP (patrón común en logs de acceso)
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_match = re.search(ip_pattern, log_text)
    if ip_match:
        metadata['source_ip'] = ip_match.group(0)
    
    # Intentar extraer método HTTP
    http_method_pattern = r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b'
    method_match = re.search(http_method_pattern, log_text)
    if method_match:
        metadata['http_method'] = method_match.group(1)
    
    return metadata


# ============================================================================
# ETAPA 2: CLASIFICACIÓN Y DETECCIÓN DE AMENAZAS
# ============================================================================

def predict_injection(log_text: str) -> Tuple[bool, List[str]]:
    """
    Simula la detección de SQL Injection mediante análisis de patrones.
    
    Metodología (Sección 3.3.2 - Clasificación con IA):
    NOTA: Esta es una implementación temporal basada en reglas que simula
    el comportamiento del modelo BERT. En la versión final, esta función
    será reemplazada por inferencia del modelo de Deep Learning.
    
    Patrones detectados:
    - UNION-based SQL Injection
    - Boolean-based Blind SQL Injection
    - Time-based Blind SQL Injection
    - Stacked Queries
    - Comment-based Injection
    
    Args:
        log_text: Texto del log a analizar
        
    Returns:
        Tuple[bool, List[str]]: (es_malicioso, lista_de_patrones_detectados)
    """
    
    # Convertir a minúsculas para análisis case-insensitive
    log_lower = log_text.lower()
    
    detected_patterns = []
    
    # ========================================================================
    # PATRONES DE SQL INJECTION (Basados en OWASP Top 10)
    # ========================================================================
    
    # 1. UNION-based Injection
    union_patterns = [
        r"union\s+select",
        r"union\s+all\s+select",
        r"\bunion\b.*\bselect\b"
    ]
    
    # 2. Boolean-based Blind Injection
    boolean_patterns = [
        r"'\s*or\s*'1'\s*=\s*'1",
        r"'\s*or\s*1\s*=\s*1",
        r"'\s*or\s*'a'\s*=\s*'a",
        r"\bor\b\s+\d+\s*=\s*\d+",
        r"'\s*and\s*'1'\s*=\s*'2",
        r"admin'\s*--",
        r"admin'\s*#"
    ]
    
    # 3. Time-based Blind Injection
    time_patterns = [
        r"sleep\s*\(",
        r"benchmark\s*\(",
        r"waitfor\s+delay",
        r"pg_sleep\s*\("
    ]
    
    # 4. Stacked Queries
    stacked_patterns = [
        r";\s*drop\s+table",
        r";\s*delete\s+from",
        r";\s*update\s+",
        r";\s*insert\s+into",
        r";\s*exec\s*\(",
        r";\s*execute\s*\("
    ]
    
    # 5. Comment-based Injection
    comment_patterns = [
        r"--\s*$",
        r"#\s*$",
        r"/\*.*\*/",
        r"'\s*--",
        r"'\s*#"
    ]
    
    # 6. Information Schema Exploitation
    schema_patterns = [
        r"information_schema",
        r"sys\.databases",
        r"mysql\.user",
        r"pg_catalog"
    ]
    
    # 7. String Concatenation Attacks
    concat_patterns = [
        r"concat\s*\(",
        r"\|\|",  # PostgreSQL/Oracle concatenation
        r"\+.*select"  # SQL Server concatenation
    ]
    
    # ========================================================================
    # ANÁLISIS DE PATRONES
    # ========================================================================
    
    pattern_groups = {
        'UNION-based Injection': union_patterns,
        'Boolean-based Blind Injection': boolean_patterns,
        'Time-based Blind Injection': time_patterns,
        'Stacked Queries': stacked_patterns,
        'Comment-based Injection': comment_patterns,
        'Information Schema Exploitation': schema_patterns,
        'String Concatenation Attack': concat_patterns
    }
    
    for attack_type, patterns in pattern_groups.items():
        for pattern in patterns:
            if re.search(pattern, log_lower):
                detected_patterns.append(attack_type)
                break  # Solo agregar el tipo una vez
    
    # Determinar si es malicioso
    is_malicious = len(detected_patterns) > 0
    
    return is_malicious, detected_patterns


# ============================================================================
# ETAPA 3: ALMACENAMIENTO DE ALERTAS
# ============================================================================

def create_alert_object(metadata: Dict, detected_patterns: List[str]) -> Dict:
    """
    Crea el objeto JSON de alerta con toda la información relevante.
    
    Metodología (Sección 3.4 - Almacenamiento de Alertas):
    Estructura la información de la amenaza detectada en formato JSON
    para su almacenamiento y análisis posterior.
    
    Args:
        metadata: Metadatos extraídos del log
        detected_patterns: Lista de patrones de ataque detectados
        
    Returns:
        Dict: Objeto de alerta estructurado
    """
    alert = {
        'alert_id': f"alert-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
        'timestamp': metadata['timestamp'],
        'severity': 'HIGH',  # Todas las SQL Injections son de alta severidad
        'attack_type': 'SQL Injection',
        'attack_patterns': detected_patterns,
        'source': {
            'ip_address': metadata['source_ip'],
            'http_method': metadata['http_method'],
            'url_path': metadata['url_path']
        },
        'payload': {
            'raw_log': metadata['raw_log']
        },
        'detection_method': 'Pattern-based (Simulated BERT)',
        'status': 'DETECTED',
        'requires_investigation': True
    }
    
    return alert


def save_alert_to_s3(alert: Dict) -> bool:
    """
    Guarda la alerta en el bucket S3 de AthenAI.
    
    Metodología (Sección 3.4 - Almacenamiento de Alertas):
    Persiste las alertas en S3 para análisis forense y generación de reportes.
    Compatible con LocalStack para desarrollo local.
    
    Args:
        alert: Objeto de alerta a guardar
        
    Returns:
        bool: True si se guardó exitosamente, False en caso contrario
    """
    try:
        # Generar nombre de archivo único
        alert_id = alert['alert_id']
        timestamp = datetime.utcnow().strftime('%Y/%m/%d')
        s3_key = f"alerts/{timestamp}/{alert_id}.json"
        
        # Convertir alerta a JSON
        alert_json = json.dumps(alert, indent=2, ensure_ascii=False)
        
        # Subir a S3
        s3_client.put_object(
            Bucket=ALERT_BUCKET,
            Key=s3_key,
            Body=alert_json,
            ContentType='application/json',
            Metadata={
                'severity': alert['severity'],
                'attack_type': alert['attack_type']
            }
        )
        
        print(f"✓ Alerta guardada exitosamente: s3://{ALERT_BUCKET}/{s3_key}")
        return True
        
    except Exception as e:
        print(f"✗ Error guardando alerta en S3: {str(e)}")
        return False


# ============================================================================
# FUNCIÓN PRINCIPAL DEL HANDLER LAMBDA
# ============================================================================

def lambda_handler(event: Dict, context: Any) -> Dict:
    """
    Handler principal de la función Lambda.
    
    Metodología (Sección 3 - Arquitectura del Sistema):
    Esta función orquesta todo el pipeline de detección:
    1. Preprocesamiento: Decodificación de logs de Kinesis
    2. Clasificación: Detección de patrones de SQL Injection
    3. Almacenamiento: Persistencia de alertas en S3
    
    Args:
        event: Evento de Kinesis con los registros de logs
        context: Contexto de ejecución de Lambda
        
    Returns:
        Dict: Resumen de la ejecución
    """
    
    print("=" * 80)
    print("AthenAI - Sistema de Detección de Intrusos")
    print("Iniciando procesamiento de logs...")
    print("=" * 80)
    
    # Contadores para estadísticas
    total_records = 0
    malicious_records = 0
    alerts_saved = 0
    
    try:
        # Iterar sobre todos los registros del evento de Kinesis
        for record in event['Records']:
            total_records += 1
            
            # ================================================================
            # ETAPA 1: PREPROCESAMIENTO
            # ================================================================
            print(f"\n[{total_records}] Procesando registro...")
            
            # Decodificar el registro de Kinesis
            log_text = decode_kinesis_record(record)
            
            if not log_text:
                print("  ⚠ Registro vacío o error en decodificación. Saltando...")
                continue
            
            print(f"  ✓ Log decodificado: {log_text[:100]}...")
            
            # Extraer metadatos del log
            metadata = extract_log_metadata(log_text)
            
            # ================================================================
            # ETAPA 2: CLASIFICACIÓN
            # ================================================================
            print("  → Analizando con detector de SQL Injection...")
            
            # Ejecutar detección de SQL Injection
            is_malicious, detected_patterns = predict_injection(log_text)
            
            if is_malicious:
                malicious_records += 1
                print(f"  ⚠ AMENAZA DETECTADA!")
                print(f"  → Patrones identificados: {', '.join(detected_patterns)}")
                
                # ============================================================
                # ETAPA 3: ALMACENAMIENTO DE ALERTA
                # ============================================================
                
                # Crear objeto de alerta
                alert = create_alert_object(metadata, detected_patterns)
                
                # Guardar en S3
                if save_alert_to_s3(alert):
                    alerts_saved += 1
            else:
                print("  ✓ Tráfico legítimo. No se detectaron amenazas.")
        
        # ====================================================================
        # RESUMEN DE EJECUCIÓN
        # ====================================================================
        print("\n" + "=" * 80)
        print("RESUMEN DE PROCESAMIENTO")
        print("=" * 80)
        print(f"Total de registros procesados: {total_records}")
        print(f"Amenazas detectadas: {malicious_records}")
        print(f"Alertas guardadas en S3: {alerts_saved}")
        print("=" * 80)
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Procesamiento completado exitosamente',
                'statistics': {
                    'total_records': total_records,
                    'malicious_records': malicious_records,
                    'alerts_saved': alerts_saved,
                    'detection_rate': f"{(malicious_records/total_records*100):.2f}%" if total_records > 0 else "0%"
                }
            })
        }
        
    except Exception as e:
        print(f"\n✗ ERROR CRÍTICO: {str(e)}")
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'Error en el procesamiento',
                'error': str(e)
            })
        }


# ============================================================================
# FUNCIÓN DE PRUEBA LOCAL (Opcional)
# ============================================================================

if __name__ == "__main__":
    """
    Función de prueba para desarrollo local.
    Simula un evento de Kinesis con logs de prueba.
    """
    
    # Logs de prueba (algunos maliciosos, otros legítimos)
    test_logs = [
        "192.168.1.100 - - [20/Jan/2026:15:30:45 +0000] \"GET /products?id=1 HTTP/1.1\" 200 1234",
        "192.168.1.101 - - [20/Jan/2026:15:31:12 +0000] \"GET /login?user=admin' OR '1'='1 HTTP/1.1\" 200 5678",
        "192.168.1.102 - - [20/Jan/2026:15:31:45 +0000] \"POST /search?q=laptop HTTP/1.1\" 200 2345",
        "192.168.1.103 - - [20/Jan/2026:15:32:10 +0000] \"GET /api/users?id=1 UNION SELECT * FROM passwords-- HTTP/1.1\" 200 3456"
    ]
    
    # Crear evento simulado de Kinesis
    simulated_event = {
        'Records': []
    }
    
    for log in test_logs:
        # Codificar en base64 como lo haría Kinesis
        encoded_log = base64.b64encode(log.encode('utf-8')).decode('utf-8')
        
        record = {
            'kinesis': {
                'data': encoded_log
            }
        }
        
        simulated_event['Records'].append(record)
    
    # Ejecutar handler con evento simulado
    print("EJECUTANDO PRUEBA LOCAL")
    print("=" * 80)
    result = lambda_handler(simulated_event, None)
    print("\nRESULTADO:")
    print(json.dumps(result, indent=2))
