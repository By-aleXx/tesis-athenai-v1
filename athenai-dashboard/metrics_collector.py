"""
Metrics Collector para AthenAI

Envía métricas custom a CloudWatch Metrics (LocalStack)

Namespace: AthenAI/Security

Métricas:
- ThreatDetectionRate - Amenazas/minuto
- MLConfidence - Confianza promedio del modelo
- BlockedRequests - Requests bloqueadas/minuto
- APILatency - Latencia de API (ms)
- MLInferenceLatency - Latencia de ML (ms)
- ErrorRate - Errores/minuto
"""

import os
import boto3
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class MetricsCollector:
    def __init__(self, endpoint_url=None, namespace='AthenAI/Security'):
        """
        Inicializa el Metrics Collector.
        
        Args:
            endpoint_url: URL de LocalStack (default: leído de AWS_ENDPOINT_URL en .env)
            namespace: Namespace de CloudWatch (default: AthenAI/Security)
        """
        self.endpoint_url = endpoint_url or os.environ['AWS_ENDPOINT_URL']
        
        self.namespace = namespace
        
        self.client = boto3.client(
            'cloudwatch',
            endpoint_url=self.endpoint_url,
            region_name=os.getenv('AWS_REGION', 'us-east-1'),
            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
        )
        
        logger.info(f"✅ Metrics Collector inicializado (namespace: {namespace})")
    
    def put_metric(
        self,
        metric_name: str,
        value: float,
        unit: str = 'None',
        dimensions: Optional[List[Dict[str, str]]] = None,
        timestamp: Optional[datetime] = None
    ):
        """
        Envía una métrica a CloudWatch.
        
        Args:
            metric_name: Nombre de la métrica
            value: Valor de la métrica
            unit: Unidad (None, Count, Milliseconds, etc.)
            dimensions: Dimensiones adicionales [{'Name': 'x', 'Value': 'y'}]
            timestamp: Timestamp (default: ahora)
        """
        try:
            metric_data = {
                'MetricName': metric_name,
                'Value': value,
                'Unit': unit,
                'Timestamp': timestamp or datetime.utcnow()
            }
            
            if dimensions:
                metric_data['Dimensions'] = dimensions
            
            self.client.put_metric_data(
                Namespace=self.namespace,
                MetricData=[metric_data]
            )
            
            logger.debug(f"📊 Métrica enviada: {metric_name}={value} {unit}")
        
        except Exception as e:
            logger.error(f"Error enviando métrica {metric_name}: {e}")
    
    def put_metrics(self, metrics: List[Dict[str, Any]]):
        """
        Envía múltiples métricas en batch.
        
        Args:
            metrics: Lista de métricas [{'name': 'x', 'value': 1, 'unit': 'Count'}, ...]
        """
        try:
            metric_data = []
            
            for metric in metrics:
                data = {
                    'MetricName': metric['name'],
                    'Value': metric['value'],
                    'Unit': metric.get('unit', 'None'),
                    'Timestamp': metric.get('timestamp', datetime.utcnow())
                }
                
                if 'dimensions' in metric:
                    data['Dimensions'] = metric['dimensions']
                
                metric_data.append(data)
            
            # CloudWatch permite hasta 20 métricas por request
            for i in range(0, len(metric_data), 20):
                batch = metric_data[i:i+20]
                self.client.put_metric_data(
                    Namespace=self.namespace,
                    MetricData=batch
                )
            
            logger.debug(f"📊 {len(metrics)} métricas enviadas")
        
        except Exception as e:
            logger.error(f"Error enviando métricas en batch: {e}")
    
    # Métricas específicas de AthenAI
    
    def record_threat_detection(self, count: int = 1):
        """Registra detección de amenaza"""
        self.put_metric('ThreatDetectionRate', count, 'Count')
    
    def record_ml_confidence(self, confidence: float):
        """Registra confianza del modelo ML (0.0-1.0)"""
        self.put_metric('MLConfidence', confidence * 100, 'Percent')
    
    def record_blocked_request(self, count: int = 1):
        """Registra request bloqueada"""
        self.put_metric('BlockedRequests', count, 'Count')
    
    def record_api_latency(self, latency_ms: float, endpoint: Optional[str] = None):
        """Registra latencia de API"""
        dimensions = None
        if endpoint:
            dimensions = [{'Name': 'Endpoint', 'Value': endpoint}]
        
        self.put_metric('APILatency', latency_ms, 'Milliseconds', dimensions)
    
    def record_ml_inference_latency(self, latency_ms: float, model: Optional[str] = None):
        """Registra latencia de inferencia ML"""
        dimensions = None
        if model:
            dimensions = [{'Name': 'Model', 'Value': model}]
        
        self.put_metric('MLInferenceLatency', latency_ms, 'Milliseconds', dimensions)
    
    def record_database_latency(self, latency_ms: float, operation: Optional[str] = None):
        """Registra latencia de base de datos"""
        dimensions = None
        if operation:
            dimensions = [{'Name': 'Operation', 'Value': operation}]
        
        self.put_metric('DatabaseLatency', latency_ms, 'Milliseconds', dimensions)
    
    def record_error(self, count: int = 1, error_type: Optional[str] = None):
        """Registra error"""
        dimensions = None
        if error_type:
            dimensions = [{'Name': 'ErrorType', 'Value': error_type}]
        
        self.put_metric('ErrorRate', count, 'Count', dimensions)
    
    def record_false_positive(self, count: int = 1):
        """Registra falso positivo"""
        self.put_metric('FalsePositiveRate', count, 'Count')
    
    def record_request_count(self, count: int = 1, method: Optional[str] = None):
        """Registra cantidad de requests"""
        dimensions = None
        if method:
            dimensions = [{'Name': 'Method', 'Value': method}]
        
        self.put_metric('RequestCount', count, 'Count', dimensions)
    
    def record_cache_hit(self, count: int = 1):
        """Registra cache hit"""
        self.put_metric('CacheHitRate', count, 'Count')
    
    def record_cache_miss(self, count: int = 1):
        """Registra cache miss"""
        self.put_metric('CacheMissRate', count, 'Count')


# Instancia global
try:
    metrics_collector = MetricsCollector()
except Exception as e:
    logger.error(f"Error inicializando Metrics Collector: {e}")
    metrics_collector = None
