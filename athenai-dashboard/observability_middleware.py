"""
Middleware de Observabilidad para AthenAI

Middleware de Flask que automáticamente:
- Envía logs de cada request a CloudWatch
- Envía métricas de latencia y errores a CloudWatch
- Registra información de seguridad
"""

import time
import logging
from flask import request, g
from functools import wraps

logger = logging.getLogger(__name__)


class ObservabilityMiddleware:
    def __init__(self, app=None, cloudwatch_logger=None, metrics_collector=None):
        """
        Inicializa el middleware de observabilidad.
        
        Args:
            app: Flask app
            cloudwatch_logger: Instancia de CloudWatchLogger
            metrics_collector: Instancia de MetricsCollector
        """
        self.cloudwatch_logger = cloudwatch_logger
        self.metrics_collector = metrics_collector
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Registra el middleware en la app"""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        app.teardown_request(self.teardown_request)
        
        logger.info("✅ Observability Middleware activado")
    
    def before_request(self):
        """Se ejecuta antes de cada request"""
        # Guardar timestamp de inicio
        g.start_time = time.time()
        g.request_id = f"{int(time.time() * 1000)}-{id(request)}"
    
    def after_request(self, response):
        """Se ejecuta después de cada request"""
        if not hasattr(g, 'start_time'):
            return response
        
        # Calcular latencia
        latency_ms = (time.time() - g.start_time) * 1000
        
        # Información del request
        method = request.method
        path = request.path
        status_code = response.status_code
        source_ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # Determinar si es error
        is_error = status_code >= 400
        
        # Log a CloudWatch
        if self.cloudwatch_logger:
            try:
                log_group = 'errors' if is_error else 'api'
                level = 'ERROR' if status_code >= 500 else 'WARNING' if is_error else 'INFO'
                
                self.cloudwatch_logger.log(
                    group=log_group,
                    level=level,
                    message=f"{method} {path} → {status_code}",
                    metadata={
                        'request_id': g.request_id,
                        'method': method,
                        'path': path,
                        'status_code': status_code,
                        'latency_ms': round(latency_ms, 2),
                        'source_ip': source_ip,
                        'user_agent': user_agent
                    }
                )
            except Exception as e:
                logger.error(f"Error enviando log a CloudWatch: {e}")
        
        # Métricas a CloudWatch
        if self.metrics_collector:
            try:
                # Latencia de API
                self.metrics_collector.record_api_latency(latency_ms, path)
                
                # Count de requests
                self.metrics_collector.record_request_count(1, method)
                
                # Errores
                if is_error:
                    error_type = f"{status_code}"
                    self.metrics_collector.record_error(1, error_type)
            
            except Exception as e:
                logger.error(f"Error enviando métricas a CloudWatch: {e}")
        
        return response
    
    def teardown_request(self, exception=None):
        """Se ejecuta al finalizar el request (incluso si hay error)"""
        if exception and self.cloudwatch_logger:
            try:
                self.cloudwatch_logger.log_error(
                    message=f"Unhandled exception: {str(exception)}",
                    request_id=getattr(g, 'request_id', 'unknown'),
                    path=request.path,
                    method=request.method,
                    exception_type=type(exception).__name__
                )
            except Exception as e:
                logger.error(f"Error logging exception: {e}")


def log_ml_prediction(model_name: str, confidence: float, latency_ms: float, is_threat: bool):
    """
    Helper para loggear predicciones ML.
    
    Args:
        model_name: Nombre del modelo
        confidence: Confianza de la predicción (0.0-1.0)
        latency_ms: Latencia de inferencia (ms)
        is_threat: Si se detectó amenaza
    """
    from flask import current_app
    
    cloudwatch_logger = current_app.config.get('CLOUDWATCH_LOGGER')
    metrics_collector = current_app.config.get('METRICS_COLLECTOR')
    
    if cloudwatch_logger:
        try:
            cloudwatch_logger.log_ml(
                level='WARNING' if is_threat else 'INFO',
                message=f"ML Prediction: {model_name}",
                model=model_name,
                confidence=confidence,
                latency_ms=latency_ms,
                is_threat=is_threat
            )
        except Exception as e:
            logger.error(f"Error logging ML prediction: {e}")
    
    if metrics_collector:
        try:
            metrics_collector.record_ml_inference_latency(latency_ms, model_name)
            metrics_collector.record_ml_confidence(confidence)
            
            if is_threat:
                metrics_collector.record_threat_detection(1)
        
        except Exception as e:
            logger.error(f"Error recording ML metrics: {e}")


def log_security_event(event_type: str, source_ip: str, action: str, **metadata):
    """
    Helper para loggear eventos de seguridad.
    
    Args:
        event_type: Tipo de evento (block, rate_limit, ml_detection, etc.)
        source_ip: IP origen
        action: Acción tomada (blocked, allowed, alerted)
        **metadata: Metadata adicional
    """
    from flask import current_app
    
    cloudwatch_logger = current_app.config.get('CLOUDWATCH_LOGGER')
    metrics_collector = current_app.config.get('METRICS_COLLECTOR')
    
    if cloudwatch_logger:
        try:
            cloudwatch_logger.log_security(
                level='WARNING',
                message=f"Security Event: {event_type}",
                event_type=event_type,
                source_ip=source_ip,
                action=action,
                **metadata
            )
        except Exception as e:
            logger.error(f"Error logging security event: {e}")
    
    if metrics_collector and action == 'blocked':
        try:
            metrics_collector.record_blocked_request(1)
        except Exception as e:
            logger.error(f"Error recording blocked request metric: {e}")
