"""
AWS X-Ray Middleware for AthenAI
Provides distributed tracing for Flask application
"""

import os
import time
import functools
from typing import Callable, Any, Dict, Optional
from flask import request, g
from aws_xray_sdk.core import xray_recorder
from aws_xray_sdk.core import patch_all
from aws_xray_sdk.ext.flask.middleware import XRayMiddleware

# Patch AWS SDK and other libraries
patch_all()


class AthenAIXRayMiddleware:
    """Custom X-Ray middleware for AthenAI with enhanced tracing"""
    
    def __init__(self, app=None, use_localstack: bool = True):
        """
        Initialize X-Ray middleware
        
        Args:
            app: Flask application
            use_localstack: Whether to use LocalStack (default: True)
        """
        self.app = app
        self.use_localstack = use_localstack
        
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize X-Ray for Flask app"""
        # Configure X-Ray
        if self.use_localstack:
            # LocalStack X-Ray endpoint
            os.environ['AWS_XRAY_DAEMON_ADDRESS'] = os.getenv(
                'XRAY_DAEMON_ADDRESS',
                'localhost:2000'
            )
        
        # Set service name
        xray_recorder.configure(
            service='AthenAI-API',
            sampling=True,
            context_missing='LOG_ERROR'
        )
        
        # Apply X-Ray middleware to Flask
        XRayMiddleware(app, xray_recorder)
        
        # Add before/after request handlers
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        print("✅ X-Ray middleware initialized")
    
    def before_request(self):
        """Called before each request"""
        # Store request start time
        g.start_time = time.time()
        
        # Add annotations to current segment
        try:
            segment = xray_recorder.current_segment()
            if segment:
                # Add request metadata
                segment.put_annotation('method', request.method)
                segment.put_annotation('path', request.path)
                segment.put_annotation('remote_addr', request.remote_addr)
                
                # Add user info if available
                if hasattr(g, 'user') and g.user:
                    segment.put_annotation('user_id', g.user.get('user_id', 'unknown'))
                    segment.put_annotation('user_role', g.user.get('role', 'unknown'))
        except Exception as e:
            print(f"Error adding X-Ray annotations: {e}")
    
    def after_request(self, response):
        """Called after each request"""
        try:
            segment = xray_recorder.current_segment()
            if segment:
                # Add response metadata
                segment.put_annotation('status_code', response.status_code)
                
                # Calculate request duration
                if hasattr(g, 'start_time'):
                    duration = (time.time() - g.start_time) * 1000  # ms
                    segment.put_metadata('duration_ms', duration, 'performance')
                
                # Add threat detection info if available
                if hasattr(g, 'threat_detected'):
                    segment.put_annotation('threat_detected', g.threat_detected)
                
                if hasattr(g, 'policy_decision'):
                    segment.put_annotation('policy_decision', g.policy_decision)
                
                if hasattr(g, 'risk_score'):
                    segment.put_metadata('risk_score', g.risk_score, 'security')
        
        except Exception as e:
            print(f"Error adding X-Ray response metadata: {e}")
        
        return response


def trace_subsegment(name: str, metadata: Optional[Dict[str, Any]] = None):
    """
    Decorator to create X-Ray subsegment for a function
    
    Usage:
        @trace_subsegment('ml-inference')
        def predict(data):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                # Create subsegment
                subsegment = xray_recorder.begin_subsegment(name)
                
                # Add metadata if provided
                if metadata:
                    for key, value in metadata.items():
                        subsegment.put_metadata(key, value, 'custom')
                
                # Execute function
                start_time = time.time()
                result = func(*args, **kwargs)
                duration = (time.time() - start_time) * 1000
                
                # Add duration metadata
                subsegment.put_metadata('duration_ms', duration, 'performance')
                
                # Close subsegment
                xray_recorder.end_subsegment()
                
                return result
            
            except Exception as e:
                # Record exception
                if xray_recorder.current_subsegment():
                    xray_recorder.current_subsegment().add_exception(e)
                    xray_recorder.end_subsegment()
                raise
        
        return wrapper
    return decorator


def trace_ml_inference(model_name: str):
    """
    Decorator specifically for ML inference tracing
    
    Usage:
        @trace_ml_inference('xgboost-v1')
        def predict(features):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                subsegment = xray_recorder.begin_subsegment('ml-inference')
                subsegment.put_annotation('model_name', model_name)
                
                start_time = time.time()
                result = func(*args, **kwargs)
                duration = (time.time() - start_time) * 1000
                
                # Add ML-specific metadata
                subsegment.put_metadata('inference_time_ms', duration, 'ml')
                subsegment.put_annotation('model_version', model_name)
                
                # Add prediction metadata if result is dict
                if isinstance(result, dict):
                    if 'prediction' in result:
                        subsegment.put_annotation('prediction', str(result['prediction']))
                    if 'confidence' in result:
                        subsegment.put_metadata('confidence', result['confidence'], 'ml')
                
                xray_recorder.end_subsegment()
                return result
            
            except Exception as e:
                if xray_recorder.current_subsegment():
                    xray_recorder.current_subsegment().add_exception(e)
                    xray_recorder.end_subsegment()
                raise
        
        return wrapper
    return decorator


def trace_database_operation(operation: str, table: str):
    """
    Decorator for database operation tracing
    
    Usage:
        @trace_database_operation('put_item', 'traffic_logs')
        def save_log(data):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                subsegment = xray_recorder.begin_subsegment('database')
                subsegment.put_annotation('operation', operation)
                subsegment.put_annotation('table', table)
                
                start_time = time.time()
                result = func(*args, **kwargs)
                duration = (time.time() - start_time) * 1000
                
                subsegment.put_metadata('db_latency_ms', duration, 'database')
                
                xray_recorder.end_subsegment()
                return result
            
            except Exception as e:
                if xray_recorder.current_subsegment():
                    xray_recorder.current_subsegment().add_exception(e)
                    xray_recorder.end_subsegment()
                raise
        
        return wrapper
    return decorator


def trace_cache_operation(operation: str):
    """
    Decorator for cache operation tracing
    
    Usage:
        @trace_cache_operation('get')
        def get_from_cache(key):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                subsegment = xray_recorder.begin_subsegment('cache')
                subsegment.put_annotation('operation', operation)
                
                start_time = time.time()
                result = func(*args, **kwargs)
                duration = (time.time() - start_time) * 1000
                
                subsegment.put_metadata('cache_latency_ms', duration, 'cache')
                subsegment.put_annotation('cache_hit', result is not None)
                
                xray_recorder.end_subsegment()
                return result
            
            except Exception as e:
                if xray_recorder.current_subsegment():
                    xray_recorder.current_subsegment().add_exception(e)
                    xray_recorder.end_subsegment()
                raise
        
        return wrapper
    return decorator


def trace_evidence_store(operation: str):
    """
    Decorator for evidence store operation tracing
    
    Usage:
        @trace_evidence_store('store')
        def store_evidence(data):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                subsegment = xray_recorder.begin_subsegment('evidence-store')
                subsegment.put_annotation('operation', operation)
                
                start_time = time.time()
                result = func(*args, **kwargs)
                duration = (time.time() - start_time) * 1000
                
                subsegment.put_metadata('evidence_store_latency_ms', duration, 'storage')
                
                # Add integrity check metadata if available
                if isinstance(result, dict) and 'integrity_hash' in result:
                    subsegment.put_metadata('integrity_hash', result['integrity_hash'], 'security')
                
                xray_recorder.end_subsegment()
                return result
            
            except Exception as e:
                if xray_recorder.current_subsegment():
                    xray_recorder.current_subsegment().add_exception(e)
                    xray_recorder.end_subsegment()
                raise
        
        return wrapper
    return decorator


# Example usage functions

def add_security_metadata(threat_detected: bool, policy_decision: str, risk_score: float):
    """Add security metadata to current X-Ray segment"""
    try:
        segment = xray_recorder.current_segment()
        if segment:
            segment.put_annotation('threat_detected', threat_detected)
            segment.put_annotation('policy_decision', policy_decision)
            segment.put_metadata('risk_score', risk_score, 'security')
    except Exception as e:
        print(f"Error adding security metadata: {e}")


def add_ml_metadata(model_version: str, prediction: str, confidence: float):
    """Add ML metadata to current X-Ray segment"""
    try:
        segment = xray_recorder.current_segment()
        if segment:
            segment.put_annotation('model_version', model_version)
            segment.put_annotation('prediction', prediction)
            segment.put_metadata('confidence', confidence, 'ml')
    except Exception as e:
        print(f"Error adding ML metadata: {e}")


# Export decorators and functions
__all__ = [
    'AthenAIXRayMiddleware',
    'trace_subsegment',
    'trace_ml_inference',
    'trace_database_operation',
    'trace_cache_operation',
    'trace_evidence_store',
    'add_security_metadata',
    'add_ml_metadata',
    'xray_recorder'
]
