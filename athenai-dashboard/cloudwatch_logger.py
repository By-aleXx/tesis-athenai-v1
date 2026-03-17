"""
CloudWatch Logger para AthenAI

Envía logs estructurados a CloudWatch Logs (LocalStack)

Log Groups:
- /athenai/api - Logs de API
- /athenai/ml - Logs de ML
- /athenai/security - Logs de seguridad
- /athenai/errors - Errores
"""

import os
import boto3
import json
import logging
from datetime import datetime
from typing import Dict, Any, Optional
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class CloudWatchLogger:
    def __init__(self, endpoint_url=None):
        """
        Inicializa el CloudWatch Logger.
        
        Args:
            endpoint_url: URL de LocalStack (default: leído de AWS_ENDPOINT_URL en .env)
        """
        self.endpoint_url = endpoint_url or os.environ['AWS_ENDPOINT_URL']
        
        self.client = boto3.client(
            'logs',
            endpoint_url=self.endpoint_url,
            region_name=os.getenv('AWS_REGION', 'us-east-1'),
            aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],
            aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY']
        )
        
        # Log groups
        self.log_groups = {
            'api': '/athenai/api',
            'ml': '/athenai/ml',
            'security': '/athenai/security',
            'errors': '/athenai/errors'
        }
        
        # Crear log groups si no existen
        self._create_log_groups()
        
        # Sequence tokens por log stream
        self.sequence_tokens = {}
        
        logger.info(f"✅ CloudWatch Logger inicializado (endpoint: {self.endpoint_url})")
    
    def _create_log_groups(self):
        """Crea log groups si no existen"""
        for group_name, log_group in self.log_groups.items():
            try:
                self.client.create_log_group(logGroupName=log_group)
                logger.info(f"📦 Log group creado: {log_group}")
            except self.client.exceptions.ResourceAlreadyExistsException:
                logger.debug(f"ℹ️  Log group ya existe: {log_group}")
            except Exception as e:
                logger.error(f"Error creando log group {log_group}: {e}")
    
    def _get_or_create_stream(self, log_group: str, stream_name: str) -> Optional[str]:
        """
        Obtiene o crea un log stream.
        
        Returns:
            Sequence token (None si es nuevo stream)
        """
        stream_key = f"{log_group}/{stream_name}"
        
        # Si ya tenemos el sequence token, retornarlo
        if stream_key in self.sequence_tokens:
            return self.sequence_tokens[stream_key]
        
        # Intentar crear el stream
        try:
            self.client.create_log_stream(
                logGroupName=log_group,
                logStreamName=stream_name
            )
            logger.debug(f"📝 Log stream creado: {stream_name}")
            return None
        except self.client.exceptions.ResourceAlreadyExistsException:
            # Stream ya existe, obtener sequence token
            try:
                response = self.client.describe_log_streams(
                    logGroupName=log_group,
                    logStreamNamePrefix=stream_name,
                    limit=1
                )
                
                if response['logStreams']:
                    token = response['logStreams'][0].get('uploadSequenceToken')
                    self.sequence_tokens[stream_key] = token
                    return token
                
                return None
            except Exception as e:
                logger.error(f"Error obteniendo sequence token: {e}")
                return None
        except Exception as e:
            logger.error(f"Error creando log stream: {e}")
            return None
    
    def log(
        self,
        group: str,
        level: str,
        message: str,
        metadata: Optional[Dict[str, Any]] = None,
        stream_name: Optional[str] = None
    ):
        """
        Envía un log a CloudWatch.
        
        Args:
            group: Tipo de log ('api', 'ml', 'security', 'errors')
            level: Nivel (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            message: Mensaje del log
            metadata: Metadata adicional (dict)
            stream_name: Nombre del stream (default: fecha actual)
        """
        if group not in self.log_groups:
            logger.error(f"Log group inválido: {group}")
            return
        
        log_group = self.log_groups[group]
        
        # Stream name por defecto: fecha actual
        if not stream_name:
            stream_name = datetime.utcnow().strftime('%Y-%m-%d')
        
        # Crear log event
        log_event = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': level,
            'message': message
        }
        
        # Agregar metadata
        if metadata:
            log_event.update(metadata)
        
        # Convertir a JSON
        log_message = json.dumps(log_event, default=str)
        
        # Obtener sequence token
        sequence_token = self._get_or_create_stream(log_group, stream_name)
        
        # Enviar log
        try:
            params = {
                'logGroupName': log_group,
                'logStreamName': stream_name,
                'logEvents': [
                    {
                        'timestamp': int(datetime.utcnow().timestamp() * 1000),
                        'message': log_message
                    }
                ]
            }
            
            if sequence_token:
                params['sequenceToken'] = sequence_token
            
            response = self.client.put_log_events(**params)
            
            # Actualizar sequence token
            stream_key = f"{log_group}/{stream_name}"
            self.sequence_tokens[stream_key] = response.get('nextSequenceToken')
        
        except Exception as e:
            logger.error(f"Error enviando log a CloudWatch: {e}")
    
    # Métodos de conveniencia
    
    def log_api(self, level: str, message: str, **metadata):
        """Log de API"""
        self.log('api', level, message, metadata)
    
    def log_ml(self, level: str, message: str, **metadata):
        """Log de ML"""
        self.log('ml', level, message, metadata)
    
    def log_security(self, level: str, message: str, **metadata):
        """Log de seguridad"""
        self.log('security', level, message, metadata)
    
    def log_error(self, message: str, **metadata):
        """Log de error"""
        self.log('errors', 'ERROR', message, metadata)
    
    # Métodos por nivel
    
    def debug(self, group: str, message: str, **metadata):
        """Log DEBUG"""
        self.log(group, 'DEBUG', message, metadata)
    
    def info(self, group: str, message: str, **metadata):
        """Log INFO"""
        self.log(group, 'INFO', message, metadata)
    
    def warning(self, group: str, message: str, **metadata):
        """Log WARNING"""
        self.log(group, 'WARNING', message, metadata)
    
    def error(self, group: str, message: str, **metadata):
        """Log ERROR"""
        self.log(group, 'ERROR', message, metadata)
    
    def critical(self, group: str, message: str, **metadata):
        """Log CRITICAL"""
        self.log(group, 'CRITICAL', message, metadata)


# Instancia global
try:
    cloudwatch_logger = CloudWatchLogger()
except Exception as e:
    logger.error(f"Error inicializando CloudWatch Logger: {e}")
    cloudwatch_logger = None
