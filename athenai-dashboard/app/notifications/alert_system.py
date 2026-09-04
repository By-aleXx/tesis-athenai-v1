"""
AthenAI - Alert System

Sistema de alertas y notificaciones usando AWS SNS/SES (LocalStack).
Soporta múltiples canales: Email, SMS, Slack.

Autor: AthenAI Team
Fecha: 2026-02-11
"""

import boto3
import logging
import json
import requests
from typing import Dict, List, Optional
from datetime import datetime
from enum import Enum
import os
from dotenv import load_dotenv

load_dotenv()

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Niveles de severidad de alertas"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertChannel(Enum):
    """Canales de notificación"""
    EMAIL = "email"
    SMS = "sms"
    SLACK = "slack"
    ALL = "all"


class AlertSystem:
    """
    Sistema de alertas multi-canal.
    
    Características:
    - Email vía AWS SES (LocalStack)
    - SMS vía AWS SNS (LocalStack)
    - Webhooks de Slack
    - Filtrado por severidad
    - Historial de alertas
    """
    
    def __init__(self, use_localstack=True):
        """
        Inicializa el Alert System.
        
        Args:
            use_localstack: Si True, usa LocalStack en lugar de AWS real
        """
        self.use_localstack = use_localstack
        
        # Configuración de AWS
        if use_localstack:
            endpoint_url = os.environ['AWS_ENDPOINT_URL']
            aws_config = {
                'endpoint_url': endpoint_url,
                'aws_access_key_id': os.environ['AWS_ACCESS_KEY_ID'],
                'aws_secret_access_key': os.environ['AWS_SECRET_ACCESS_KEY'],
                'region_name': os.getenv('AWS_REGION', 'us-east-1')
            }
        else:
            aws_config = {
                'region_name': os.getenv('AWS_REGION', 'us-east-1')
            }
        
        # Clientes AWS
        try:
            self.sns_client = boto3.client('sns', **aws_config)
            self.ses_client = boto3.client('ses', **aws_config)
            logger.info(f"✅ Alert System inicializado ({'LocalStack' if use_localstack else 'AWS'})")
        except Exception as e:
            logger.error(f"❌ Error inicializando clientes AWS: {e}")
            self.sns_client = None
            self.ses_client = None
        
        # Configuración
        self.config = {
            'email_from': 'alerts@athenai.security',
            'email_to': ['admin@athenai.security'],
            'sms_numbers': [],  # Lista de números de teléfono
            'slack_webhook_url': os.getenv('SLACK_WEBHOOK_URL'),
            'sns_topic_arn': None  # Se crea dinámicamente
        }
        
        # Estadísticas
        self.stats = {
            'total_alerts': 0,
            'by_severity': {
                'low': 0,
                'medium': 0,
                'high': 0,
                'critical': 0
            },
            'by_channel': {
                'email': 0,
                'sms': 0,
                'slack': 0
            },
            'failed_alerts': 0
        }
        
        # Inicializar SNS topic si es necesario
        self._init_sns_topic()
    
    def _init_sns_topic(self):
        """Crea el SNS topic para alertas si no existe"""
        if not self.sns_client:
            return
        
        try:
            # Crear topic
            response = self.sns_client.create_topic(Name='athenai-security-alerts')
            self.config['sns_topic_arn'] = response['TopicArn']
            logger.info(f"✅ SNS Topic creado: {response['TopicArn']}")
        except Exception as e:
            logger.warning(f"⚠️  No se pudo crear SNS topic: {e}")
    
    def send_alert(self, alert_data: Dict, channels: List[AlertChannel] = None) -> bool:
        """
        Envía una alerta por los canales especificados.
        
        Args:
            alert_data: Datos de la alerta
            channels: Lista de canales (None = todos)
        
        Returns:
            True si al menos un canal fue exitoso
        """
        # Validar datos
        if not alert_data:
            logger.error("❌ No se proporcionaron datos de alerta")
            return False
        
        # Determinar severidad
        severity = alert_data.get('severity', 'medium')
        alert_type = alert_data.get('type', 'unknown')
        
        # Formatear mensaje
        message = self._format_alert_message(alert_data)
        subject = f"[AthenAI] {severity.upper()} - {alert_type}"
        
        # Determinar canales
        if channels is None or AlertChannel.ALL in channels:
            channels = [AlertChannel.EMAIL, AlertChannel.SMS, AlertChannel.SLACK]
        
        # Enviar por cada canal
        success = False
        
        if AlertChannel.EMAIL in channels:
            if self._send_email(subject, message):
                success = True
                self.stats['by_channel']['email'] += 1
        
        if AlertChannel.SMS in channels:
            if self._send_sms(message):
                success = True
                self.stats['by_channel']['sms'] += 1
        
        if AlertChannel.SLACK in channels:
            if self._send_slack(alert_data):
                success = True
                self.stats['by_channel']['slack'] += 1
        
        # Actualizar estadísticas
        if success:
            self.stats['total_alerts'] += 1
            self.stats['by_severity'][severity] += 1
            
            logger.info(
                f"🔔 Alerta enviada | "
                f"Tipo: {alert_type} | "
                f"Severidad: {severity} | "
                f"Canales: {[c.value for c in channels]}"
            )
        else:
            self.stats['failed_alerts'] += 1
            logger.error(f"❌ Error enviando alerta: {alert_type}")
        
        return success
    
    def _format_alert_message(self, alert_data: Dict) -> str:
        """
        Formatea el mensaje de alerta.
        
        Args:
            alert_data: Datos de la alerta
        
        Returns:
            Mensaje formateado
        """
        lines = [
            "=" * 60,
            "ATHENAI SECURITY ALERT",
            "=" * 60,
            "",
            f"Type: {alert_data.get('type', 'Unknown')}",
            f"Severity: {alert_data.get('severity', 'medium').upper()}",
            f"Timestamp: {alert_data.get('timestamp', datetime.now().isoformat())}",
            ""
        ]
        
        # Agregar detalles específicos
        if 'source_ip' in alert_data:
            lines.append(f"Source IP: {alert_data['source_ip']}")
        
        if 'risk_score' in alert_data:
            lines.append(f"Risk Score: {alert_data['risk_score']:.2f}")
        
        if 'attack_type' in alert_data:
            lines.append(f"Attack Type: {alert_data['attack_type']}")
        
        if 'policy' in alert_data:
            lines.append(f"Policy: {alert_data['policy']}")
        
        if 'block_duration' in alert_data:
            duration = alert_data['block_duration']
            if duration > 0:
                lines.append(f"Block Duration: {duration}s")
            else:
                lines.append("Block Duration: PERMANENT")
        
        # Mensaje adicional
        if 'message' in alert_data:
            lines.extend(["", "Details:", alert_data['message']])
        
        lines.extend(["", "=" * 60])
        
        return "\n".join(lines)
    
    def _send_email(self, subject: str, message: str) -> bool:
        """
        Envía alerta por email usando SES.
        
        Args:
            subject: Asunto del email
            message: Cuerpo del mensaje
        
        Returns:
            True si se envió exitosamente
        """
        if not self.ses_client:
            logger.warning("⚠️  SES no disponible")
            return False
        
        try:
            response = self.ses_client.send_email(
                Source=self.config['email_from'],
                Destination={
                    'ToAddresses': self.config['email_to']
                },
                Message={
                    'Subject': {'Data': subject},
                    'Body': {'Text': {'Data': message}}
                }
            )
            
            logger.info(f"📧 Email enviado | MessageId: {response.get('MessageId')}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error enviando email: {e}")
            return False
    
    def _send_sms(self, message: str) -> bool:
        """
        Envía alerta por SMS usando SNS.
        
        Args:
            message: Mensaje a enviar
        
        Returns:
            True si se envió exitosamente
        """
        if not self.sns_client:
            logger.warning("⚠️  SNS no disponible")
            return False
        
        if not self.config['sms_numbers']:
            logger.debug("ℹ️  No hay números configurados para SMS")
            return False
        
        try:
            # Truncar mensaje para SMS (160 caracteres)
            sms_message = message[:160] if len(message) > 160 else message
            
            for phone_number in self.config['sms_numbers']:
                response = self.sns_client.publish(
                    PhoneNumber=phone_number,
                    Message=sms_message
                )
                
                logger.info(f"📱 SMS enviado a {phone_number} | MessageId: {response.get('MessageId')}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error enviando SMS: {e}")
            return False
    
    def _send_slack(self, alert_data: Dict) -> bool:
        """
        Envía alerta a Slack usando webhook.
        
        Args:
            alert_data: Datos de la alerta
        
        Returns:
            True si se envió exitosamente
        """
        webhook_url = self.config.get('slack_webhook_url')
        
        if not webhook_url:
            logger.debug("ℹ️  Slack webhook no configurado")
            return False
        
        try:
            # Formatear mensaje para Slack
            severity = alert_data.get('severity', 'medium')
            alert_type = alert_data.get('type', 'Unknown')
            
            # Emoji según severidad
            emoji_map = {
                'low': ':information_source:',
                'medium': ':warning:',
                'high': ':rotating_light:',
                'critical': ':fire:'
            }
            emoji = emoji_map.get(severity, ':bell:')
            
            # Color según severidad
            color_map = {
                'low': '#36a64f',      # Verde
                'medium': '#ff9900',   # Naranja
                'high': '#ff0000',     # Rojo
                'critical': '#8b0000'  # Rojo oscuro
            }
            color = color_map.get(severity, '#808080')
            
            # Construir payload
            payload = {
                'text': f"{emoji} *AthenAI Security Alert*",
                'attachments': [{
                    'color': color,
                    'fields': [
                        {
                            'title': 'Type',
                            'value': alert_type,
                            'short': True
                        },
                        {
                            'title': 'Severity',
                            'value': severity.upper(),
                            'short': True
                        }
                    ],
                    'footer': 'AthenAI Security',
                    'ts': int(datetime.now().timestamp())
                }]
            }
            
            # Agregar campos adicionales
            if 'source_ip' in alert_data:
                payload['attachments'][0]['fields'].append({
                    'title': 'Source IP',
                    'value': alert_data['source_ip'],
                    'short': True
                })
            
            if 'risk_score' in alert_data:
                payload['attachments'][0]['fields'].append({
                    'title': 'Risk Score',
                    'value': f"{alert_data['risk_score']:.2f}",
                    'short': True
                })
            
            # Enviar webhook
            response = requests.post(webhook_url, json=payload, timeout=5)
            
            if response.status_code == 200:
                logger.info(f"💬 Alerta enviada a Slack")
                return True
            else:
                logger.error(f"❌ Error en Slack webhook: {response.status_code}")
                return False
            
        except Exception as e:
            logger.error(f"❌ Error enviando a Slack: {e}")
            return False
    
    def configure(self, **kwargs):
        """
        Configura el sistema de alertas.
        
        Args:
            **kwargs: Parámetros de configuración
        """
        for key, value in kwargs.items():
            if key in self.config:
                self.config[key] = value
                logger.info(f"✅ Configuración actualizada: {key}")
    
    def get_stats(self) -> Dict:
        """Retorna estadísticas del sistema de alertas"""
        return self.stats
    
    def test_alert(self, channel: AlertChannel = AlertChannel.EMAIL) -> bool:
        """
        Envía una alerta de prueba.
        
        Args:
            channel: Canal a probar
        
        Returns:
            True si se envió exitosamente
        """
        test_alert = {
            'type': 'test_alert',
            'severity': 'low',
            'message': 'This is a test alert from AthenAI',
            'timestamp': datetime.now().isoformat()
        }
        
        return self.send_alert(test_alert, channels=[channel])


# Instancia global
alert_system = AlertSystem()


if __name__ == "__main__":
    # Demo
    print("=" * 80)
    print("ATHENAI ALERT SYSTEM - DEMO")
    print("=" * 80)
    
    # Configurar emails de prueba
    alert_system.configure(
        email_to=['security@example.com', 'admin@example.com']
    )
    
    # Alertas de prueba
    test_alerts = [
        {
            'type': 'suspicious_activity',
            'severity': 'medium',
            'source_ip': '10.0.0.50',
            'risk_score': 55.0,
            'attack_type': 'XSS',
            'timestamp': datetime.now().isoformat()
        },
        {
            'type': 'threat_blocked',
            'severity': 'high',
            'source_ip': '203.0.113.45',
            'risk_score': 85.0,
            'attack_type': 'SQL Injection',
            'block_duration': 3600,
            'timestamp': datetime.now().isoformat()
        },
        {
            'type': 'critical_threat',
            'severity': 'critical',
            'source_ip': '198.51.100.10',
            'risk_score': 98.5,
            'attack_type': 'Remote Code Execution',
            'block_duration': -1,
            'escalate': True,
            'timestamp': datetime.now().isoformat()
        }
    ]
    
    print("\n🔔 Enviando alertas de prueba:\n")
    
    for i, alert in enumerate(test_alerts, 1):
        print(f"Alerta {i}: {alert['type']} ({alert['severity']})")
        success = alert_system.send_alert(alert, channels=[AlertChannel.EMAIL])
        print(f"   {'✅ Enviada' if success else '❌ Error'}\n")
    
    # Estadísticas
    print("📊 Estadísticas:")
    stats = alert_system.get_stats()
    print(f"   Total alertas: {stats['total_alerts']}")
    print(f"   Por severidad:")
    for severity, count in stats['by_severity'].items():
        print(f"      {severity}: {count}")
    print(f"   Por canal:")
    for channel, count in stats['by_channel'].items():
        print(f"      {channel}: {count}")
    print(f"   Fallidas: {stats['failed_alerts']}")
    
    print("\n" + "=" * 80)
