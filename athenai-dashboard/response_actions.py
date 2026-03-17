"""
AthenAI - Response Actions

Sistema de acciones de respuesta que ejecuta las decisiones del Policy Engine.
Implementa: ALLOW, ALERT, BLOCK, RATE_LIMIT

Autor: AthenAI Team
Fecha: 2026-02-11
"""

import logging
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from flask import Response, jsonify
import json

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ResponseActions:
    """
    Ejecuta acciones de respuesta basadas en decisiones del Policy Engine.
    """
    
    def __init__(self, alert_system=None, ip_blocker=None):
        """
        Inicializa el sistema de respuesta.
        
        Args:
            alert_system: Sistema de alertas (opcional)
            ip_blocker: Sistema de bloqueo de IPs (opcional)
        """
        # Importar dependencias si no se proporcionan
        if alert_system is None:
            try:
                from alert_system import alert_system as default_alert_system
                self.alert_system = default_alert_system
                logger.info("✅ Alert System integrado")
            except Exception as e:
                logger.warning(f"⚠️  Alert System no disponible: {e}")
                self.alert_system = None
        else:
            self.alert_system = alert_system
        
        if ip_blocker is None:
            try:
                from ip_blocker import ip_blocker as default_ip_blocker
                self.ip_blocker = default_ip_blocker
                logger.info("✅ IP Blocker integrado")
            except Exception as e:
                logger.warning(f"⚠️  IP Blocker no disponible: {e}")
                self.ip_blocker = None
        else:
            self.ip_blocker = ip_blocker
        self.stats = {
            'allowed': 0,
            'alerted': 0,
            'blocked': 0,
            'rate_limited': 0
        }
        
        logger.info("✅ Response Actions inicializado")
    
    def execute(self, action: str, metadata: Dict, request_data: Dict) -> Tuple[Response, int]:
        """
        Ejecuta la acción determinada por el Policy Engine.
        
        Args:
            action: Acción a ejecutar (ALLOW, ALERT, BLOCK, RATE_LIMIT)
            metadata: Metadata de la decisión del Policy Engine
            request_data: Datos de la petición original
        
        Returns:
            Tupla con (Response, status_code)
        """
        action = action.upper()
        
        if action == "ALLOW":
            return self.allow(metadata, request_data)
        elif action == "ALERT":
            return self.alert(metadata, request_data)
        elif action == "BLOCK":
            return self.block(metadata, request_data)
        elif action == "RATE_LIMIT":
            return self.rate_limit(metadata, request_data)
        else:
            logger.error(f"❌ Acción desconocida: {action}")
            return self.allow(metadata, request_data)
    
    def allow(self, metadata: Dict, request_data: Dict) -> Tuple[Response, int]:
        """
        Permite la petición sin restricciones.
        
        Args:
            metadata: Metadata de la decisión
            request_data: Datos de la petición
        
        Returns:
            Tupla con (Response, 200)
        """
        self.stats['allowed'] += 1
        
        source_ip = request_data.get('source_ip', 'unknown')
        risk_score = request_data.get('risk_score', 0)
        
        logger.info(
            f"✅ ALLOW | IP: {source_ip} | "
            f"Risk: {risk_score:.2f} | "
            f"Policy: {metadata.get('policy_name')}"
        )
        
        response_data = {
            'status': 'allowed',
            'message': 'Request processed successfully',
            'risk_score': risk_score,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(response_data), 200
    
    def alert(self, metadata: Dict, request_data: Dict) -> Tuple[Response, int]:
        """
        Genera alerta pero permite la petición.
        
        Args:
            metadata: Metadata de la decisión
            request_data: Datos de la petición
        
        Returns:
            Tupla con (Response, 200) con header de warning
        """
        self.stats['alerted'] += 1
        
        source_ip = request_data.get('source_ip', 'unknown')
        risk_score = request_data.get('risk_score', 0)
        attack_type = request_data.get('attack_type', 'Unknown')
        
        logger.warning(
            f"⚠️ ALERT | IP: {source_ip} | "
            f"Risk: {risk_score:.2f} | "
            f"Attack: {attack_type} | "
            f"Policy: {metadata.get('policy_name')}"
        )
        
        # Generar alerta si el sistema está disponible
        if self.alert_system and metadata.get('notify', False):
            try:
                alert_data = {
                    'type': 'suspicious_activity',
                    'severity': metadata.get('severity', 'medium'),
                    'source_ip': source_ip,
                    'risk_score': risk_score,
                    'attack_type': attack_type,
                    'timestamp': datetime.now().isoformat(),
                    'policy': metadata.get('policy_name')
                }
                self.alert_system.send_alert(alert_data)
            except Exception as e:
                logger.error(f"❌ Error enviando alerta: {e}")
        
        response_data = {
            'status': 'allowed_with_warning',
            'message': 'Request processed with security warning',
            'risk_score': risk_score,
            'warning': 'Suspicious activity detected',
            'timestamp': datetime.now().isoformat()
        }
        
        # Crear respuesta con header de warning
        response = jsonify(response_data)
        response.headers['X-AthenAI-Warning'] = 'Suspicious activity detected'
        response.headers['X-AthenAI-Risk-Score'] = str(risk_score)
        
        return response, 200
    
    def block(self, metadata: Dict, request_data: Dict) -> Tuple[Response, int]:
        """
        Bloquea la petición.
        
        Args:
            metadata: Metadata de la decisión
            request_data: Datos de la petición
        
        Returns:
            Tupla con (Response, 403)
        """
        self.stats['blocked'] += 1
        
        source_ip = request_data.get('source_ip', 'unknown')
        risk_score = request_data.get('risk_score', 0)
        attack_type = request_data.get('attack_type', 'Unknown')
        block_duration = metadata.get('block_duration', 3600)  # Default: 1 hora
        
        logger.error(
            f"🚫 BLOCK | IP: {source_ip} | "
            f"Risk: {risk_score:.2f} | "
            f"Attack: {attack_type} | "
            f"Duration: {block_duration}s | "
            f"Policy: {metadata.get('policy_name')}"
        )
        
        # Bloquear IP si el sistema está disponible
        if self.ip_blocker and source_ip != 'unknown':
            try:
                self.ip_blocker.block_ip(
                    ip=source_ip,
                    duration=block_duration,
                    reason=f"{attack_type} - Risk: {risk_score:.2f}"
                )
            except Exception as e:
                logger.error(f"❌ Error bloqueando IP: {e}")
        
        # Generar alerta crítica
        if self.alert_system and metadata.get('notify', False):
            try:
                alert_data = {
                    'type': 'threat_blocked',
                    'severity': metadata.get('severity', 'high'),
                    'source_ip': source_ip,
                    'risk_score': risk_score,
                    'attack_type': attack_type,
                    'block_duration': block_duration,
                    'timestamp': datetime.now().isoformat(),
                    'policy': metadata.get('policy_name'),
                    'escalate': metadata.get('escalate', False)
                }
                self.alert_system.send_alert(alert_data)
            except Exception as e:
                logger.error(f"❌ Error enviando alerta: {e}")
        
        # Calcular tiempo de desbloqueo
        if block_duration > 0:
            unblock_time = datetime.now() + timedelta(seconds=block_duration)
            unblock_msg = f"Unblocked at {unblock_time.isoformat()}"
        else:
            unblock_msg = "Permanent block"
        
        response_data = {
            'status': 'blocked',
            'message': 'Access denied - Security threat detected',
            'reason': attack_type,
            'risk_score': risk_score,
            'block_info': unblock_msg,
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(response_data), 403
    
    def rate_limit(self, metadata: Dict, request_data: Dict) -> Tuple[Response, int]:
        """
        Aplica rate limiting a la petición.
        
        Args:
            metadata: Metadata de la decisión
            request_data: Datos de la petición
        
        Returns:
            Tupla con (Response, 429)
        """
        self.stats['rate_limited'] += 1
        
        source_ip = request_data.get('source_ip', 'unknown')
        risk_score = request_data.get('risk_score', 0)
        
        logger.warning(
            f"⏱️ RATE_LIMIT | IP: {source_ip} | "
            f"Risk: {risk_score:.2f} | "
            f"Policy: {metadata.get('policy_name')}"
        )
        
        # Calcular tiempo de retry
        retry_after = metadata.get('retry_after', 60)  # Default: 60 segundos
        
        response_data = {
            'status': 'rate_limited',
            'message': 'Too many requests - Please try again later',
            'retry_after': retry_after,
            'timestamp': datetime.now().isoformat()
        }
        
        response = jsonify(response_data)
        response.headers['Retry-After'] = str(retry_after)
        response.headers['X-RateLimit-Limit'] = str(metadata.get('rate_limit', 100))
        response.headers['X-RateLimit-Remaining'] = '0'
        
        return response, 429
    
    def get_stats(self) -> Dict:
        """
        Retorna estadísticas de acciones ejecutadas.
        
        Returns:
            Diccionario con estadísticas
        """
        total = sum(self.stats.values())
        
        return {
            'total_actions': total,
            'allowed': self.stats['allowed'],
            'alerted': self.stats['alerted'],
            'blocked': self.stats['blocked'],
            'rate_limited': self.stats['rate_limited'],
            'percentages': {
                'allowed': (self.stats['allowed'] / total * 100) if total > 0 else 0,
                'alerted': (self.stats['alerted'] / total * 100) if total > 0 else 0,
                'blocked': (self.stats['blocked'] / total * 100) if total > 0 else 0,
                'rate_limited': (self.stats['rate_limited'] / total * 100) if total > 0 else 0
            }
        }
    
    def reset_stats(self):
        """Resetea las estadísticas"""
        self.stats = {
            'allowed': 0,
            'alerted': 0,
            'blocked': 0,
            'rate_limited': 0
        }
        logger.info("📊 Estadísticas reseteadas")


# Instancia global
response_actions = ResponseActions()


if __name__ == "__main__":
    # Demo
    print("=" * 80)
    print("ATHENAI RESPONSE ACTIONS - DEMO")
    print("=" * 80)
    
    # Simular diferentes acciones
    test_cases = [
        {
            'action': 'ALLOW',
            'metadata': {'policy_name': 'low_risk_allow', 'severity': 'low'},
            'request_data': {'source_ip': '192.168.1.100', 'risk_score': 15.5}
        },
        {
            'action': 'ALERT',
            'metadata': {'policy_name': 'medium_risk_alert', 'severity': 'medium', 'notify': True},
            'request_data': {'source_ip': '10.0.0.50', 'risk_score': 55.0, 'attack_type': 'XSS'}
        },
        {
            'action': 'BLOCK',
            'metadata': {
                'policy_name': 'high_risk_block',
                'severity': 'high',
                'notify': True,
                'block_duration': 3600
            },
            'request_data': {'source_ip': '203.0.113.45', 'risk_score': 85.0, 'attack_type': 'SQL Injection'}
        },
        {
            'action': 'RATE_LIMIT',
            'metadata': {'policy_name': 'rate_limit_policy', 'retry_after': 60},
            'request_data': {'source_ip': '198.51.100.10', 'risk_score': 40.0}
        }
    ]
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n📊 Test Case {i}: {test['action']}")
        response, status_code = response_actions.execute(
            test['action'],
            test['metadata'],
            test['request_data']
        )
        print(f"   Status Code: {status_code}")
        print(f"   Response: {response.get_json()}")
    
    # Mostrar estadísticas
    print("\n📈 Estadísticas:")
    stats = response_actions.get_stats()
    print(json.dumps(stats, indent=2))
    
    print("\n" + "=" * 80)
