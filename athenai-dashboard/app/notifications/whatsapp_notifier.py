"""
AthenAI - WhatsApp Notifier
Envía alertas de seguridad vía WhatsApp usando el microservicio open-wa.
"""
import os
import json
import logging
import urllib.request
import urllib.error
from datetime import datetime

logger = logging.getLogger(__name__)

WHATSAPP_SERVICE_URL = os.getenv('WHATSAPP_SERVICE_URL', 'http://athenai-whatsapp:3001')


def _post(endpoint: str, payload: dict) -> dict:
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        f"{WHATSAPP_SERVICE_URL}{endpoint}",
        data=data,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        raise RuntimeError(f"HTTP {e.code}: {body}")


def _get(endpoint: str) -> dict:
    try:
        with urllib.request.urlopen(f"{WHATSAPP_SERVICE_URL}{endpoint}", timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as e:
        raise RuntimeError(str(e))


def get_status() -> dict:
    """Retorna el estado de conexión del servicio WhatsApp."""
    try:
        return _get('/status')
    except Exception as e:
        return {'status': 'UNAVAILABLE', 'connected': False, 'error': str(e)}


def get_qr() -> dict:
    """Retorna el QR code como imagen base64 para escanear."""
    try:
        return _get('/qr')
    except Exception as e:
        return {'status': 'ERROR', 'error': str(e)}


def send_message(number: str, message: str) -> dict:
    """Envía un mensaje de texto simple."""
    return _post('/send', {'number': number, 'message': message})


def send_security_alert(number: str, threat_type: str, ip: str,
                        reason: str = '', timestamp: str = None) -> dict:
    """Envía una alerta de seguridad formateada."""
    return _post('/send-alert', {
        'number': number,
        'threat_type': threat_type,
        'ip': ip,
        'reason': reason,
        'timestamp': timestamp or datetime.now().isoformat(),
    })


def notify_all(numbers: list, threat_type: str, ip: str,
               reason: str = '', timestamp: str = None) -> list:
    """Envía alerta a múltiples números. Retorna lista de resultados."""
    results = []
    for number in numbers:
        try:
            result = send_security_alert(number, threat_type, ip, reason, timestamp)
            results.append({'number': number, 'success': True, 'result': result})
            logger.info(f"📱 WhatsApp alert enviada a {number}: {threat_type}")
        except Exception as e:
            results.append({'number': number, 'success': False, 'error': str(e)})
            logger.warning(f"⚠️ Error enviando WhatsApp a {number}: {e}")
    return results
