"""
AthenAI - Email Notifier via Resend
Envía alertas de seguridad por correo cuando el WAF detecta ataques.
"""

import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

_RESEND_AVAILABLE = False
try:
    import resend
    _api_key = os.getenv('RESEND_API_KEY', '')
    if _api_key:
        resend.api_key = _api_key
        _RESEND_AVAILABLE = True
    else:
        logger.warning('RESEND_API_KEY no configurada — notificaciones por email desactivadas')
except ImportError:
    logger.warning('Módulo resend no instalado — notificaciones por email desactivadas')


def is_available() -> bool:
    return _RESEND_AVAILABLE


def get_from_address() -> str:
    return os.getenv('RESEND_FROM', 'AthenAI WAF <onboarding@resend.dev>')


def get_alert_emails() -> list[str]:
    raw = os.getenv('RESEND_ALERT_EMAIL', '')
    return [e.strip() for e in raw.split(',') if e.strip()]


def _build_alert_html(threat_type: str, ip: str, reason: str, timestamp: str | None = None) -> str:
    ts = timestamp or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    dashboard_url = os.getenv('DASHBOARD_URL', 'http://localhost:5000')
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Alerta de Seguridad — AthenAI WAF</title>
</head>
<body style="margin:0;padding:0;background:#0f172a;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0f172a;padding:32px 0;">
    <tr><td align="center">
      <table width="580" cellpadding="0" cellspacing="0" style="background:#1e293b;border-radius:12px;overflow:hidden;border:1px solid #334155;">

        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#dc2626,#991b1b);padding:28px 32px;">
          <h1 style="margin:0;color:#fff;font-size:22px;font-weight:700;">🚨 Alerta de Seguridad</h1>
          <p style="margin:6px 0 0;color:#fca5a5;font-size:14px;">AthenAI WAF — Sistema de Detección de Intrusos</p>
        </td></tr>

        <!-- Cuerpo -->
        <tr><td style="padding:32px;">

          <p style="color:#94a3b8;font-size:14px;margin:0 0 24px;">
            El WAF detectó y bloqueó un ataque. Revisa los detalles a continuación.
          </p>

          <!-- Tarjeta de ataque -->
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="background:#0f172a;border-radius:8px;border:1px solid #dc2626;margin-bottom:24px;">
            <tr><td style="padding:20px;">
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:8px 0;border-bottom:1px solid #1e293b;">
                    <span style="color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:.05em;">Tipo de ataque</span><br>
                    <span style="color:#f87171;font-size:16px;font-weight:700;">{threat_type}</span>
                  </td>
                </tr>
                <tr>
                  <td style="padding:8px 0;border-bottom:1px solid #1e293b;">
                    <span style="color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:.05em;">IP de origen</span><br>
                    <span style="color:#e2e8f0;font-size:15px;font-family:monospace;">{ip or 'Desconocida'}</span>
                  </td>
                </tr>
                <tr>
                  <td style="padding:8px 0;border-bottom:1px solid #1e293b;">
                    <span style="color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:.05em;">Detalle</span><br>
                    <span style="color:#cbd5e1;font-size:14px;">{reason or 'Ataque detectado y bloqueado automáticamente'}</span>
                  </td>
                </tr>
                <tr>
                  <td style="padding:8px 0;">
                    <span style="color:#64748b;font-size:12px;text-transform:uppercase;letter-spacing:.05em;">Hora</span><br>
                    <span style="color:#94a3b8;font-size:14px;">{ts}</span>
                  </td>
                </tr>
              </table>
            </td></tr>
          </table>

          <!-- Estado -->
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="background:#14532d;border-radius:8px;border:1px solid #16a34a;margin-bottom:28px;">
            <tr><td style="padding:14px 20px;">
              <span style="color:#86efac;font-size:14px;font-weight:600;">✅ IP bloqueada automáticamente — el sistema está protegido</span>
            </td></tr>
          </table>

          <!-- Botón -->
          <table cellpadding="0" cellspacing="0">
            <tr><td style="border-radius:8px;background:#4f46e5;">
              <a href="{dashboard_url}" target="_blank"
                 style="display:inline-block;padding:12px 28px;color:#fff;font-size:14px;font-weight:600;text-decoration:none;">
                Abrir Dashboard AthenAI →
              </a>
            </td></tr>
          </table>

        </td></tr>

        <!-- Footer -->
        <tr><td style="background:#0f172a;padding:16px 32px;border-top:1px solid #334155;">
          <p style="margin:0;color:#475569;font-size:12px;">
            AthenAI WAF · Sistema de Detección y Prevención de Intrusos<br>
            Este correo fue generado automáticamente. No respondas a este mensaje.
          </p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""


def send_security_alert(
    to: str | list[str],
    threat_type: str,
    ip: str,
    reason: str,
    timestamp: str | None = None,
) -> dict:
    if not _RESEND_AVAILABLE:
        return {'success': False, 'error': 'Resend no disponible'}
    recipients = [to] if isinstance(to, str) else to
    try:
        result = resend.Emails.send({
            'from': get_from_address(),
            'to': recipients,
            'subject': f'🚨 AthenAI WAF — Ataque bloqueado: {threat_type}',
            'html': _build_alert_html(threat_type, ip, reason, timestamp),
        })
        logger.info(f'Email de alerta enviado a {recipients}: {result.get("id")}')
        return {'success': True, 'id': result.get('id'), 'to': recipients}
    except Exception as e:
        logger.error(f'Error enviando email de alerta: {e}')
        return {'success': False, 'error': str(e)}


def send_test_email(to: str) -> dict:
    if not _RESEND_AVAILABLE:
        return {'success': False, 'error': 'Resend no disponible'}
    try:
        result = resend.Emails.send({
            'from': get_from_address(),
            'to': [to],
            'subject': '✅ AthenAI WAF — Prueba de notificaciones',
            'html': _build_alert_html(
                threat_type='SQL_INJECTION (prueba)',
                ip='192.168.1.100',
                reason='Este es un correo de prueba. El sistema de alertas está configurado correctamente.',
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            ),
        })
        return {'success': True, 'id': result.get('id')}
    except Exception as e:
        logger.error(f'Error enviando email de prueba: {e}')
        return {'success': False, 'error': str(e)}


def notify_all_emails(threat_type: str, ip: str, reason: str) -> dict:
    recipients = get_alert_emails()
    if not recipients:
        return {'success': False, 'error': 'No hay destinatarios configurados (RESEND_ALERT_EMAIL vacío)'}
    return send_security_alert(recipients, threat_type, ip, reason)
