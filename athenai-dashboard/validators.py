"""
AthenAI - Validadores de Entrada (Input Validation Layer)

Define schemas de marshmallow para validar el cuerpo JSON de cada
endpoint, y el decorador @validate_json que los aplica de forma
uniforme con una sola línea.

Uso:
    from validators import validate_json, BlockIPSchema

    @app.route('/api/blocked-ips', methods=['POST'])
    @validate_json(BlockIPSchema)
    def block_ip():
        data = request.validated_data   # dict limpio y validado
        ...

Respuesta de error automática (HTTP 422):
    {
        "error": "Validation failed",
        "messages": {
            "ip": ["Not a valid IPv4 or IPv6 address."],
            "duration": ["Must be between 1 and 604800."]
        }
    }
"""

import re
import ipaddress
from functools import wraps

from flask import request, jsonify
from marshmallow import (
    Schema, fields, validates, validates_schema,
    ValidationError, validate, pre_load, EXCLUDE
)


# ============================================================
# Decorador principal
# ============================================================

def validate_json(schema_class):
    """
    Decorador que valida el cuerpo JSON de un request con un Schema.

    - Si el JSON es inválido o falta, devuelve HTTP 400.
    - Si el schema falla, devuelve HTTP 422 con los mensajes de error.
    - Si pasa, adjunta el dict validado en request.validated_data.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Parsear JSON
            json_data = request.get_json(silent=True)
            if json_data is None:
                return jsonify({
                    'error': 'Invalid or missing JSON body',
                    'hint': 'Ensure Content-Type is application/json'
                }), 400

            # Validar con el schema
            schema = schema_class()
            try:
                validated = schema.load(json_data)
            except ValidationError as err:
                return jsonify({
                    'error': 'Validation failed',
                    'messages': err.messages
                }), 422

            # Adjuntar datos validados al request
            request.validated_data = validated
            return f(*args, **kwargs)

        return wrapper
    return decorator


# ============================================================
# Validadores personalizados reutilizables
# ============================================================

def _is_valid_ip(value: str) -> bool:
    """Retorna True si el string es una IPv4 o IPv6 válida."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class IPAddressField(fields.String):
    """Campo marshmallow que valida formato de IP (IPv4 o IPv6)."""

    def _validate(self, value):
        super()._validate(value)
        if not _is_valid_ip(value):
            raise ValidationError(
                f"'{value}' no es una dirección IP válida (IPv4 o IPv6)."
            )


# ============================================================
# Schemas de autenticación
# ============================================================

class LoginSchema(Schema):
    """Validación para POST /api/auth/login"""

    class Meta:
        unknown = EXCLUDE  # Ignorar campos no declarados

    username = fields.String(
        required=True,
        validate=[
            validate.Length(min=2, max=50,
                            error="El username debe tener entre 2 y 50 caracteres."),
            validate.Regexp(
                r'^[a-zA-Z0-9_.-]+$',
                error="El username solo puede contener letras, números, _, . y -"
            )
        ]
    )
    password = fields.String(
        required=True,
        validate=validate.Length(
            min=6, max=128,
            error="La contraseña debe tener entre 6 y 128 caracteres."
        )
    )


class RegisterSchema(Schema):
    """Validación para POST /api/auth/register"""

    class Meta:
        unknown = EXCLUDE

    username = fields.String(
        required=True,
        validate=[
            validate.Length(min=2, max=50,
                            error="El username debe tener entre 2 y 50 caracteres."),
            validate.Regexp(
                r'^[a-zA-Z0-9_.-]+$',
                error="El username solo puede contener letras, números, _, . y -"
            )
        ]
    )
    password = fields.String(
        required=True,
        validate=validate.Length(
            min=6, max=128,
            error="La contraseña debe tener entre 6 y 128 caracteres."
        )
    )
    email = fields.Email(
        required=True,
        error_messages={'validator_failed': 'Dirección de email inválida.'}
    )
    role = fields.String(
        load_default='viewer',
        validate=validate.OneOf(
            ['admin', 'analyst', 'viewer'],
            error="El rol debe ser uno de: admin, analyst, viewer."
        )
    )


class RefreshTokenSchema(Schema):
    """Validación para POST /api/auth/refresh"""

    class Meta:
        unknown = EXCLUDE

    refresh_token = fields.String(
        required=True,
        validate=validate.Length(
            min=10,
            error="refresh_token inválido."
        )
    )


# ============================================================
# Schemas de gestión de IPs
# ============================================================

class BlockIPSchema(Schema):
    """Validación para POST /api/blocked-ips"""

    class Meta:
        unknown = EXCLUDE

    ip = IPAddressField(
        required=True
    )
    reason = fields.String(
        load_default='Manual block',
        validate=validate.Length(
            max=200,
            error="La razón no puede superar los 200 caracteres."
        )
    )
    duration = fields.Integer(
        load_default=3600,
        validate=validate.Range(
            min=1, max=604800,  # 1 seg – 7 días
            error="La duración debe estar entre 1 y 604800 segundos (7 días)."
        )
    )


class WhitelistSchema(Schema):
    """Validación para POST /api/whitelist"""

    class Meta:
        unknown = EXCLUDE

    ip = IPAddressField(
        required=True
    )
    reason = fields.String(
        load_default='Trusted source',
        validate=validate.Length(
            max=200,
            error="La razón no puede superar los 200 caracteres."
        )
    )


# ============================================================
# Schemas de A/B Testing y Policy Engine
# ============================================================

class TrafficSplitSchema(Schema):
    """Validación para POST /api/ab-testing/traffic-split"""

    class Meta:
        unknown = EXCLUDE

    model_a_percentage = fields.Float(
        required=True,
        validate=validate.Range(
            min=0.0, max=100.0,
            error="El porcentaje debe estar entre 0 y 100."
        )
    )


class PolicyThresholdSchema(Schema):
    """Validación para actualizar thresholds del Policy Engine en runtime."""

    class Meta:
        unknown = EXCLUDE

    low = fields.Float(
        load_default=None,
        allow_none=True,
        validate=validate.Range(min=0.0, max=100.0,
                                error="Threshold 'low' debe estar entre 0 y 100.")
    )
    medium = fields.Float(
        load_default=None,
        allow_none=True,
        validate=validate.Range(min=0.0, max=100.0,
                                error="Threshold 'medium' debe estar entre 0 y 100.")
    )
    high = fields.Float(
        load_default=None,
        allow_none=True,
        validate=validate.Range(min=0.0, max=100.0,
                                error="Threshold 'high' debe estar entre 0 y 100.")
    )
    critical = fields.Float(
        load_default=None,
        allow_none=True,
        validate=validate.Range(min=0.0, max=100.0,
                                error="Threshold 'critical' debe estar entre 0 y 100.")
    )

    @validates_schema
    def validate_threshold_order(self, data, **kwargs):
        """Verifica que los thresholds estén en orden ascendente."""
        values = {k: v for k, v in data.items() if v is not None}
        order = [
            ('low', 'medium'),
            ('medium', 'high'),
            ('high', 'critical'),
        ]
        for lower_key, upper_key in order:
            lower = values.get(lower_key)
            upper = values.get(upper_key)
            if lower is not None and upper is not None and lower >= upper:
                raise ValidationError(
                    f"'{lower_key}' ({lower}) debe ser menor que '{upper_key}' ({upper})."
                )
