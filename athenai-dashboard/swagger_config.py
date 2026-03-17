"""
AthenAI - Configuración de Swagger / OpenAPI

Proporciona la especificación OpenAPI 2.0 completa del sistema.
Accesible en: http://localhost:5000/apidocs/

Autor: AthenAI Team
"""

SWAGGER_CONFIG = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec",
            "route": "/apispec.json",
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/",
}

SWAGGER_TEMPLATE = {
    "swagger": "2.0",
    "info": {
        "title": "AthenAI IDS - API REST",
        "description": (
            "## Sistema Híbrido de Detección de Intrusos\n\n"
            "**AthenAI** es un IDS (Intrusion Detection System) que combina "
            "Machine Learning con arquitectura serverless para detectar amenazas "
            "en tiempo real.\n\n"
            "### Arquitectura\n"
            "```\n"
            "Tráfico → Middleware → Feature Engineering → AI Engine → Policy Engine → Acción\n"
            "```\n\n"
            "### Autenticación\n"
            "Los endpoints marcados con 🔒 requieren un JWT en el header:\n"
            "```\n"
            "Authorization: Bearer <access_token>\n"
            "```\n"
            "Obtén el token en `POST /api/auth/login`."
        ),
        "version": "1.0.0",
        "contact": {
            "name": "AthenAI Team",
            "email": "admin@athenai.com"
        },
        "license": {
            "name": "MIT"
        }
    },
    "host": "localhost:5000",
    "basePath": "/",
    "schemes": ["http"],
    "consumes": ["application/json"],
    "produces": ["application/json"],
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Formato: Bearer <token>"
        }
    },
    "tags": [
        {"name": "Auth", "description": "Autenticación y gestión de tokens JWT"},
        {"name": "Dashboard", "description": "Datos para el dashboard (stats, tráfico, alertas)"},
        {"name": "IP Management", "description": "Bloqueo y whitelist de IPs"},
        {"name": "AI / ML", "description": "Estado del AI Engine y continuous learning"},
        {"name": "Policy Engine", "description": "Decisiones de seguridad por score de amenaza"},
        {"name": "System", "description": "Health check, métricas y estado del sistema"},
    ],
    "definitions": {
        "LoginRequest": {
            "type": "object",
            "required": ["username", "password"],
            "properties": {
                "username": {"type": "string", "minLength": 2, "maxLength": 50, "example": "admin"},
                "password": {"type": "string", "minLength": 6, "example": "admin123"}
            }
        },
        "LoginResponse": {
            "type": "object",
            "properties": {
                "access_token": {"type": "string", "example": "eyJ0eXAiOiJKV1QiLCJhb..."},
                "refresh_token": {"type": "string", "example": "eyJ0eXAiOiJKV1QiLCJhb..."},
                "user": {
                    "type": "object",
                    "properties": {
                        "username": {"type": "string"},
                        "role": {"type": "string", "enum": ["admin", "analyst", "viewer"]},
                        "email": {"type": "string"}
                    }
                }
            }
        },
        "RegisterRequest": {
            "type": "object",
            "required": ["username", "password", "email"],
            "properties": {
                "username": {"type": "string", "minLength": 2, "maxLength": 50, "example": "newuser"},
                "password": {"type": "string", "minLength": 6, "example": "secure_password"},
                "email": {"type": "string", "format": "email", "example": "user@athenai.com"},
                "role": {"type": "string", "enum": ["admin", "analyst", "viewer"], "default": "viewer"}
            }
        },
        "BlockIPRequest": {
            "type": "object",
            "required": ["ip"],
            "properties": {
                "ip": {"type": "string", "example": "192.168.1.100"},
                "reason": {"type": "string", "maxLength": 200, "example": "Suspicious activity"},
                "duration": {"type": "integer", "minimum": 1, "maximum": 604800,
                             "default": 3600, "description": "Duración en segundos (máx 7 días)"}
            }
        },
        "WhitelistRequest": {
            "type": "object",
            "required": ["ip"],
            "properties": {
                "ip": {"type": "string", "example": "10.0.0.1"},
                "reason": {"type": "string", "maxLength": 200, "example": "Internal server"}
            }
        },
        "ValidationError": {
            "type": "object",
            "properties": {
                "error": {"type": "string", "example": "Validation failed"},
                "messages": {
                    "type": "object",
                    "additionalProperties": {"type": "array", "items": {"type": "string"}},
                    "example": {"ip": ["'abc' no es una dirección IP válida."]}
                }
            }
        },
        "PolicyDecision": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["allow", "log", "alert", "rate_limit", "block"],
                    "example": "rate_limit"
                },
                "threat_score": {"type": "number", "example": 85.0},
                "threat_type": {"type": "string", "example": "sql_injection"},
                "reason": {"type": "string"},
                "timestamp": {"type": "string", "format": "date-time"}
            }
        }
    }
}
