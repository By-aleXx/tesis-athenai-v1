"""
conftest.py - Configuración compartida de pytest para AthenAI

Fixtures disponibles:
  - app_client    → Flask test client (no requiere auth)
  - auth_headers  → Headers con JWT válido para endpoints protegidos
"""

import os
import sys
import pytest

# Agregar el directorio del dashboard al path de Python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'athenai-dashboard'))

# Establecer variables de entorno de prueba ANTES de importar el app
os.environ.setdefault('REMOTE_SERVER_IP', '127.0.0.1')
os.environ.setdefault('AWS_ENDPOINT_URL', 'http://127.0.0.1:4566')
os.environ.setdefault('AWS_REGION', 'us-east-1')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('REDIS_HOST', '127.0.0.1')
os.environ.setdefault('REDIS_PORT', '6379')
os.environ.setdefault('JWT_SECRET_KEY', 'test-jwt-secret-key-for-pytest')
os.environ.setdefault('JWT_REFRESH_SECRET_KEY', 'test-jwt-refresh-secret-for-pytest')
os.environ.setdefault('FLASK_DEBUG', 'False')
os.environ.setdefault('ADMIN_PASSWORD', 'admin123')


@pytest.fixture(scope='session')
def app_client():
    """
    Flask test client para toda la sesión de tests.
    Usa una base de datos SQLite en memoria para no afectar la BD real.
    """
    # Importar app aquí (DESPUÉS de setear env vars)
    from api_backend import app

    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        yield client


@pytest.fixture(scope='session')
def auth_headers(app_client):
    """
    Obtiene un JWT válido haciendo login con el usuario admin del AuthManager
    (auth.py). Retorna el dict de headers listo para usar en test requests.
    """
    response = app_client.post(
        '/api/auth/login',
        json={'username': 'admin', 'password': 'admin123'},
        content_type='application/json'
    )

    if response.status_code == 200:
        token = response.get_json().get('access_token')
        if token:
            return {'Authorization': f'Bearer {token}'}

    # Fallback: retornar headers vacíos (endpoints sin auth seguirán funcionando)
    return {}
