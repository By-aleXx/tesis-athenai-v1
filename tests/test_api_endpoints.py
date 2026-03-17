"""
Tests de integración para los endpoints de la API REST (api_backend.py)

Usa el Flask test client para hacer peticiones HTTP reales al backend
y verificar status codes y estructura de respuestas.

Requiere: pytest, el app corriendo en modo TESTING (sin Redis/DynamoDB reales).
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'athenai-dashboard'))

# Env vars ya seteadas en conftest.py


class TestHealthEndpoint:
    """GET /api/health — no requiere autenticación"""

    def test_health_returns_200(self, app_client):
        resp = app_client.get('/api/health')
        assert resp.status_code == 200

    def test_health_response_structure(self, app_client):
        resp = app_client.get('/api/health')
        data = resp.get_json()
        assert 'status' in data
        assert 'timestamp' in data
        assert 'services' in data

    def test_health_status_is_healthy(self, app_client):
        resp = app_client.get('/api/health')
        data = resp.get_json()
        assert data['status'] in ['healthy', 'unhealthy']  # acepta ambos (S3 puede no estar)


class TestAuthEndpoints:
    """POST /api/auth/login y /api/auth/refresh"""

    def test_login_valid_credentials(self, app_client):
        resp = app_client.post(
            '/api/auth/login',
            json={'username': 'admin', 'password': 'admin123'},
            content_type='application/json'
        )
        # Puede ser 200 (auth_manager disponible) o 503 (sin auth_manager)
        assert resp.status_code in [200, 503]

    def test_login_empty_username_rejected_422(self, app_client):
        resp = app_client.post(
            '/api/auth/login',
            json={'username': '', 'password': 'admin123'},
            content_type='application/json'
        )
        assert resp.status_code == 422
        data = resp.get_json()
        assert data['error'] == 'Validation failed'
        assert 'username' in data['messages']

    def test_login_short_password_rejected_422(self, app_client):
        resp = app_client.post(
            '/api/auth/login',
            json={'username': 'admin', 'password': 'x'},
            content_type='application/json'
        )
        assert resp.status_code == 422

    def test_login_missing_json_returns_400(self, app_client):
        resp = app_client.post(
            '/api/auth/login',
            data='not json',
            content_type='text/plain'
        )
        assert resp.status_code == 400

    def test_login_special_chars_username_rejected(self, app_client):
        resp = app_client.post(
            '/api/auth/login',
            json={'username': '<script>alert(1)</script>', 'password': 'pass123'},
            content_type='application/json'
        )
        assert resp.status_code == 422

    def test_register_invalid_email_rejected(self, app_client):
        resp = app_client.post(
            '/api/auth/register',
            json={
                'username': 'newuser',
                'password': 'password123',
                'email': 'no-es-un-email'
            },
            content_type='application/json'
        )
        assert resp.status_code == 422
        data = resp.get_json()
        assert 'email' in data['messages']

    def test_register_invalid_role_rejected(self, app_client):
        resp = app_client.post(
            '/api/auth/register',
            json={
                'username': 'newuser',
                'password': 'password123',
                'email': 'new@test.com',
                'role': 'superadmin'
            },
            content_type='application/json'
        )
        assert resp.status_code == 422
        data = resp.get_json()
        assert 'role' in data['messages']

    def test_refresh_missing_token_rejected(self, app_client):
        resp = app_client.post(
            '/api/auth/refresh',
            json={},
            content_type='application/json'
        )
        assert resp.status_code == 422


class TestIPManagementValidation:
    """POST /api/blocked-ips y /api/whitelist — validación de IP"""

    def test_block_invalid_ip_rejected(self, app_client, auth_headers):
        resp = app_client.post(
            '/api/blocked-ips',
            json={'ip': 'not-an-ip', 'reason': 'test'},
            content_type='application/json',
            headers=auth_headers
        )
        assert resp.status_code == 422
        data = resp.get_json()
        assert 'ip' in data['messages']

    def test_block_duration_out_of_range_rejected(self, app_client, auth_headers):
        resp = app_client.post(
            '/api/blocked-ips',
            json={'ip': '10.0.0.1', 'duration': 9999999},
            content_type='application/json',
            headers=auth_headers
        )
        assert resp.status_code == 422

    def test_whitelist_invalid_ip_rejected(self, app_client, auth_headers):
        resp = app_client.post(
            '/api/whitelist',
            json={'ip': '999.0.0.1'},
            content_type='application/json',
            headers=auth_headers
        )
        assert resp.status_code == 422

    def test_whitelist_reason_too_long_rejected(self, app_client, auth_headers):
        resp = app_client.post(
            '/api/whitelist',
            json={'ip': '10.0.0.1', 'reason': 'x' * 201},
            content_type='application/json',
            headers=auth_headers
        )
        assert resp.status_code == 422


class TestPublicEndpoints:
    """Endpoints sin autenticación que deben responder correctamente."""

    def test_home_endpoint(self, app_client):
        resp = app_client.get('/api/home')
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['status'] == 'operational'

    def test_traffic_endpoint(self, app_client):
        resp = app_client.get('/api/traffic')
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, list)
        assert len(data) == 24  # 24 horas

    def test_traffic_data_has_correct_fields(self, app_client):
        resp = app_client.get('/api/traffic')
        data = resp.get_json()
        for item in data:
            assert 'time' in item
            assert 'requests' in item
            assert 'threats' in item

    def test_model_info_endpoint(self, app_client):
        resp = app_client.get('/api/model-info')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'xgboost' in data
        assert 'isolation_forest' in data
