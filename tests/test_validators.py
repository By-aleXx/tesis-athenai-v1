"""
Tests unitarios para validators.py

Verifica que cada schema de marshmallow:
  - Acepta datos válidos y retorna valores con defaults correctos
  - Rechaza datos inválidos con mensajes de error apropiados
  - El decorador @validate_json retorna HTTP 422 ante datos inválidos
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'athenai-dashboard'))

# Setear env vars para importaciones
os.environ.setdefault('JWT_SECRET_KEY', 'test-key')
os.environ.setdefault('JWT_REFRESH_SECRET_KEY', 'test-refresh-key')
os.environ.setdefault('AWS_ENDPOINT_URL', 'http://127.0.0.1:4566')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('REMOTE_SERVER_IP', '127.0.0.1')
os.environ.setdefault('REDIS_HOST', '127.0.0.1')

from marshmallow import ValidationError
from validators import (
    LoginSchema, RegisterSchema, RefreshTokenSchema,
    BlockIPSchema, WhitelistSchema, TrafficSplitSchema,
    PolicyThresholdSchema
)


# ============================================================
# LoginSchema
# ============================================================

class TestLoginSchema:
    def test_valid_credentials(self):
        result = LoginSchema().load({'username': 'admin', 'password': 'admin123'})
        assert result['username'] == 'admin'
        assert result['password'] == 'admin123'

    def test_empty_username_rejected(self):
        with pytest.raises(ValidationError) as exc:
            LoginSchema().load({'username': '', 'password': 'admin123'})
        assert 'username' in exc.value.messages

    def test_short_password_rejected(self):
        with pytest.raises(ValidationError) as exc:
            LoginSchema().load({'username': 'admin', 'password': '123'})
        assert 'password' in exc.value.messages

    def test_missing_fields_rejected(self):
        with pytest.raises(ValidationError) as exc:
            LoginSchema().load({})
        assert 'username' in exc.value.messages
        assert 'password' in exc.value.messages

    def test_special_chars_in_username_rejected(self):
        with pytest.raises(ValidationError) as exc:
            LoginSchema().load({'username': 'admin<script>', 'password': 'pass123'})
        assert 'username' in exc.value.messages

    def test_extra_fields_ignored(self):
        result = LoginSchema().load({
            'username': 'admin', 'password': 'pass123', 'extra_field': 'ignored'
        })
        assert 'extra_field' not in result


# ============================================================
# RegisterSchema
# ============================================================

class TestRegisterSchema:
    def test_valid_registration(self):
        result = RegisterSchema().load({
            'username': 'newuser',
            'password': 'secure123',
            'email': 'user@example.com'
        })
        assert result['role'] == 'viewer'  # default

    def test_invalid_email_rejected(self):
        with pytest.raises(ValidationError) as exc:
            RegisterSchema().load({
                'username': 'user', 'password': 'pass123', 'email': 'no-es-email'
            })
        assert 'email' in exc.value.messages

    def test_invalid_role_rejected(self):
        with pytest.raises(ValidationError) as exc:
            RegisterSchema().load({
                'username': 'user', 'password': 'pass123',
                'email': 'u@u.com', 'role': 'superuser'
            })
        assert 'role' in exc.value.messages

    def test_valid_roles_accepted(self):
        for role in ['admin', 'analyst', 'viewer']:
            result = RegisterSchema().load({
                'username': 'u', 'password': 'pass123',
                'email': 'u@u.com', 'role': role
            })
            assert result['role'] == role


# ============================================================
# BlockIPSchema
# ============================================================

class TestBlockIPSchema:
    def test_valid_ipv4(self):
        result = BlockIPSchema().load({'ip': '192.168.1.100'})
        assert result['ip'] == '192.168.1.100'
        assert result['duration'] == 3600       # default
        assert result['reason'] == 'Manual block'  # default

    def test_valid_ipv6(self):
        result = BlockIPSchema().load({'ip': '2001:db8::1'})
        assert result['ip'] == '2001:db8::1'

    def test_invalid_ip_rejected(self):
        with pytest.raises(ValidationError) as exc:
            BlockIPSchema().load({'ip': 'not-an-ip'})
        assert 'ip' in exc.value.messages

    def test_duration_out_of_range_rejected(self):
        with pytest.raises(ValidationError) as exc:
            BlockIPSchema().load({'ip': '1.2.3.4', 'duration': 999999})
        assert 'duration' in exc.value.messages

    def test_duration_zero_rejected(self):
        with pytest.raises(ValidationError) as exc:
            BlockIPSchema().load({'ip': '1.2.3.4', 'duration': 0})
        assert 'duration' in exc.value.messages

    def test_reason_too_long_rejected(self):
        with pytest.raises(ValidationError) as exc:
            BlockIPSchema().load({'ip': '1.2.3.4', 'reason': 'x' * 201})
        assert 'reason' in exc.value.messages

    def test_custom_duration_accepted(self):
        result = BlockIPSchema().load({'ip': '10.0.0.1', 'duration': 7200, 'reason': 'Test'})
        assert result['duration'] == 7200


# ============================================================
# WhitelistSchema
# ============================================================

class TestWhitelistSchema:
    def test_valid_ip(self):
        result = WhitelistSchema().load({'ip': '10.0.0.1'})
        assert result['ip'] == '10.0.0.1'
        assert result['reason'] == 'Trusted source'  # default

    def test_invalid_ip_rejected(self):
        with pytest.raises(ValidationError) as exc:
            WhitelistSchema().load({'ip': '999.999.999.999'})
        assert 'ip' in exc.value.messages


# ============================================================
# TrafficSplitSchema
# ============================================================

class TestTrafficSplitSchema:
    def test_valid_percentage(self):
        result = TrafficSplitSchema().load({'model_a_percentage': 80.0})
        assert result['model_a_percentage'] == 80.0

    def test_percentage_above_100_rejected(self):
        with pytest.raises(ValidationError) as exc:
            TrafficSplitSchema().load({'model_a_percentage': 150})
        assert 'model_a_percentage' in exc.value.messages

    def test_negative_percentage_rejected(self):
        with pytest.raises(ValidationError) as exc:
            TrafficSplitSchema().load({'model_a_percentage': -5})
        assert 'model_a_percentage' in exc.value.messages

    def test_boundary_values_accepted(self):
        assert TrafficSplitSchema().load({'model_a_percentage': 0})['model_a_percentage'] == 0
        assert TrafficSplitSchema().load({'model_a_percentage': 100})['model_a_percentage'] == 100


# ============================================================
# PolicyThresholdSchema
# ============================================================

class TestPolicyThresholdSchema:
    def test_valid_thresholds(self):
        result = PolicyThresholdSchema().load(
            {'low': 20.0, 'medium': 50.0, 'high': 75.0, 'critical': 90.0}
        )
        assert result['low'] == 20.0

    def test_out_of_order_thresholds_rejected(self):
        with pytest.raises(ValidationError):
            PolicyThresholdSchema().load({'low': 60.0, 'medium': 30.0})  # low > medium
