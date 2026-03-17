"""
Tests unitarios para policy_engine.py

Verifica que el PolicyEngine tome las decisiones correctas
(ALLOW/LOG/ALERT/RATE_LIMIT/BLOCK) según el threat score.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'athenai-dashboard'))

os.environ.setdefault('REMOTE_SERVER_IP', '127.0.0.1')
os.environ.setdefault('AWS_ENDPOINT_URL', 'http://127.0.0.1:4566')
os.environ.setdefault('AWS_ACCESS_KEY_ID', 'test')
os.environ.setdefault('AWS_SECRET_ACCESS_KEY', 'test')
os.environ.setdefault('REDIS_HOST', '127.0.0.1')
os.environ.setdefault('JWT_SECRET_KEY', 'test-key')
os.environ.setdefault('JWT_REFRESH_SECRET_KEY', 'test-refresh-key')

from policy_engine import PolicyEngine, PolicyAction, PolicyDecision


@pytest.fixture
def engine():
    """PolicyEngine con thresholds por defecto: 30 / 60 / 80 / 95"""
    return PolicyEngine()


class TestPolicyActions:
    """Verifica que cada rango de score produce la acción correcta."""

    def test_score_0_is_allow(self, engine):
        d = engine.evaluate(0.0, 'normal')
        assert d.action == PolicyAction.ALLOW

    def test_score_15_is_allow(self, engine):
        d = engine.evaluate(15.0, 'normal')
        assert d.action == PolicyAction.ALLOW

    def test_score_29_is_allow(self, engine):
        d = engine.evaluate(29.9, 'normal')
        assert d.action == PolicyAction.ALLOW

    def test_score_30_is_log(self, engine):
        d = engine.evaluate(30.0, 'anomaly')
        assert d.action == PolicyAction.LOG

    def test_score_45_is_log(self, engine):
        d = engine.evaluate(45.0, 'anomaly')
        assert d.action == PolicyAction.LOG

    def test_score_60_is_alert(self, engine):
        d = engine.evaluate(60.0, 'xss')
        assert d.action == PolicyAction.ALERT

    def test_score_75_is_alert(self, engine):
        d = engine.evaluate(75.0, 'sql_injection')
        assert d.action == PolicyAction.ALERT

    def test_score_80_is_rate_limit(self, engine):
        d = engine.evaluate(80.0, 'brute_force')
        assert d.action == PolicyAction.RATE_LIMIT

    def test_score_90_is_rate_limit(self, engine):
        d = engine.evaluate(90.0, 'dos')
        assert d.action == PolicyAction.RATE_LIMIT

    def test_score_95_is_block(self, engine):
        d = engine.evaluate(95.0, 'ddos')
        assert d.action == PolicyAction.BLOCK

    def test_score_100_is_block(self, engine):
        d = engine.evaluate(100.0, 'ddos')
        assert d.action == PolicyAction.BLOCK


class TestPolicyDecisionContent:
    """Verifica que PolicyDecision tenga el contenido correcto."""

    def test_decision_has_all_fields(self, engine):
        d = engine.evaluate(85.0, 'sql_injection')
        assert isinstance(d, PolicyDecision)
        assert d.threat_score == 85.0
        assert d.threat_type == 'sql_injection'
        assert d.reason != ''
        assert d.timestamp != ''

    def test_to_dict_is_serializable(self, engine):
        d = engine.evaluate(50.0, 'xss')
        result = d.to_dict()
        assert result['action'] == 'log'
        assert result['threat_score'] == 50.0
        assert result['threat_type'] == 'xss'
        assert 'timestamp' in result

    def test_reason_mentions_score(self, engine):
        d = engine.evaluate(72.5, 'brute_force')
        assert '72.5' in d.reason


class TestWhitelistContext:
    """IPs en whitelist deben recibir ALLOW independientemente del score."""

    def test_whitelisted_ip_always_allow(self, engine):
        d = engine.evaluate(99.0, 'ddos', context={'is_whitelisted': True})
        assert d.action == PolicyAction.ALLOW

    def test_non_whitelisted_high_score_blocks(self, engine):
        d = engine.evaluate(99.0, 'ddos', context={'is_whitelisted': False})
        assert d.action == PolicyAction.BLOCK


class TestThresholdUpdate:
    """Verifica que los thresholds se pueden actualizar en runtime."""

    def test_update_thresholds_changes_behavior(self):
        engine = PolicyEngine()
        # Con threshold_low=30, score 25 → ALLOW
        assert engine.evaluate(25.0, 'test').action == PolicyAction.ALLOW

        # Subir threshold_low a 50, score 25 debería seguir siendo ALLOW
        # (para que pase a LOG necesitamos que score >= low)
        engine.update_thresholds(low=10.0)
        # score 25 ahora está ENTRE 10 (low) y 60 (medium) → LOG
        assert engine.evaluate(25.0, 'test').action == PolicyAction.LOG

    def test_get_thresholds_returns_dict(self):
        engine = PolicyEngine()
        t = engine.get_thresholds()
        assert 'allow_below' in t
        assert 'block_at_or_above' in t
