"""
RBAC Integration Tests — AthenAI Dashboard
Verifies the 3-tier role system: viewer / analyst / admin

Run against a live server:
    pytest test_rbac.py -v

Tests are skipped automatically if the server is not reachable.
"""

import pytest
import requests

BASE_URL = "http://127.0.0.1:5000"

# ---------------------------------------------------------------------------
# Server availability guard
# ---------------------------------------------------------------------------

def _server_available() -> bool:
    try:
        r = requests.get(f"{BASE_URL}/api/health", timeout=3)
        return r.status_code < 500
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _server_available(),
    reason="AthenAI server not reachable at http://127.0.0.1:5000"
)


# ---------------------------------------------------------------------------
# Fixtures — obtain one JWT per role, session-scoped
# ---------------------------------------------------------------------------

CREDENTIALS = {
    "admin":   {"username": "admin@athenai.com",   "password": "admin123"},
    "analyst": {"username": "analyst@athenai.com", "password": "analyst123"},
    "viewer":  {"username": "viewer@athenai.com",  "password": "viewer123"},
}


def _login(username: str, password: str) -> str:
    resp = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"username": username, "password": password},
        timeout=10,
    )
    assert resp.status_code == 200, f"Login failed for {username}: {resp.text}"
    data = resp.json()
    token = data.get("access_token") or data.get("token")
    assert token, f"No token in login response: {data}"
    return token


@pytest.fixture(scope="session")
def admin_token():
    c = CREDENTIALS["admin"]
    return _login(c["username"], c["password"])


@pytest.fixture(scope="session")
def analyst_token():
    c = CREDENTIALS["analyst"]
    return _login(c["username"], c["password"])


@pytest.fixture(scope="session")
def viewer_token():
    c = CREDENTIALS["viewer"]
    return _login(c["username"], c["password"])


def _headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# 1. Viewer — read-only endpoints must return non-403
# ---------------------------------------------------------------------------

VIEWER_READABLE = [
    "/api/stats",
    "/api/traffic",
    "/api/attacks",
    "/api/alerts",
    "/api/blocked-ips",
    "/api/whitelist",
    "/api/ml/performance",
    "/api/threats/summary",
    "/api/security/stats",
    "/api/ip-stats",
]


@pytest.mark.parametrize("endpoint", VIEWER_READABLE)
def test_viewer_can_read(viewer_token, endpoint):
    r = requests.get(f"{BASE_URL}{endpoint}", headers=_headers(viewer_token), timeout=10)
    assert r.status_code != 403, (
        f"Viewer got 403 on {endpoint} — should be readable. Response: {r.text[:200]}"
    )


# ---------------------------------------------------------------------------
# 2. Viewer — mutation / privileged endpoints must return 403
# ---------------------------------------------------------------------------

VIEWER_BLOCKED_POST = [
    ("/api/blocked-ips",              {"ip": "1.2.3.4", "reason": "test", "duration": 60}),
    ("/api/whitelist",                {"ip": "1.2.3.5", "reason": "test"}),
    ("/api/security/analyze",         {"request_data": {"path": "/test", "method": "GET", "ip": "1.2.3.6", "user_agent": "test"}}),
    ("/api/ab-testing/traffic-split", {"model_a_percentage": 60}),
    ("/api/ab-testing/promote",       {}),
    ("/api/ab-testing/reset",         {}),
]


@pytest.mark.parametrize("endpoint,body", VIEWER_BLOCKED_POST)
def test_viewer_blocked_on_mutations(viewer_token, endpoint, body):
    r = requests.post(f"{BASE_URL}{endpoint}", json=body, headers=_headers(viewer_token), timeout=10)
    assert r.status_code == 403, (
        f"Viewer should be blocked (403) on POST {endpoint} but got {r.status_code}. Response: {r.text[:200]}"
    )


# ---------------------------------------------------------------------------
# 3. Analyst — inherits viewer reads + additional analyst-tier endpoints
# ---------------------------------------------------------------------------

ANALYST_READABLE = VIEWER_READABLE + [
    "/api/ab-testing/stats",
    "/api/continuous-learning/stats",
    "/api/ml/models",
    "/api/ml/stats",
    "/api/ml/training-jobs",
    "/api/ml/endpoints",
    "/api/backup/list",
]


@pytest.mark.parametrize("endpoint", ANALYST_READABLE)
def test_analyst_can_read(analyst_token, endpoint):
    r = requests.get(f"{BASE_URL}{endpoint}", headers=_headers(analyst_token), timeout=10)
    assert r.status_code != 403, (
        f"Analyst got 403 on {endpoint} — should be readable. Response: {r.text[:200]}"
    )


def test_analyst_can_analyze(analyst_token):
    body = {"request_data": {"path": "/test", "method": "GET", "ip": "1.2.3.7", "user_agent": "pytest"}}
    r = requests.post(f"{BASE_URL}/api/security/analyze", json=body, headers=_headers(analyst_token), timeout=10)
    assert r.status_code != 403, f"Analyst blocked on /api/security/analyze: {r.text[:200]}"


# ---------------------------------------------------------------------------
# 4. Analyst — admin-only endpoints must return 403
# ---------------------------------------------------------------------------

ANALYST_BLOCKED = [
    ("GET",  "/api/cache-stats",     None),
    ("POST", "/api/backup/manual",   {}),
    ("POST", "/api/backup/restore",  {"backup_file": "test.json"}),
]


@pytest.mark.parametrize("method,endpoint,body", ANALYST_BLOCKED)
def test_analyst_blocked_on_admin_endpoints(analyst_token, method, endpoint, body):
    fn = requests.get if method == "GET" else requests.post
    kwargs = {"headers": _headers(analyst_token), "timeout": 10}
    if body is not None:
        kwargs["json"] = body
    r = fn(f"{BASE_URL}{endpoint}", **kwargs)
    assert r.status_code == 403, (
        f"Analyst should be blocked (403) on {method} {endpoint} but got {r.status_code}. Response: {r.text[:200]}"
    )


# ---------------------------------------------------------------------------
# 5. Admin — full access across all tiers
# ---------------------------------------------------------------------------

ALL_READABLE = list(set(ANALYST_READABLE + ["/api/cache-stats"]))


@pytest.mark.parametrize("endpoint", ALL_READABLE)
def test_admin_full_read_access(admin_token, endpoint):
    r = requests.get(f"{BASE_URL}{endpoint}", headers=_headers(admin_token), timeout=10)
    assert r.status_code != 403, (
        f"Admin got 403 on GET {endpoint}. Response: {r.text[:200]}"
    )


# ---------------------------------------------------------------------------
# 6. Unauthenticated requests must return 401
# ---------------------------------------------------------------------------

PROTECTED_ENDPOINTS = [
    "/api/stats",
    "/api/blocked-ips",
    "/api/ml/models",
    "/api/cache-stats",
    "/api/threats/summary",
]


@pytest.mark.parametrize("endpoint", PROTECTED_ENDPOINTS)
def test_unauthenticated_gets_401(endpoint):
    r = requests.get(f"{BASE_URL}{endpoint}", timeout=10)
    assert r.status_code == 401, (
        f"Expected 401 on unauthenticated {endpoint}, got {r.status_code}. Response: {r.text[:200]}"
    )


def test_malformed_token_gets_401():
    r = requests.get(f"{BASE_URL}/api/stats", headers={"Authorization": "Bearer not.a.jwt"}, timeout=10)
    assert r.status_code == 401


def test_missing_bearer_prefix_gets_401():
    r = requests.get(f"{BASE_URL}/api/stats", headers={"Authorization": "justaplainstring"}, timeout=10)
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# 7. Cross-role token isolation
# ---------------------------------------------------------------------------

def test_viewer_token_rejected_on_analyst_endpoint(viewer_token):
    r = requests.get(f"{BASE_URL}/api/continuous-learning/stats", headers=_headers(viewer_token), timeout=10)
    assert r.status_code == 403, (
        f"Viewer token should be rejected (403) on analyst endpoint, got {r.status_code}"
    )


def test_viewer_token_rejected_on_admin_endpoint(viewer_token):
    r = requests.get(f"{BASE_URL}/api/cache-stats", headers=_headers(viewer_token), timeout=10)
    assert r.status_code == 403, (
        f"Viewer token should be rejected (403) on admin endpoint, got {r.status_code}"
    )


def test_analyst_token_rejected_on_admin_endpoint(analyst_token):
    r = requests.get(f"{BASE_URL}/api/cache-stats", headers=_headers(analyst_token), timeout=10)
    assert r.status_code == 403, (
        f"Analyst token should be rejected (403) on admin endpoint, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# 8. Auth self-service: login → /me → correct role
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role,creds", CREDENTIALS.items())
def test_login_returns_token_and_me_returns_correct_role(role, creds):
    # Login
    resp = requests.post(f"{BASE_URL}/api/auth/login", json=creds, timeout=10)
    assert resp.status_code == 200, f"Login failed for {role}: {resp.text}"
    token = resp.json().get("access_token") or resp.json().get("token")
    assert token

    # /api/auth/me reflects correct role
    me = requests.get(f"{BASE_URL}/api/auth/me", headers={"Authorization": f"Bearer {token}"}, timeout=10)
    assert me.status_code == 200
    user = me.json().get("user", me.json())
    assert user.get("role") == role, (
        f"Expected role '{role}', got '{user.get('role')}'"
    )


def test_wrong_password_returns_401():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"username": "admin@athenai.com", "password": "wrongpassword"},
        timeout=10,
    )
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# 9. Logout — token is revoked via Redis blacklist
# ---------------------------------------------------------------------------

def test_logout_revokes_token():
    # Get a fresh token
    c = CREDENTIALS["viewer"]
    token = _login(c["username"], c["password"])

    # Confirm it works before logout
    r = requests.get(f"{BASE_URL}/api/stats", headers=_headers(token), timeout=10)
    assert r.status_code != 401, "Token should be valid before logout"

    # Logout
    r_logout = requests.post(f"{BASE_URL}/api/auth/logout", headers=_headers(token), timeout=10)
    assert r_logout.status_code == 200

    # Token must now be rejected
    r_after = requests.get(f"{BASE_URL}/api/stats", headers=_headers(token), timeout=10)
    assert r_after.status_code == 401, (
        f"Token should be revoked after logout, but got {r_after.status_code}"
    )
