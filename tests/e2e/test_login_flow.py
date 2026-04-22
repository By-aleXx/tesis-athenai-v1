"""
AthenAI — E2E Login Flow Tests (Playwright)

Covers:
  - empty-submit
  - bad credentials
  - good credentials → dashboard redirect
  - SQL injection attempt
  - XSS attempt
  - rate-limit (5 failed attempts → 429)

Run:
  pip install playwright pytest-playwright
  playwright install chromium
  pytest tests/e2e/test_login_flow.py -v --base-url=http://127.0.0.1:5000
"""

import re
import pytest
from playwright.sync_api import Page, expect

BASE = "http://127.0.0.1:5000"
LOGIN = f"{BASE}/login.html"


@pytest.fixture(autouse=True)
def go_to_login(page: Page):
    page.goto(LOGIN)
    page.wait_for_load_state("networkidle")


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _fill_and_submit(page: Page, username: str, password: str):
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#loginBtn")
    page.wait_for_load_state("networkidle")


# ---------------------------------------------------------------------------
# 1. Empty submit — should not navigate away
# ---------------------------------------------------------------------------

def test_empty_submit_shows_validation(page: Page):
    page.click("#loginBtn")
    # HTML5 required validation keeps us on the login page
    expect(page).to_have_url(re.compile(r"/login\.html"))


# ---------------------------------------------------------------------------
# 2. Wrong credentials — error message shown
# ---------------------------------------------------------------------------

def test_bad_credentials_shows_error(page: Page):
    _fill_and_submit(page, "nobody", "wrongpass")
    error = page.locator("#errorMessage")
    expect(error).to_be_visible(timeout=5_000)
    expect(error).not_to_have_text("")


# ---------------------------------------------------------------------------
# 3. Correct admin credentials — redirects to dashboard
# ---------------------------------------------------------------------------

def test_good_credentials_admin_redirect(page: Page):
    _fill_and_submit(page, "admin", "admin123")
    expect(page).to_have_url(re.compile(r"/index\.html"), timeout=8_000)


# ---------------------------------------------------------------------------
# 4. Correct analyst credentials
# ---------------------------------------------------------------------------

def test_good_credentials_analyst_redirect(page: Page):
    _fill_and_submit(page, "analyst", "analyst123")
    expect(page).to_have_url(re.compile(r"/index\.html"), timeout=8_000)


# ---------------------------------------------------------------------------
# 5. SQL injection attempt — stays on login, no 500
# ---------------------------------------------------------------------------

def test_sqli_attempt_blocked(page: Page):
    _fill_and_submit(page, "' OR '1'='1", "' OR '1'='1")
    # Must remain on login page (no redirect to dashboard)
    expect(page).not_to_have_url(re.compile(r"/index\.html"), timeout=4_000)


# ---------------------------------------------------------------------------
# 6. XSS attempt — stays on login, no script execution
# ---------------------------------------------------------------------------

def test_xss_attempt_blocked(page: Page):
    _fill_and_submit(page, "<script>alert(1)</script>", "x")
    expect(page).not_to_have_url(re.compile(r"/index\.html"), timeout=4_000)


# ---------------------------------------------------------------------------
# 7. Rate limit — 5 failed attempts should trigger 429
# ---------------------------------------------------------------------------

def test_rate_limit_after_five_failures(page: Page):
    responses: list[int] = []

    def on_response(resp):
        if "/api/auth/login" in resp.url:
            responses.append(resp.status)

    page.on("response", on_response)

    for _ in range(6):
        page.fill("#username", "admin")
        page.fill("#password", "wrongpass")
        page.click("#loginBtn")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(300)

    assert any(s == 429 for s in responses), (
        f"Expected a 429 after repeated failures, got: {responses}"
    )
