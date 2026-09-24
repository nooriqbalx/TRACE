# ruff: noqa: S101
"""
Automated ground-truth tests for TRACE-Bench.

Each function checks a scenario's vulnerable behavior (no patch flag) and
its patched behavior (flag set to "1") via FastAPI's TestClient. No server
process needed: patch flags are read at request time, so monkeypatch.setenv
takes effect immediately on the next call.
"""

import os

import pytest
from fastapi.testclient import TestClient
from tracebench.main import app, reset_data, sessions

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_between_tests():
    reset_data()
    yield
    reset_data()


def _clear_patch_env():
    for key in list(os.environ):
        if key.startswith("TRACEBENCH_PATCH_"):
            del os.environ[key]


@pytest.fixture(autouse=True)
def _clean_env():
    _clear_patch_env()
    yield
    _clear_patch_env()


# ---------------------------------------------------------------------------
# BOLA
# ---------------------------------------------------------------------------


def test_bola_direct_path(monkeypatch):
    r = client.get("/patients/2", headers={"X-User-Id": "1"})
    assert r.status_code == 200

    monkeypatch.setenv("TRACEBENCH_PATCH_BOLA_DIRECT_PATH", "1")
    r = client.get("/patients/1", headers={"X-User-Id": "1"})
    assert r.status_code == 200
    r = client.get("/patients/2", headers={"X-User-Id": "1"})
    assert r.status_code == 403


def test_bola_body_id(monkeypatch):
    r = client.post("/patients/lookup", json={"patient_id": 2}, headers={"X-User-Id": "1"})
    assert r.status_code == 200

    monkeypatch.setenv("TRACEBENCH_PATCH_BOLA_BODY_ID", "1")
    r = client.post("/patients/lookup", json={"patient_id": 1}, headers={"X-User-Id": "1"})
    assert r.status_code == 200
    r = client.post("/patients/lookup", json={"patient_id": 2}, headers={"X-User-Id": "1"})
    assert r.status_code == 403


def test_bola_related_object(monkeypatch):
    r = client.get("/appointments/2", headers={"X-User-Id": "1"})
    assert r.status_code == 200

    monkeypatch.setenv("TRACEBENCH_PATCH_BOLA_RELATED_OBJECT", "1")
    r = client.get("/appointments/1", headers={"X-User-Id": "1"})
    assert r.status_code == 200
    r = client.get("/appointments/2", headers={"X-User-Id": "1"})
    assert r.status_code == 403


def test_bola_write_access(monkeypatch):
    r = client.put(
        "/patients/2/notes", json={"medical_note": "tampered"}, headers={"X-User-Id": "1"}
    )
    assert r.status_code == 200

    monkeypatch.setenv("TRACEBENCH_PATCH_BOLA_WRITE_ACCESS", "1")
    r = client.put(
        "/patients/1/notes", json={"medical_note": "own update"}, headers={"X-User-Id": "1"}
    )
    assert r.status_code == 200
    r = client.put(
        "/patients/2/notes", json={"medical_note": "tampered again"}, headers={"X-User-Id": "1"}
    )
    assert r.status_code == 403


def test_bola_decoy_protected():
    r = client.get("/patients/2/billing", headers={"X-User-Id": "1"})
    assert r.status_code == 403
    r = client.get("/patients/1/billing", headers={"X-User-Id": "1"})
    assert r.status_code == 200


def test_bola_decoy_public():
    r = client.get("/doctors/1")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Broken Authentication
# ---------------------------------------------------------------------------


def test_authn_otp_bruteforce(monkeypatch):
    client.post("/auth/request-otp", params={"email": "a@example.com"})
    for _ in range(6):
        r = client.post("/auth/verify-otp", json={"email": "a@example.com", "otp": "wrong"})
    assert r.status_code == 401

    monkeypatch.setenv("TRACEBENCH_PATCH_AUTHN_OTP_BRUTEFORCE", "1")
    client.post("/auth/request-otp", params={"email": "b@example.com"})
    for _ in range(6):
        r = client.post("/auth/verify-otp", json={"email": "b@example.com", "otp": "wrong"})
    assert r.status_code == 429


def test_authn_predictable_token(monkeypatch):
    client.post("/auth/login-predictable", params={"user_id": 2})
    r = client.get("/me", headers={"X-Session-Token": "session-2"})
    assert r.status_code == 200

    reset_data()
    monkeypatch.setenv("TRACEBENCH_PATCH_AUTHN_PREDICTABLE_TOKEN", "1")
    client.post("/auth/login-predictable", params={"user_id": 2})
    r = client.get("/me", headers={"X-Session-Token": "session-2"})
    assert r.status_code == 401


def test_authn_token_no_expiry(monkeypatch):
    r = client.post("/auth/login-session", params={"user_id": 1})
    token = r.json()["token"]
    sessions[token]["issued_at"] -= 100
    r = client.get("/me/expiring", headers={"X-Session-Token": token})
    assert r.status_code == 200

    monkeypatch.setenv("TRACEBENCH_PATCH_AUTHN_TOKEN_NO_EXPIRY", "1")
    r = client.get("/me/expiring", headers={"X-Session-Token": token})
    assert r.status_code == 401


def test_authn_reset_token_reuse(monkeypatch):
    r = client.post("/auth/request-reset", params={"email": "a@example.com"})
    token = r.json()["token"]
    r1 = client.post("/auth/reset-password", json={"token": token, "new_password": "x"})
    r2 = client.post("/auth/reset-password", json={"token": token, "new_password": "y"})
    assert r1.status_code == 200
    assert r2.status_code == 200

    r = client.post("/auth/request-reset", params={"email": "b@example.com"})
    token = r.json()["token"]
    monkeypatch.setenv("TRACEBENCH_PATCH_AUTHN_RESET_TOKEN_REUSE", "1")
    r1 = client.post("/auth/reset-password", json={"token": token, "new_password": "x"})
    r2 = client.post("/auth/reset-password", json={"token": token, "new_password": "y"})
    assert r1.status_code == 200
    assert r2.status_code == 400


def test_authn_decoy_rate_limited():
    for _ in range(6):
        r = client.post("/auth/login-protected", params={"email": "c@example.com"})
    assert r.status_code == 429


def test_authn_decoy_public():
    r = client.get("/auth/status")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Excessive Data Exposure
# ---------------------------------------------------------------------------


def test_exposure_extra_pii_fields(monkeypatch):
    r = client.get("/patients/1/profile")
    assert "national_id" in r.json()

    monkeypatch.setenv("TRACEBENCH_PATCH_EXPOSURE_EXTRA_PII_FIELDS", "1")
    r = client.get("/patients/1/profile")
    assert "national_id" not in r.json()


def test_exposure_stack_trace(monkeypatch):
    r = client.get("/patients/1/risk-score", params={"divisor": 0})
    assert r.status_code == 500
    assert "division" in r.json()["detail"].lower()

    monkeypatch.setenv("TRACEBENCH_PATCH_EXPOSURE_STACK_TRACE", "1")
    r = client.get("/patients/1/risk-score", params={"divisor": 0})
    assert r.status_code == 400
    assert "division" not in r.json()["detail"].lower()


def test_exposure_list_leaks_others(monkeypatch):
    r = client.get("/patients", params={"mine": "true"}, headers={"X-User-Id": "1"})
    ids = [p["id"] for p in r.json()]
    assert 2 in ids

    monkeypatch.setenv("TRACEBENCH_PATCH_EXPOSURE_LIST_LEAKS_OTHERS", "1")
    r = client.get("/patients", params={"mine": "true"}, headers={"X-User-Id": "1"})
    ids = [p["id"] for p in r.json()]
    assert ids == [1]


def test_exposure_admin_flags(monkeypatch):
    r = client.get("/patients/1/full")
    assert "internal_risk_score" in r.json()

    monkeypatch.setenv("TRACEBENCH_PATCH_EXPOSURE_ADMIN_FLAGS", "1")
    r = client.get("/patients/1/full")
    assert "internal_risk_score" not in r.json()


def test_exposure_decoy_own_profile():
    r = client.get("/me/profile", headers={"X-User-Id": "1"})
    assert r.status_code == 200
    assert "phone" in r.json()


def test_exposure_decoy_public_directory():
    r = client.get("/doctors")
    assert r.status_code == 200
    assert len(r.json()) >= 1


# ---------------------------------------------------------------------------
# Rate Limiting
# ---------------------------------------------------------------------------


def test_ratelimit_login_bruteforce(monkeypatch):
    for _ in range(6):
        r = client.post("/auth/login", json={"email": "alice@example.com", "password": "wrong"})
    assert r.status_code == 401

    monkeypatch.setenv("TRACEBENCH_PATCH_RATELIMIT_LOGIN_BRUTEFORCE", "1")
    for _ in range(6):
        r = client.post("/auth/login", json={"email": "bob@example.com", "password": "wrong"})
    assert r.status_code == 429


def test_ratelimit_password_reset_trigger(monkeypatch):
    for _ in range(4):
        r = client.post("/auth/forgot-password", params={"email": "a@example.com"})
    assert r.status_code == 200

    monkeypatch.setenv("TRACEBENCH_PATCH_RATELIMIT_PASSWORD_RESET_TRIGGER", "1")
    for _ in range(4):
        r = client.post("/auth/forgot-password", params={"email": "z@example.com"})
    assert r.status_code == 429


def test_ratelimit_expensive_search(monkeypatch):
    for _ in range(11):
        r = client.get("/patients/search", params={"q": "a"}, headers={"X-Client-Id": "c1"})
    assert r.status_code == 200

    monkeypatch.setenv("TRACEBENCH_PATCH_RATELIMIT_EXPENSIVE_SEARCH", "1")
    for _ in range(11):
        r = client.get("/patients/search", params={"q": "a"}, headers={"X-Client-Id": "c2"})
    assert r.status_code == 429


def test_ratelimit_signup_spam(monkeypatch):
    for i in range(4):
        r = client.post(
            "/auth/signup",
            json={"email": f"x{i}@example.com", "password": "p"},
            headers={"X-Forwarded-For": "1.1.1.1"},
        )
    assert r.status_code == 200

    monkeypatch.setenv("TRACEBENCH_PATCH_RATELIMIT_SIGNUP_SPAM", "1")
    for i in range(4):
        r = client.post(
            "/auth/signup",
            json={"email": f"y{i}@example.com", "password": "p"},
            headers={"X-Forwarded-For": "2.2.2.2"},
        )
    assert r.status_code == 429


def test_ratelimit_decoy_already_protected():
    for _ in range(4):
        r = client.post("/support/contact", params={"message": "hi"})
    assert r.status_code == 429


def test_ratelimit_decoy_unlimited_by_design():
    for _ in range(20):
        r = client.get("/health")
    assert r.status_code == 200
