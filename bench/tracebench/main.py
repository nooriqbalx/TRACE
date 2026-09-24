"""
TRACE-Bench: a small, deliberately vulnerable/patched FastAPI app used as a
labeled benchmark for TRACE's automated verifier.

Toggle a scenario's behavior with an environment variable, e.g.:
    TRACEBENCH_PATCH_BOLA_DIRECT_PATH=1 uvicorn tracebench.main:app --reload

Authentication is simplified to an X-User-Id header (no real login flow)
for scenarios that are not specifically testing broken authentication.
Broken-authentication scenarios use a simplified real token flow.
"""

import os
import secrets
import time
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="TRACE-Bench", version="0.2.0")


def is_patched(flag: str) -> bool:
    """Read a per-scenario patch toggle from the environment."""
    return os.getenv(f"TRACEBENCH_PATCH_{flag}", "0") == "1"


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

_SEED_PATIENTS: dict[int, dict[str, Any]] = {
    1: {
        "id": 1,
        "name": "Alice Patient",
        "owner_user_id": 1,
        "medical_note": "Canary-A: routine checkup, no issues.",
        "phone": "+10000000001",
        "national_id": "NID-CANARY-A-0001",
        "is_test_account": True,
        "internal_risk_score": 12,
    },
    2: {
        "id": 2,
        "name": "Bob Patient",
        "owner_user_id": 2,
        "medical_note": "Canary-B: follow-up required in 3 months.",
        "phone": "+10000000002",
        "national_id": "NID-CANARY-B-0002",
        "is_test_account": True,
        "internal_risk_score": 47,
    },
}

_SEED_APPOINTMENTS: dict[int, dict[str, Any]] = {
    1: {"id": 1, "patient_id": 1, "doctor_id": 1, "notes": "Canary-A appointment"},
    2: {"id": 2, "patient_id": 2, "doctor_id": 1, "notes": "Canary-B appointment"},
}

_SEED_DOCTORS: dict[int, dict[str, Any]] = {
    1: {"id": 1, "name": "Dr. Jane Smith", "specialty": "General Practice"},
}

_SEED_USERS: dict[int, dict[str, Any]] = {
    1: {"id": 1, "email": "alice@example.com", "password": "correct-horse-1"},
    2: {"id": 2, "email": "bob@example.com", "password": "correct-horse-2"},
}

patients: dict[int, dict[str, Any]] = {}
appointments: dict[int, dict[str, Any]] = {}
doctors: dict[int, dict[str, Any]] = {}
users: dict[int, dict[str, Any]] = {}

sessions: dict[str, dict[str, Any]] = {}
otp_state: dict[str, dict[str, Any]] = {}
reset_tokens: dict[str, dict[str, Any]] = {}
_rate_log: dict[str, list[float]] = {}


def reset_data() -> None:
    global patients, appointments, doctors, users
    patients = {k: dict(v) for k, v in _SEED_PATIENTS.items()}
    appointments = {k: dict(v) for k, v in _SEED_APPOINTMENTS.items()}
    doctors = {k: dict(v) for k, v in _SEED_DOCTORS.items()}
    users = {k: dict(v) for k, v in _SEED_USERS.items()}
    sessions.clear()
    otp_state.clear()
    reset_tokens.clear()
    _rate_log.clear()


reset_data()


def rate_limited(key: str, flag: str, limit: int = 5, window_seconds: float = 60.0) -> bool:
    """Record a call; return True only if patched AND over the limit."""
    now = time.time()
    calls = _rate_log.setdefault(key, [])
    calls[:] = [t for t in calls if now - t < window_seconds]
    calls.append(now)
    return is_patched(flag) and len(calls) > limit


def rate_limited_always(key: str, limit: int = 5, window_seconds: float = 60.0) -> bool:
    """Rate limiting that is always enforced, used for decoy scenarios."""
    now = time.time()
    calls = _rate_log.setdefault(key, [])
    calls[:] = [t for t in calls if now - t < window_seconds]
    calls.append(now)
    return len(calls) > limit


@app.post("/admin/reset", tags=["admin"])
def admin_reset() -> dict[str, str]:
    reset_data()
    return {"status": "reset"}


# ---------------------------------------------------------------------------
# NOTE ON ROUTE ORDERING: literal paths (e.g. /patients/search) must be
# declared BEFORE parameterized paths that could shadow them
# (e.g. /patients/{patient_id}), since Starlette matches routes in
# declaration order. /patients/search is therefore declared here, ahead
# of the BOLA section below, even though it belongs to the rate-limiting
# scenario group.
# ---------------------------------------------------------------------------


@app.get("/patients/search", tags=["ratelimit-expensive-search"])
def search_patients(q: str, x_client_id: str = Header(default="anon")) -> dict[str, Any]:
    if rate_limited(f"search:{x_client_id}", "RATELIMIT_EXPENSIVE_SEARCH", limit=10):
        raise HTTPException(status_code=429, detail="Too many requests")
    results = [p for p in patients.values() if q.lower() in p["name"].lower()]
    return {"results": results}


# ===========================================================================
# BOLA (6 scenarios)
# ===========================================================================


@app.get("/patients/{patient_id}", tags=["bola-direct-path"])
def get_patient(patient_id: int, x_user_id: int | None = Header(default=None)) -> dict[str, Any]:
    patient = patients.get(patient_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")
    if is_patched("BOLA_DIRECT_PATH") and (
        x_user_id is None or x_user_id != patient["owner_user_id"]
    ):
        raise HTTPException(status_code=403, detail="Forbidden")
    return patient


class PatientLookupRequest(BaseModel):
    patient_id: int


@app.post("/patients/lookup", tags=["bola-body-id"])
def lookup_patient(
    body: PatientLookupRequest, x_user_id: int | None = Header(default=None)
) -> dict[str, Any]:
    patient = patients.get(body.patient_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")
    if is_patched("BOLA_BODY_ID") and (x_user_id is None or x_user_id != patient["owner_user_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")
    return patient


@app.get("/appointments/{appointment_id}", tags=["bola-related-object"])
def get_appointment(
    appointment_id: int, x_user_id: int | None = Header(default=None)
) -> dict[str, Any]:
    appt = appointments.get(appointment_id)
    if appt is None:
        raise HTTPException(status_code=404, detail="Appointment not found")
    patient = patients.get(appt["patient_id"])
    owner_id = patient["owner_user_id"] if patient else None
    if is_patched("BOLA_RELATED_OBJECT") and (x_user_id is None or x_user_id != owner_id):
        raise HTTPException(status_code=403, detail="Forbidden")
    note = patient["medical_note"] if patient else None
    return {**appt, "patient_medical_note": note}


class UpdateNoteRequest(BaseModel):
    medical_note: str


@app.put("/patients/{patient_id}/notes", tags=["bola-write-access"])
def update_patient_note(
    patient_id: int,
    body: UpdateNoteRequest,
    x_user_id: int | None = Header(default=None),
) -> dict[str, Any]:
    patient = patients.get(patient_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")
    if is_patched("BOLA_WRITE_ACCESS") and (
        x_user_id is None or x_user_id != patient["owner_user_id"]
    ):
        raise HTTPException(status_code=403, detail="Forbidden")
    patient["medical_note"] = body.medical_note
    return patient


@app.get("/patients/{patient_id}/billing", tags=["bola-decoy-protected"])
def get_patient_billing(
    patient_id: int, x_user_id: int | None = Header(default=None)
) -> dict[str, Any]:
    """Decoy: always ownership-checked in every build. Not a real finding."""
    patient = patients.get(patient_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")
    if x_user_id is None or x_user_id != patient["owner_user_id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return {"patient_id": patient_id, "balance_due": 0.0}


@app.get("/doctors/{doctor_id}", tags=["bola-decoy-public"])
def get_doctor(doctor_id: int) -> dict[str, Any]:
    """Decoy: intentionally public in every build. Not a real finding."""
    doctor = doctors.get(doctor_id)
    if doctor is None:
        raise HTTPException(status_code=404, detail="Doctor not found")
    return doctor


# ===========================================================================
# Broken Authentication (6 scenarios)
# ===========================================================================


@app.post("/auth/request-otp", tags=["authn-otp-bruteforce"])
def request_otp(email: str) -> dict[str, str]:
    otp_state[email] = {"code": "1234", "attempts": 0}
    return {"status": "otp sent"}


class VerifyOtpRequest(BaseModel):
    email: str
    otp: str


@app.post("/auth/verify-otp", tags=["authn-otp-bruteforce"])
def verify_otp(body: VerifyOtpRequest) -> dict[str, str]:
    state = otp_state.get(body.email)
    if state is None:
        raise HTTPException(status_code=400, detail="No OTP requested")
    if is_patched("AUTHN_OTP_BRUTEFORCE") and state["attempts"] >= 5:
        raise HTTPException(status_code=429, detail="Too many attempts")
    state["attempts"] += 1
    if body.otp != state["code"]:
        raise HTTPException(status_code=401, detail="Invalid OTP")
    return {"status": "verified"}


@app.post("/auth/login-predictable", tags=["authn-predictable-token"])
def login_predictable(user_id: int) -> dict[str, str]:
    if is_patched("AUTHN_PREDICTABLE_TOKEN"):
        token = secrets.token_urlsafe(32)
    else:
        token = f"session-{user_id}"
    sessions[token] = {"user_id": user_id, "issued_at": time.time()}
    return {"token": token}


@app.get("/me", tags=["authn-predictable-token"])
def get_me(x_session_token: str | None = Header(default=None)) -> dict[str, Any]:
    session = sessions.get(x_session_token or "")
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid session")
    return {"user_id": session["user_id"]}


@app.post("/auth/login-session", tags=["authn-token-no-expiry"])
def login_session(user_id: int) -> dict[str, str]:
    token = secrets.token_urlsafe(16)
    sessions[token] = {"user_id": user_id, "issued_at": time.time()}
    return {"token": token}


@app.get("/me/expiring", tags=["authn-token-no-expiry"])
def get_me_expiring(x_session_token: str | None = Header(default=None)) -> dict[str, Any]:
    session = sessions.get(x_session_token or "")
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid session")
    if is_patched("AUTHN_TOKEN_NO_EXPIRY"):
        age = time.time() - session["issued_at"]
        if age > 5:
            raise HTTPException(status_code=401, detail="Session expired")
    return {"user_id": session["user_id"]}


@app.post("/auth/request-reset", tags=["authn-reset-token-reuse"])
def request_reset(email: str) -> dict[str, str]:
    token = secrets.token_urlsafe(8)
    reset_tokens[token] = {"email": email, "used": False}
    return {"token": token}


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


@app.post("/auth/reset-password", tags=["authn-reset-token-reuse"])
def reset_password(body: ResetPasswordRequest) -> dict[str, str]:
    record = reset_tokens.get(body.token)
    if record is None:
        raise HTTPException(status_code=400, detail="Invalid token")
    if is_patched("AUTHN_RESET_TOKEN_REUSE") and record["used"]:
        raise HTTPException(status_code=400, detail="Token already used")
    record["used"] = True
    return {"status": "password reset"}


@app.post("/auth/login-protected", tags=["authn-decoy-rate-limited"])
def login_protected(email: str) -> dict[str, str]:
    """Decoy: always rate-limited in every build. Not a real finding."""
    if rate_limited_always(f"login-protected:{email}", limit=5):
        raise HTTPException(status_code=429, detail="Too many attempts")
    return {"status": "attempted"}


@app.get("/auth/status", tags=["authn-decoy-public"])
def auth_status() -> dict[str, str]:
    """Decoy: intentionally public in every build. Not a real finding."""
    return {"status": "ok"}


# ===========================================================================
# Excessive Data Exposure (6 scenarios)
# ===========================================================================


@app.get("/patients/{patient_id}/profile", tags=["exposure-extra-pii-fields"])
def get_patient_profile(patient_id: int) -> dict[str, Any]:
    patient = patients.get(patient_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")
    if is_patched("EXPOSURE_EXTRA_PII_FIELDS"):
        return {"id": patient["id"], "name": patient["name"]}
    return dict(patient)


@app.get("/patients/{patient_id}/risk-score", tags=["exposure-stack-trace"])
def get_risk_score(patient_id: int, divisor: int = 1) -> dict[str, Any]:
    patient = patients.get(patient_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")
    try:
        score = patient["internal_risk_score"] / divisor
    except ZeroDivisionError as exc:
        if is_patched("EXPOSURE_STACK_TRACE"):
            raise HTTPException(status_code=400, detail="Invalid request") from exc
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"risk_score": score}


@app.get("/patients", tags=["exposure-list-leaks-others"])
def list_patients(
    mine: bool = False, x_user_id: int | None = Header(default=None)
) -> list[dict[str, Any]]:
    if mine and is_patched("EXPOSURE_LIST_LEAKS_OTHERS"):
        return [p for p in patients.values() if p["owner_user_id"] == x_user_id]
    # Vulnerable build: 'mine' is silently ignored, returns everyone.
    return list(patients.values())


@app.get("/patients/{patient_id}/full", tags=["exposure-admin-flags"])
def get_patient_full(patient_id: int) -> dict[str, Any]:
    patient = patients.get(patient_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")
    if is_patched("EXPOSURE_ADMIN_FLAGS"):
        return {
            k: v for k, v in patient.items() if k not in ("is_test_account", "internal_risk_score")
        }
    return dict(patient)


@app.get("/me/profile", tags=["exposure-decoy-own-profile"])
def get_my_profile(x_user_id: int | None = Header(default=None)) -> dict[str, Any]:
    """Decoy: full own-record access is correct in every build."""
    if x_user_id is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    patient = patients.get(x_user_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")
    return dict(patient)


@app.get("/doctors", tags=["exposure-decoy-public-directory"])
def list_doctors() -> list[dict[str, Any]]:
    """Decoy: public directory info, correct in every build."""
    return list(doctors.values())


# ===========================================================================
# Rate Limiting (6 scenarios; /patients/search is declared above, near the
# top of the file, due to the route-ordering constraint noted there)
# ===========================================================================


class LoginRequest(BaseModel):
    email: str
    password: str


@app.post("/auth/login", tags=["ratelimit-login-bruteforce"])
def login(body: LoginRequest) -> dict[str, str]:
    if rate_limited(f"login:{body.email}", "RATELIMIT_LOGIN_BRUTEFORCE", limit=5):
        raise HTTPException(status_code=429, detail="Too many attempts")
    user = next((u for u in users.values() if u["email"] == body.email), None)
    if user is None or user["password"] != body.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"status": "logged in"}


@app.post("/auth/forgot-password", tags=["ratelimit-password-reset-trigger"])
def forgot_password(email: str) -> dict[str, str]:
    if rate_limited(f"forgot:{email}", "RATELIMIT_PASSWORD_RESET_TRIGGER", limit=3):
        raise HTTPException(status_code=429, detail="Too many requests")
    return {"status": "reset email sent"}


class SignupRequest(BaseModel):
    email: str
    password: str


@app.post("/auth/signup", tags=["ratelimit-signup-spam"])
def signup(body: SignupRequest, x_forwarded_for: str = Header(default="unset")) -> dict[str, str]:
    if rate_limited(f"signup:{x_forwarded_for}", "RATELIMIT_SIGNUP_SPAM", limit=3):
        raise HTTPException(status_code=429, detail="Too many signups")
    new_id = max(users.keys(), default=0) + 1
    users[new_id] = {"id": new_id, "email": body.email, "password": body.password}
    return {"status": "account created", "id": str(new_id)}


@app.post("/support/contact", tags=["ratelimit-decoy-already-protected"])
def contact_support(message: str) -> dict[str, str]:
    """Decoy: always rate-limited in every build. Not a real finding."""
    if rate_limited_always("support-contact", limit=3):
        raise HTTPException(status_code=429, detail="Too many requests")
    return {"status": "message received"}


@app.get("/health", tags=["ratelimit-decoy-unlimited-by-design"])
def health() -> dict[str, str]:
    """Decoy: health checks must never be rate-limited. Not a real finding."""
    return {"status": "ok"}
