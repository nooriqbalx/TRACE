"""
TRACE-Bench: a small, deliberately vulnerable/patched FastAPI app used as a
labeled benchmark for TRACE's automated verifier.

Toggle a scenario's behavior with an environment variable, e.g.:
    TRACEBENCH_PATCH_BOLA_DIRECT_PATH=1 uvicorn tracebench.main:app --reload

Authentication is simplified to an X-User-Id header (no real login flow)
for scenarios that are not specifically testing broken authentication.
Broken-authentication scenarios, added separately, use a real token flow.
"""

import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

app = FastAPI(title="TRACE-Bench", version="0.1.0")


def is_patched(flag: str) -> bool:
    """Read a per-scenario patch toggle from the environment.

    Each vulnerable/patched pair is controlled by its own flag so
    scenarios can be flipped independently, one at a time, while
    building ground truth.
    """
    return os.getenv(f"TRACEBENCH_PATCH_{flag}", "0") == "1"


# ---------------------------------------------------------------------------
# In-memory data store (reset with POST /admin/reset)
# ---------------------------------------------------------------------------

_SEED_PATIENTS = {
    1: {
        "id": 1,
        "name": "Alice Patient",
        "owner_user_id": 1,
        "medical_note": "Canary-A: routine checkup, no issues.",
    },
    2: {
        "id": 2,
        "name": "Bob Patient",
        "owner_user_id": 2,
        "medical_note": "Canary-B: follow-up required in 3 months.",
    },
}

patients: dict[int, dict[str, object]] = {}


def reset_data() -> None:
    global patients
    patients = {k: dict(v) for k, v in _SEED_PATIENTS.items()}


reset_data()


@app.post("/admin/reset", tags=["admin"])
def admin_reset() -> dict[str, str]:
    """Reset all TRACE-Bench data to its seeded state. Call this between
    scanner runs so every run starts from identical, known ground truth."""
    reset_data()
    return {"status": "reset"}


# ---------------------------------------------------------------------------
# BOLA scenario: direct path-parameter ID
#
# Ground truth: GET /patients/{id} with an X-User-Id header that does not
# match the patient's owner must be rejected. The vulnerable build returns
# the record regardless of the caller's identity, matching the exact bug
# confirmed manually on crAPI's vehicle-location endpoint.
# ---------------------------------------------------------------------------


@app.get("/patients/{patient_id}", tags=["bola-direct-path"])
def get_patient(patient_id: int, x_user_id: int | None = Header(default=None)) -> dict[str, object]:
    patient = patients.get(patient_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")

    if is_patched("BOLA_DIRECT_PATH") and (
        x_user_id is None or x_user_id != patient["owner_user_id"]
    ):
        raise HTTPException(status_code=403, detail="Forbidden")

    return patient


# ---------------------------------------------------------------------------
# BOLA scenario: ID inside JSON request body (not the URL path)
#
# Same underlying bug as bola_direct_path, but the identifier arrives in
# a POST body field instead of a path parameter. Included because some
# scanners only inspect path/query parameters for BOLA and miss
# body-based identifiers entirely, a real gap this benchmark should catch.
# ---------------------------------------------------------------------------


class PatientLookupRequest(BaseModel):
    patient_id: int


@app.post("/patients/lookup", tags=["bola-body-id"])
def lookup_patient(
    body: PatientLookupRequest, x_user_id: int | None = Header(default=None)
) -> dict[str, object]:
    patient = patients.get(body.patient_id)
    if patient is None:
        raise HTTPException(status_code=404, detail="Patient not found")

    if is_patched("BOLA_BODY_ID") and (x_user_id is None or x_user_id != patient["owner_user_id"]):
        raise HTTPException(status_code=403, detail="Forbidden")

    return patient
