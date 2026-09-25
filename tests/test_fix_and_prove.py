"""
Unit tests for tracesec.fix_and_prove: end-to-end pre/post-patch
verification against TRACE-Bench's real FastAPI app, run as a genuine
live server in a background thread for the duration of each test
(rather than a mock transport), since fix_and_prove exists
specifically to exercise the real TRACEBENCH_PATCH_* toggle mechanism
the same way TRACE would talk to any other live target.
"""

import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
import uvicorn

sys.path.insert(0, str(Path(__file__).parent.parent / "bench"))

from tracebench.main import app as tracebench_app
from tracebench.main import reset_data

from tracesec.evidence import EvidenceStore
from tracesec.executor import Executor
from tracesec.fix_and_prove import RegressionCheckFailed, run_fix_and_prove
from tracesec.scope import ScopedClient, ScopeGuard
from tracesec.sessions import Identity, Role
from tracesec.verifier import verify_bola

# TRACE-Bench seeds patient 2 as owned by user_id=2 (see
# bench/tracebench/main.py _SEED_PATIENTS), and all tests below query
# /patients/2 -- so OWNER must carry user 2's identity to actually be
# the resource's owner, with OTHER as an unrelated identity.
OWNER = Identity(label="owner", role=Role.USER, headers={"X-User-Id": "2"})
OTHER = Identity(label="other", role=Role.USER, headers={"X-User-Id": "1"})


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def tracebench_base_url() -> Iterator[str]:
    """Run TRACE-Bench's real app as a live server on an OS-assigned
    free port, in a background thread, for one test's duration."""
    port = _free_port()
    config = uvicorn.Config(tracebench_app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.monotonic() + 5.0
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started, "TRACE-Bench test server did not start in time"

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=5.0)


@pytest.fixture(autouse=True)
def _reset_tracebench():
    reset_data()
    yield
    reset_data()


def _executor(tmp_path):
    guard = ScopeGuard({"127.0.0.1"})
    client = ScopedClient(guard)
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    return Executor(client, evidence, session_id="fix-and-prove")


def test_fix_and_prove_confirms_bola_regression_on_tracebench(tracebench_base_url, tmp_path):
    executor = _executor(tmp_path)
    url = f"{tracebench_base_url}/patients/2"

    def verify(ex):
        return verify_bola(
            ex,
            url,
            "GET",
            OWNER,
            OTHER,
            finding_id="bola-direct-path",
            endpoint="/patients/{patient_id}",
        )

    result = run_fix_and_prove(
        "bola_direct_path", "TRACEBENCH_PATCH_BOLA_DIRECT_PATH", verify, executor
    )

    assert result.regression_confirmed is True
    assert result.pre_patch_finding.verdict.value == "confirmed"
    assert result.post_patch_finding.verdict.value == "refuted"


def test_fix_and_prove_restores_env_var_after_success(tracebench_base_url, tmp_path, monkeypatch):
    monkeypatch.delenv("TRACEBENCH_PATCH_BOLA_DIRECT_PATH", raising=False)
    executor = _executor(tmp_path)
    url = f"{tracebench_base_url}/patients/2"

    def verify(ex):
        return verify_bola(
            ex,
            url,
            "GET",
            OWNER,
            OTHER,
            finding_id="bola-direct-path",
            endpoint="/patients/{patient_id}",
        )

    run_fix_and_prove("bola_direct_path", "TRACEBENCH_PATCH_BOLA_DIRECT_PATH", verify, executor)

    import os

    assert "TRACEBENCH_PATCH_BOLA_DIRECT_PATH" not in os.environ


def test_fix_and_prove_raises_if_no_regression_observed(tracebench_base_url, tmp_path):
    """Wired to a scenario name that does not exist, so the toggle env
    var never actually changes this endpoint's behavior and both
    passes stay CONFIRMED -- this must raise, not silently succeed."""
    executor = _executor(tmp_path)
    url = f"{tracebench_base_url}/patients/2"

    def verify(ex):
        return verify_bola(
            ex,
            url,
            "GET",
            OWNER,
            OTHER,
            finding_id="bola-direct-path",
            endpoint="/patients/{patient_id}",
        )

    with pytest.raises(RegressionCheckFailed):
        run_fix_and_prove(
            "bola_direct_path", "TRACEBENCH_PATCH_NONEXISTENT_SCENARIO", verify, executor
        )
