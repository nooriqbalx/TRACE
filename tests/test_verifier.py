"""
Unit tests for tracesec.verifier: configuration C5's deterministic
oracles. Each handler below deliberately mirrors a real TRACE-Bench
scenario's behavior (vulnerable and patched) via httpx.MockTransport,
so these tests double as documentation of exactly what each oracle
is meant to catch.
"""

import httpx

from tracesec.evidence import EvidenceStore
from tracesec.executor import Executor
from tracesec.findings import Finding, VerifierVerdict, VulnerabilityClass
from tracesec.scope import ScopedClient, ScopeGuard
from tracesec.sessions import Identity, Role
from tracesec.verifier import check_regression, verify_bola, verify_exposure, verify_unthrottled

OWNER = Identity(label="owner", role=Role.USER, headers={"X-User-Id": "1"})
OTHER = Identity(label="other", role=Role.USER, headers={"X-User-Id": "2"})


def _executor(handler, tmp_path):
    guard = ScopeGuard({"good.test"})
    client = ScopedClient(guard, transport=httpx.MockTransport(handler))
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    return Executor(client, evidence, session_id="verifier"), evidence


def test_verify_bola_confirmed_when_no_ownership_check(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "medical_note": "secret"})

    executor, evidence = _executor(handler, tmp_path)
    finding = verify_bola(
        executor,
        "https://good.test/patients/1",
        "GET",
        OWNER,
        OTHER,
        finding_id="f1",
        endpoint="/patients/{id}",
    )
    assert finding.verdict == VerifierVerdict.CONFIRMED
    assert finding.vuln_class == VulnerabilityClass.BOLA
    assert evidence.verify_chain()


def test_verify_bola_refuted_when_ownership_enforced(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("x-user-id") == "1":
            return httpx.Response(200, json={"id": 1})
        return httpx.Response(403, json={"detail": "Forbidden"})

    executor, _ = _executor(handler, tmp_path)
    finding = verify_bola(
        executor,
        "https://good.test/patients/1",
        "GET",
        OWNER,
        OTHER,
        finding_id="f2",
        endpoint="/patients/{id}",
    )
    assert finding.verdict == VerifierVerdict.REFUTED


def test_verify_bola_inconclusive_when_owner_baseline_fails(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500)

    executor, _ = _executor(handler, tmp_path)
    finding = verify_bola(
        executor,
        "https://good.test/patients/1",
        "GET",
        OWNER,
        OTHER,
        finding_id="f3",
        endpoint="/patients/{id}",
    )
    assert finding.verdict == VerifierVerdict.INCONCLUSIVE


def test_verify_bola_regression_flips_confirmed_to_refuted(tmp_path):
    def vulnerable_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1})

    def patched_handler(request: httpx.Request) -> httpx.Response:
        if request.headers.get("x-user-id") == "1":
            return httpx.Response(200, json={"id": 1})
        return httpx.Response(403)

    pre_executor, _ = _executor(vulnerable_handler, tmp_path)
    pre = verify_bola(
        pre_executor,
        "https://good.test/patients/1",
        "GET",
        OWNER,
        OTHER,
        finding_id="pre",
        endpoint="/patients/{id}",
    )

    post_executor, _ = _executor(patched_handler, tmp_path)
    post = verify_bola(
        post_executor,
        "https://good.test/patients/1",
        "GET",
        OWNER,
        OTHER,
        finding_id="post",
        endpoint="/patients/{id}",
    )

    assert check_regression(pre, post) is True


def test_verify_unthrottled_confirmed_when_never_rate_limited(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "Invalid OTP"})

    executor, _ = _executor(handler, tmp_path)

    def attempt():
        return executor.post("https://good.test/auth/verify-otp", json={"otp": "0000"})

    finding = verify_unthrottled(
        attempt,
        max_attempts=10,
        vuln_class=VulnerabilityClass.BROKEN_AUTHENTICATION,
        finding_id="f4",
        endpoint="/auth/verify-otp",
        method="POST",
    )
    assert finding.verdict == VerifierVerdict.CONFIRMED
    assert len(finding.evidence_ids) == 10


def test_verify_unthrottled_refuted_when_rate_limited(tmp_path):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        if calls["count"] > 3:
            return httpx.Response(429)
        return httpx.Response(401)

    executor, _ = _executor(handler, tmp_path)

    def attempt():
        return executor.post("https://good.test/auth/login", json={"password": "wrong"})

    finding = verify_unthrottled(
        attempt,
        max_attempts=10,
        vuln_class=VulnerabilityClass.RATE_LIMITING,
        finding_id="f5",
        endpoint="/auth/login",
        method="POST",
    )
    assert finding.verdict == VerifierVerdict.REFUTED
    assert len(finding.evidence_ids) == 4


def test_verify_unthrottled_respects_max_attempts_cap(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    executor, _ = _executor(handler, tmp_path)
    call_count = {"n": 0}

    def attempt():
        call_count["n"] += 1
        return executor.get("https://good.test/health")

    verify_unthrottled(
        attempt,
        max_attempts=5,
        vuln_class=VulnerabilityClass.RATE_LIMITING,
        finding_id="f6",
        endpoint="/health",
        method="GET",
    )
    assert call_count["n"] == 5


def test_verify_exposure_confirmed_when_disallowed_field_present(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "name": "Alice", "national_id": "NID-1"})

    executor, _ = _executor(handler, tmp_path)
    finding = verify_exposure(
        executor,
        "https://good.test/patients/1/profile",
        "GET",
        OWNER,
        disallowed_fields={"national_id", "phone"},
        finding_id="f7",
        endpoint="/patients/{id}/profile",
    )
    assert finding.verdict == VerifierVerdict.CONFIRMED
    assert "national_id" in finding.verifier_notes


def test_verify_exposure_refuted_when_fields_filtered(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1, "name": "Alice"})

    executor, _ = _executor(handler, tmp_path)
    finding = verify_exposure(
        executor,
        "https://good.test/patients/1/profile",
        "GET",
        OWNER,
        disallowed_fields={"national_id", "phone"},
        finding_id="f8",
        endpoint="/patients/{id}/profile",
    )
    assert finding.verdict == VerifierVerdict.REFUTED


def test_verify_exposure_inconclusive_on_non_json_body(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="not json")

    executor, _ = _executor(handler, tmp_path)
    finding = verify_exposure(
        executor,
        "https://good.test/patients/1/profile",
        "GET",
        OWNER,
        disallowed_fields={"national_id"},
        finding_id="f9",
        endpoint="/patients/{id}/profile",
    )
    assert finding.verdict == VerifierVerdict.INCONCLUSIVE


def test_check_regression_false_if_verdicts_dont_flip_correctly():
    a = Finding(
        finding_id="a",
        vuln_class=VulnerabilityClass.BOLA,
        endpoint="/x",
        method="GET",
        claim="c",
        evidence_ids=[0],
        verdict=VerifierVerdict.CONFIRMED,
    )
    b = Finding(
        finding_id="b",
        vuln_class=VulnerabilityClass.BOLA,
        endpoint="/x",
        method="GET",
        claim="c",
        evidence_ids=[0],
        verdict=VerifierVerdict.CONFIRMED,
    )
    assert check_regression(a, b) is False


def test_check_regression_false_for_different_endpoints():
    a = Finding(
        finding_id="a",
        vuln_class=VulnerabilityClass.BOLA,
        endpoint="/x",
        method="GET",
        claim="c",
        evidence_ids=[0],
        verdict=VerifierVerdict.CONFIRMED,
    )
    b = Finding(
        finding_id="b",
        vuln_class=VulnerabilityClass.BOLA,
        endpoint="/y",
        method="GET",
        claim="c",
        evidence_ids=[0],
        verdict=VerifierVerdict.REFUTED,
    )
    assert check_regression(a, b) is False
