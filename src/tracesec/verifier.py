"""
tracesec.verifier

Configuration C5: independent, deterministic verification of a
suspected vulnerability. No LLM is involved anywhere in this module --
every oracle here reaches its verdict purely by executing real
requests (through tracesec.executor.Executor, which is itself
scope-guarded and evidence-logging) and comparing real responses. This
is what makes C5 resistant to exactly the failure mode C2 and C4
cannot avoid on their own: an LLM (or a human) being wrong about
whether a claim is true. The oracle either observes the vulnerability
happen, or it does not.

Each oracle below generalizes a pattern already exercised by hand in
this project: verify_bola mirrors the manual crAPI vehicle-location
and mechanic-report tests (docs/lab/crapi-manual-notes.md) and
TRACE-Bench's bola_* scenarios; verify_unthrottled mirrors the manual
OTP brute-force test (docs/lab/crapi-manual-notes.md,
"Broken Authentication") and TRACE-Bench's authn_otp_bruteforce /
ratelimit_* scenarios; verify_exposure mirrors
exposure_extra_pii_fields.

Verdicts (see tracesec.findings.VerifierVerdict):
- CONFIRMED: the oracle observed the vulnerable behavior directly.
- REFUTED: the oracle observed the endpoint correctly rejecting the
  attack (e.g. a 403 on cross-identity access, or a 429 within the
  request budget).
- INCONCLUSIVE: the oracle could not establish a clean baseline (e.g.
  even the legitimate owner's request failed), so no verdict about the
  vulnerability itself can be drawn from this run.

Safety: verify_unthrottled takes an explicit max_attempts cap and is
the only oracle that sends more than a couple of requests, per
THREAT_MODEL.md T6 (accidental DoS) and RESPONSIBLE_USE.md. It never
sends unbounded traffic; the caller decides the cap.
"""

import json
from collections.abc import Callable
from typing import Any

from tracesec.executor import ExecutionResult, Executor
from tracesec.findings import Finding, VerifierVerdict, VulnerabilityClass
from tracesec.sessions import Identity


def verify_bola(
    executor: Executor,
    url: str,
    method: str,
    owner: Identity,
    other: Identity,
    *,
    finding_id: str,
    endpoint: str,
) -> Finding:
    """Differential BOLA oracle. Sends the same request twice: once as
    the resource's legitimate owner (the baseline/negative control),
    once as a different, unrelated identity (the actual attack).

    CONFIRMED: the owner's request succeeds AND the other identity's
    request also succeeds (2xx) -- no ownership check exists.
    REFUTED: the owner's request succeeds but the other identity's is
    rejected (401/403) -- ownership is correctly enforced.
    INCONCLUSIVE: even the owner's baseline request did not succeed,
    so no conclusion about ownership enforcement can be drawn.
    """
    owner_result = executor.request(method, url, headers=dict(owner.headers))
    other_result = executor.request(method, url, headers=dict(other.headers))

    evidence_ids = [owner_result.evidence.index, other_result.evidence.index]
    owner_ok = 200 <= owner_result.response.status_code < 300
    other_ok = 200 <= other_result.response.status_code < 300

    if not owner_ok:
        verdict = VerifierVerdict.INCONCLUSIVE
        notes = (
            f"owner baseline request returned {owner_result.response.status_code}; "
            "cannot establish a clean baseline"
        )
    elif other_ok:
        verdict = VerifierVerdict.CONFIRMED
        notes = (
            f"owner request: {owner_result.response.status_code}; "
            f"other-identity request: {other_result.response.status_code} "
            "(no ownership check observed)"
        )
    else:
        verdict = VerifierVerdict.REFUTED
        notes = (
            f"owner request: {owner_result.response.status_code}; "
            f"other-identity request: {other_result.response.status_code} "
            "(ownership correctly enforced)"
        )

    return Finding(
        finding_id=finding_id,
        vuln_class=VulnerabilityClass.BOLA,
        endpoint=endpoint,
        method=method,
        claim=f"cross-identity access to {endpoint}",
        evidence_ids=evidence_ids,
        verdict=verdict,
        verifier_notes=notes,
    )


def verify_unthrottled(
    attempt: Callable[[], ExecutionResult],
    max_attempts: int,
    vuln_class: VulnerabilityClass,
    *,
    finding_id: str,
    endpoint: str,
    method: str,
) -> Finding:
    """Bounded-burst oracle for broken-authentication (e.g. OTP or
    login guessing) and rate-limiting checks -- structurally the same
    test, capped at max_attempts requests, per THREAT_MODEL.md T6.

    CONFIRMED: max_attempts requests were sent and none received a 429
    -- no throttling observed within the budget.
    REFUTED: a 429 was received before the cap was reached --
    throttling is enforced.

    `attempt` is a zero-argument callable the caller constructs to
    perform one request (e.g. a closure over a changing OTP guess or
    a fixed wrong password); it must return an ExecutionResult so this
    oracle can read the response status and cite the evidence record.
    """
    evidence_ids: list[int] = []
    for i in range(max_attempts):
        result = attempt()
        evidence_ids.append(result.evidence.index)
        if result.response.status_code == 429:
            return Finding(
                finding_id=finding_id,
                vuln_class=vuln_class,
                endpoint=endpoint,
                method=method,
                claim=f"unthrottled requests to {endpoint}",
                evidence_ids=evidence_ids,
                verdict=VerifierVerdict.REFUTED,
                verifier_notes=f"received 429 after {i + 1} attempt(s); throttling enforced",
            )

    return Finding(
        finding_id=finding_id,
        vuln_class=vuln_class,
        endpoint=endpoint,
        method=method,
        claim=f"unthrottled requests to {endpoint}",
        evidence_ids=evidence_ids,
        verdict=VerifierVerdict.CONFIRMED,
        verifier_notes=f"no 429 within {max_attempts} attempts; no throttling observed",
    )


def verify_exposure(
    executor: Executor,
    url: str,
    method: str,
    identity: Identity,
    disallowed_fields: set[str],
    *,
    finding_id: str,
    endpoint: str,
) -> Finding:
    """Excessive-data-exposure oracle: fetch the endpoint as a
    legitimate identity and check the response for fields the caller
    has declared should never appear (e.g. an internal risk score, a
    national ID, another party's PII).

    CONFIRMED: at least one disallowed field is present in the
    response body.
    REFUTED: none of the disallowed fields are present.
    INCONCLUSIVE: the response body is not a JSON object, so no field
    check could be performed.
    """
    result = executor.request(method, url, headers=dict(identity.headers))
    evidence_ids = [result.evidence.index]

    try:
        body: Any = json.loads(result.response.text)
    except ValueError, TypeError:
        return Finding(
            finding_id=finding_id,
            vuln_class=VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE,
            endpoint=endpoint,
            method=method,
            claim=f"response fields exposed by {endpoint}",
            evidence_ids=evidence_ids,
            verdict=VerifierVerdict.INCONCLUSIVE,
            verifier_notes="response body was not valid JSON; could not check fields",
        )

    present_fields = set(body.keys()) if isinstance(body, dict) else set()
    leaked = present_fields & disallowed_fields

    if leaked:
        verdict = VerifierVerdict.CONFIRMED
        notes = f"response included disallowed fields: {sorted(leaked)}"
    else:
        verdict = VerifierVerdict.REFUTED
        notes = "no disallowed fields present in the response"

    return Finding(
        finding_id=finding_id,
        vuln_class=VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE,
        endpoint=endpoint,
        method=method,
        claim=f"response fields exposed by {endpoint}",
        evidence_ids=evidence_ids,
        verdict=verdict,
        verifier_notes=notes,
    )


def check_regression(pre_patch: Finding, post_patch: Finding) -> bool:
    """Regression check: confirm a finding correctly flips from
    CONFIRMED (before a fix was applied) to REFUTED (after), for the
    same vulnerability class and endpoint. This is what proves a
    verifier oracle is actually sensitive to the underlying behavior,
    rather than always returning the same verdict regardless of the
    target's state."""
    return (
        pre_patch.vuln_class == post_patch.vuln_class
        and pre_patch.endpoint == post_patch.endpoint
        and pre_patch.verdict == VerifierVerdict.CONFIRMED
        and post_patch.verdict == VerifierVerdict.REFUTED
    )
