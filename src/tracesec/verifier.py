"""
tracesec.verifier

Configuration C5: independent, deterministic verification of a
suspected vulnerability. No LLM is involved anywhere in this module --
every oracle here reaches its verdict purely by executing real
requests (through tracesec.executor.Executor, which is itself
scope-guarded and evidence-logging) and comparing real responses.

Each oracle below generalizes a pattern already exercised by hand in
this project: verify_bola mirrors the manual crAPI vehicle-location
and mechanic-report tests (docs/lab/crapi-manual-notes.md) and
TRACE-Bench's bola_* scenarios; verify_unthrottled mirrors the manual
OTP brute-force test and TRACE-Bench's authn_otp_bruteforce /
ratelimit_* scenarios; verify_exposure mirrors
exposure_extra_pii_fields.

Verdicts (see tracesec.findings.VerifierVerdict):
- CONFIRMED: the oracle observed the vulnerable behavior directly.
- REFUTED: the oracle observed the endpoint correctly rejecting the
  attack.
- INCONCLUSIVE: the oracle could not establish a clean baseline.

Safety: verify_unthrottled takes an explicit max_attempts cap, per
THREAT_MODEL.md T6.
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
    body: dict[str, Any] | None = None,
) -> Finding:
    """Differential BOLA oracle. Sends the same request twice: once as
    the resource's legitimate owner (the baseline/negative control),
    once as a different, unrelated identity (the actual attack).

    body, when given, is sent as the JSON request body on both calls --
    needed for body-based BOLA (e.g. POST /patients/lookup) and
    write-access BOLA (e.g. PUT /patients/{id}/notes), where the
    identifier or the attack itself lives in the body rather than the
    URL. Defaults to None (no body sent), preserving the original
    path-parameter-only behavior for existing callers.

    CONFIRMED: the owner's request succeeds AND the other identity's
    request also succeeds (2xx) -- no ownership check exists.
    REFUTED: the owner's request succeeds but the other identity's is
    rejected (401/403) -- ownership is correctly enforced.
    INCONCLUSIVE: even the owner's baseline request did not succeed.
    """
    owner_kwargs: dict[str, Any] = {"headers": dict(owner.headers)}
    other_kwargs: dict[str, Any] = {"headers": dict(other.headers)}
    if body is not None:
        owner_kwargs["json"] = body
        other_kwargs["json"] = body

    owner_result = executor.request(method, url, **owner_kwargs)
    other_result = executor.request(method, url, **other_kwargs)

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
    login guessing) and rate-limiting checks, capped at max_attempts
    requests, per THREAT_MODEL.md T6.

    CONFIRMED: max_attempts requests were sent and none received a 429.
    REFUTED: a 429 was received before the cap was reached.
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
    has declared should never appear.

    CONFIRMED: at least one disallowed field is present.
    REFUTED: none of the disallowed fields are present.
    INCONCLUSIVE: the response body is not a JSON object.
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
    same vulnerability class and endpoint."""
    return (
        pre_patch.vuln_class == post_patch.vuln_class
        and pre_patch.endpoint == post_patch.endpoint
        and pre_patch.verdict == VerifierVerdict.CONFIRMED
        and post_patch.verdict == VerifierVerdict.REFUTED
    )
