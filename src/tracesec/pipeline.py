"""
tracesec.pipeline

Orchestrates configurations C4 (evidence-grounded) and C5 (full TRACE)
on top of an LLM-proposed finding list (C2/C3's output, whose evidence
is only the LLM's own claim -- see llm_scanner.py).

Each finding is re-anchored to a REAL probe of the live target before
it is judged, rather than trusted at face value:

1. ground_finding() calls a caller-supplied `prober` to execute one
   real request against the finding's claimed endpoint, and replaces
   the finding's evidence_ids with the resulting real EvidenceRecord.
   `prober` returns None when no probe strategy exists for this
   finding's vuln_class/endpoint (e.g. the LLM proposed something
   TRACE does not know how to test); such findings are rejected
   outright -- TRACE only reports what it can actually probe. This is
   configuration C4.

2. verify_finding() re-dispatches an already-grounded finding to the
   correct deterministic oracle via a caller-supplied `oracle`
   callable, replacing its verdict with the oracle's real CONFIRMED /
   REFUTED / INCONCLUSIVE result. This is configuration C5.

`prober` and `oracle` are supplied by the caller rather than hardcoded
here, since constructing a concrete request (which identifiers to
substitute, which identities to use) is target-specific knowledge; see
experiments/eval-run-1/ for TRACE-Bench's concrete strategy.
"""

import dataclasses
from collections.abc import Callable

from tracesec.evidence import EvidenceStore
from tracesec.executor import ExecutionResult, Executor
from tracesec.findings import Finding, VerifierVerdict
from tracesec.grounding import is_grounded

ProberFn = Callable[[Finding, Executor], ExecutionResult | None]
OracleFn = Callable[[Finding, Executor], Finding]


def ground_finding(
    finding: Finding, executor: Executor, evidence: EvidenceStore, prober: ProberFn
) -> tuple[Finding | None, str]:
    """Execute prober(finding, executor); on success, re-anchor the
    finding to the resulting real evidence and grounding-check it. On
    failure (prober returns None), reject with a reason. Returns
    (grounded_finding_or_None, reason); reason is "" on success."""
    result = prober(finding, executor)
    if result is None:
        return None, "no probe strategy available for this finding's vuln_class/endpoint"

    reanchored = dataclasses.replace(finding, evidence_ids=[result.evidence.index])
    ok, reason = is_grounded(reanchored, evidence)
    if not ok:
        return None, reason
    return reanchored, ""


def ground_findings(
    findings: list[Finding], executor: Executor, evidence: EvidenceStore, prober: ProberFn
) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    """Apply ground_finding to every finding, splitting into grounded
    and rejected (with the reason for each rejection)."""
    grounded: list[Finding] = []
    rejected: list[tuple[Finding, str]] = []
    for finding in findings:
        result, reason = ground_finding(finding, executor, evidence, prober)
        if result is not None:
            grounded.append(result)
        else:
            rejected.append((finding, reason))
    return grounded, rejected


def verify_finding(finding: Finding, executor: Executor, oracle: OracleFn) -> Finding:
    """Re-dispatch a grounded finding to its oracle, returning the
    oracle's Finding (with a real verdict) in place of the input."""
    return oracle(finding, executor)


def verify_findings(findings: list[Finding], executor: Executor, oracle: OracleFn) -> list[Finding]:
    return [verify_finding(f, executor, oracle) for f in findings]


def confirmed_only(findings: list[Finding]) -> list[Finding]:
    """The final C5 report: only CONFIRMED findings are reported as
    vulnerabilities. REFUTED and INCONCLUSIVE are real oracle outcomes,
    but neither is a vulnerability."""
    return [f for f in findings if f.verdict == VerifierVerdict.CONFIRMED]
