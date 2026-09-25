"""
tracesec.grounding

Configuration C4: gates findings on genuine, replayable evidence,
rather than accepting a claim at face value. A finding is "grounded"
only if every evidence_id it cites resolves to a real EvidenceRecord
in the store, AND at least one cited record has response_status != 0
-- the sentinel this codebase uses (see zap_adapter.py and
llm_scanner.py) for evidence backed only by a report line or an LLM's
own claim text, never by an actually executed request.

This is the mechanical difference between C2 (LLM-only, evidence
present but only the model's own claim) and C4 (evidence-grounded,
evidence must come from a real executed probe, e.g. via
tracesec.executor.Executor): grounding does not evaluate whether a
claim is TRUE, only whether it is backed by something real enough to
possibly verify. Establishing truth is C5's job (tracesec.verifier).

Ungrounded findings are REJECTED outright, not downgraded or kept with
a lower confidence score -- per docs/EVALUATION.md, an evidence
requirement that can be satisfied by keeping the finding anyway is not
a real requirement.
"""

from dataclasses import dataclass

from tracesec.evidence import EvidenceStore
from tracesec.findings import Finding

# Evidence records with this response_status were not produced by an
# executed request (see zap_adapter.ingest_zap_report and
# llm_scanner.run_llm_scanner, both of which record synthetic evidence
# for a report line / raw claim using this sentinel).
_SYNTHETIC_STATUS = 0


@dataclass(frozen=True)
class GroundingResult:
    grounded: list[Finding]
    rejected: list[tuple[Finding, str]]


def is_grounded(finding: Finding, evidence: EvidenceStore) -> tuple[bool, str]:
    """Check one finding. Returns (True, "") if grounded, or
    (False, reason) if not."""
    if not finding.evidence_ids:
        return False, "finding cites no evidence_ids"

    resolved = []
    for evidence_id in finding.evidence_ids:
        record = evidence.get(evidence_id)
        if record is None:
            return False, f"evidence_id {evidence_id} does not resolve in the evidence store"
        resolved.append(record)

    if all(r.response_status == _SYNTHETIC_STATUS for r in resolved):
        return False, (
            "all cited evidence is synthetic (response_status == "
            f"{_SYNTHETIC_STATUS}); no cited record represents an actually "
            "executed request"
        )

    return True, ""


def ground_findings(findings: list[Finding], evidence: EvidenceStore) -> GroundingResult:
    """Apply is_grounded to every finding, splitting into grounded and
    rejected (with the reason for each rejection)."""
    grounded: list[Finding] = []
    rejected: list[tuple[Finding, str]] = []
    for finding in findings:
        ok, reason = is_grounded(finding, evidence)
        if ok:
            grounded.append(finding)
        else:
            rejected.append((finding, reason))
    return GroundingResult(grounded=grounded, rejected=rejected)
