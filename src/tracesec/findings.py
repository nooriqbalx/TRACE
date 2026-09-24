"""
tracesec.findings

The Finding schema: what TRACE emits for a single suspected
vulnerability. Every finding must reference the EvidenceRecord(s) that
support it -- a finding with no evidence_ids is invalid, since "trust
the LLM's claim" is exactly the failure mode TRACE is built to avoid.
"""

from dataclasses import dataclass, field
from enum import StrEnum


class VulnerabilityClass(StrEnum):
    BOLA = "bola"
    BROKEN_AUTHENTICATION = "broken_authentication"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    RATE_LIMITING = "rate_limiting"


class VerifierVerdict(StrEnum):
    UNVERIFIED = "unverified"
    CONFIRMED = "confirmed"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


CLASS_TO_STANDARD: dict[VulnerabilityClass, tuple[str, str]] = {
    VulnerabilityClass.BOLA: ("API1:2023", "CWE-639"),
    VulnerabilityClass.BROKEN_AUTHENTICATION: ("API2:2023", "CWE-287"),
    VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE: ("API3:2023", "CWE-213"),
    VulnerabilityClass.RATE_LIMITING: ("API4:2023", "CWE-770"),
}


@dataclass
class Finding:
    finding_id: str
    vuln_class: VulnerabilityClass
    endpoint: str
    method: str
    claim: str
    evidence_ids: list[int] = field(default_factory=list)
    verdict: VerifierVerdict = VerifierVerdict.UNVERIFIED
    verifier_notes: str | None = None

    def __post_init__(self) -> None:
        if not self.evidence_ids:
            raise ValueError(
                f"Finding {self.finding_id!r} has no evidence_ids; every "
                "finding must cite at least one EvidenceRecord"
            )

    @property
    def owasp_id(self) -> str:
        return CLASS_TO_STANDARD[self.vuln_class][0]

    @property
    def cwe_id(self) -> str:
        return CLASS_TO_STANDARD[self.vuln_class][1]

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "vuln_class": self.vuln_class.value,
            "endpoint": self.endpoint,
            "method": self.method,
            "claim": self.claim,
            "evidence_ids": list(self.evidence_ids),
            "verdict": self.verdict.value,
            "verifier_notes": self.verifier_notes,
            "owasp_id": self.owasp_id,
            "cwe_id": self.cwe_id,
        }
