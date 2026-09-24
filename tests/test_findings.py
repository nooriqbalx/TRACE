"""
Unit tests for tracesec.findings: the Finding schema.
"""

import pytest

from tracesec.findings import Finding, VerifierVerdict, VulnerabilityClass


def test_finding_requires_evidence_ids():
    with pytest.raises(ValueError, match="no evidence_ids"):
        Finding(
            finding_id="f1",
            vuln_class=VulnerabilityClass.BOLA,
            endpoint="/patients/{id}",
            method="GET",
            claim="cross-user access succeeded",
            evidence_ids=[],
        )


@pytest.mark.parametrize(
    ("vuln_class", "expected_owasp", "expected_cwe"),
    [
        (VulnerabilityClass.BOLA, "API1:2023", "CWE-639"),
        (VulnerabilityClass.BROKEN_AUTHENTICATION, "API2:2023", "CWE-287"),
        (VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE, "API3:2023", "CWE-213"),
        (VulnerabilityClass.RATE_LIMITING, "API4:2023", "CWE-770"),
    ],
)
def test_finding_owasp_cwe_mapping(vuln_class, expected_owasp, expected_cwe):
    finding = Finding(
        finding_id="f1",
        vuln_class=vuln_class,
        endpoint="/x",
        method="GET",
        claim="test",
        evidence_ids=[0],
    )
    assert finding.owasp_id == expected_owasp
    assert finding.cwe_id == expected_cwe


def test_finding_to_dict_shape():
    finding = Finding(
        finding_id="f1",
        vuln_class=VulnerabilityClass.BOLA,
        endpoint="/patients/{id}",
        method="GET",
        claim="user B read user A's record",
        evidence_ids=[0, 1],
        verdict=VerifierVerdict.CONFIRMED,
        verifier_notes="replayed successfully",
    )
    d = finding.to_dict()
    assert d["finding_id"] == "f1"
    assert d["vuln_class"] == "bola"
    assert d["verdict"] == "confirmed"
    assert d["evidence_ids"] == [0, 1]
    assert d["owasp_id"] == "API1:2023"
