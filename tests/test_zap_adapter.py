"""
Unit tests for tracesec.zap_adapter: ZAP JSON report -> Findings.
"""

from tracesec.evidence import EvidenceStore
from tracesec.findings import VulnerabilityClass
from tracesec.zap_adapter import ingest_zap_report, parse_zap_report

_SAMPLE_REPORT = {
    "site": [
        {
            "@name": "http://localhost:9000",
            "alerts": [
                {
                    "name": "Broken Object Level Authorization",
                    "cweid": "639",
                    "desc": "A user can access another user's resource.",
                    "instances": [
                        {
                            "uri": "http://localhost:9000/patients/2",
                            "method": "GET",
                            "param": "patient_id",
                            "evidence": "returned another user's record",
                        }
                    ],
                },
                {
                    "name": "Missing Anti-clickjacking Header",
                    "cweid": "1021",
                    "desc": "Not one of TRACE's four classes; must be skipped.",
                    "instances": [
                        {
                            "uri": "http://localhost:9000/",
                            "method": "GET",
                            "param": "",
                            "evidence": "",
                        }
                    ],
                },
                {
                    "name": "Insufficient Authentication",
                    "cweid": "287",
                    "desc": "OTP has no rate limiting.",
                    "instances": [
                        {
                            "uri": "http://localhost:9000/auth/verify-otp",
                            "method": "POST",
                            "param": "",
                            "evidence": "",
                        }
                    ],
                },
            ],
        }
    ]
}


def test_parse_zap_report_skips_unmapped_cwe():
    rows = parse_zap_report(_SAMPLE_REPORT)
    assert len(rows) == 2  # the CWE-1021 alert is dropped
    classes = {row["vuln_class"] for row in rows}
    assert classes == {
        VulnerabilityClass.BOLA,
        VulnerabilityClass.BROKEN_AUTHENTICATION,
    }


def test_parse_zap_report_extracts_instance_fields():
    rows = parse_zap_report(_SAMPLE_REPORT)
    bola_row = next(r for r in rows if r["vuln_class"] == VulnerabilityClass.BOLA)
    assert bola_row["method"] == "GET"
    assert bola_row["uri"] == "http://localhost:9000/patients/2"


def test_ingest_zap_report_creates_findings_with_evidence(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    findings = ingest_zap_report(_SAMPLE_REPORT, evidence)

    assert len(findings) == 2
    assert len(evidence.records) == 2
    assert evidence.verify_chain()

    for finding in findings:
        assert finding.evidence_ids
        cited_record = evidence.get(finding.evidence_ids[0])
        assert cited_record is not None


def test_ingest_zap_report_empty_site_list(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    findings = ingest_zap_report({"site": []}, evidence)
    assert findings == []
    assert evidence.records == []


def test_ingest_zap_report_missing_site_key(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    findings = ingest_zap_report({}, evidence)
    assert findings == []
