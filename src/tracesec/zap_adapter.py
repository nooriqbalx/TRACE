"""
tracesec.zap_adapter

Converts an OWASP ZAP JSON alert report into TRACE Findings, backed by
synthetic EvidenceRecords built from the alert's own URI/method/
evidence fields. ZAP's JSON report does not include full raw request/
response headers and bodies the way TRACE's own executor does, so the
evidence recorded here is necessarily thinner than TRACE's own
findings -- that asymmetry is itself worth noting in the eventual
evaluation write-up.

Only alerts whose cweid maps to one of TRACE's four vulnerability
classes are converted; every other ZAP alert (there are many: missing
security headers, cookie flags, etc.) is out of scope for this
comparison and silently skipped.

Expected input shape (ZAP's traditional JSON report format):
{
  "site": [
    {
      "alerts": [
        {
          "name": "...",
          "cweid": "639",
          "desc": "...",
          "instances": [
            {"uri": "...", "method": "GET", "param": "...", "evidence": "..."}
          ]
        }
      ]
    }
  ]
}
"""

from typing import Any

from tracesec.evidence import EvidenceStore
from tracesec.findings import (
    CLASS_TO_STANDARD,
    Finding,
    VerifierVerdict,
    VulnerabilityClass,
)

CWE_TO_VULNERABILITY_CLASS: dict[str, VulnerabilityClass] = {
    cwe: vuln_class for vuln_class, (_owasp, cwe) in CLASS_TO_STANDARD.items()
}


def parse_zap_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten a ZAP JSON report into one row per (alert, instance)
    pair, keeping only alerts mapped to a known VulnerabilityClass."""
    rows: list[dict[str, Any]] = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            cwe_id = f"CWE-{alert.get('cweid')}" if alert.get("cweid") else None
            vuln_class = CWE_TO_VULNERABILITY_CLASS.get(cwe_id) if cwe_id else None
            if vuln_class is None:
                continue
            for instance in alert.get("instances", []):
                rows.append(
                    {
                        "vuln_class": vuln_class,
                        "name": alert.get("name", "ZAP alert"),
                        "method": instance.get("method", "GET"),
                        "uri": instance.get("uri", ""),
                        "param": instance.get("param", ""),
                        "evidence_text": instance.get("evidence", ""),
                        "desc": alert.get("desc", ""),
                    }
                )
    return rows


def ingest_zap_report(
    report: dict[str, Any],
    evidence: EvidenceStore,
    session_id: str = "zap-baseline",
) -> list[Finding]:
    """Parse a ZAP report and return one Finding per (alert, instance),
    each backed by a synthetic EvidenceRecord recorded into `evidence`.
    """
    findings: list[Finding] = []
    for i, row in enumerate(parse_zap_report(report)):
        record = evidence.add(
            session_id=session_id,
            method=row["method"],
            url=row["uri"],
            request_headers={},
            request_body=None,
            response_status=0,
            response_headers={},
            response_body=row["evidence_text"] or row["desc"],
            elapsed_seconds=0.0,
        )
        finding = Finding(
            finding_id=f"zap-{i}",
            vuln_class=row["vuln_class"],
            endpoint=row["uri"],
            method=row["method"],
            claim=row["name"],
            evidence_ids=[record.index],
            verdict=VerifierVerdict.UNVERIFIED,
            verifier_notes="from OWASP ZAP baseline scan; not independently verified",
        )
        findings.append(finding)
    return findings
