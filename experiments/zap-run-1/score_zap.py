"""
Score the C1 (ZAP baseline) smoke-run against TRACE-Bench's ground
truth. Loads a real ZAP JSON report, converts it to Findings via
tracesec.zap_adapter, and scores against the four vulnerable-endpoint
rows manually transcribed from bench/GROUND_TRUTH.yaml (the 12
non-decoy scenarios that are vulnerable while TRACE-Bench runs
unpatched, which is how it was running during this scan).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "bench"))

from tracesec.evidence import EvidenceStore
from tracesec.findings import VulnerabilityClass
from tracesec.scoring import score_by_class, score_findings
from tracesec.zap_adapter import ingest_zap_report

REPORT_PATH = Path(__file__).parent / "zap-report.json"
EVIDENCE_PATH = Path(__file__).parent / "evidence.jsonl"

# The 18 vulnerable (non-decoy) TRACE-Bench endpoints, as they were
# exposed during this unpatched run. Host/port omitted to match
# TRACE-Bench's own path convention; ZAP's URIs include the host, so
# endpoint comparison below strips it before scoring.
GROUND_TRUTH = [
    (VulnerabilityClass.BOLA, "GET", "/patients/{patient_id}"),
    (VulnerabilityClass.BOLA, "POST", "/patients/lookup"),
    (VulnerabilityClass.BOLA, "GET", "/appointments/{appointment_id}"),
    (VulnerabilityClass.BOLA, "PUT", "/patients/{patient_id}/notes"),
    (VulnerabilityClass.BROKEN_AUTHENTICATION, "POST", "/auth/verify-otp"),
    (VulnerabilityClass.BROKEN_AUTHENTICATION, "POST", "/auth/login-predictable"),
    (VulnerabilityClass.BROKEN_AUTHENTICATION, "GET", "/me/expiring"),
    (VulnerabilityClass.BROKEN_AUTHENTICATION, "POST", "/auth/reset-password"),
    (VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE, "GET", "/patients/{patient_id}/profile"),
    (VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE, "GET", "/patients/{patient_id}/risk-score"),
    (VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE, "GET", "/patients"),
    (VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE, "GET", "/patients/{patient_id}/full"),
    (VulnerabilityClass.RATE_LIMITING, "POST", "/auth/login"),
    (VulnerabilityClass.RATE_LIMITING, "POST", "/auth/forgot-password"),
    (VulnerabilityClass.RATE_LIMITING, "GET", "/patients/search"),
    (VulnerabilityClass.RATE_LIMITING, "POST", "/auth/signup"),
]


def strip_host(url: str) -> str:
    """Reduce a full ZAP URI to a bare path for comparison against
    ground truth, which uses path-only endpoints."""
    for prefix_end in ("//",):
        idx = url.find(prefix_end)
        if idx != -1:
            rest = url[idx + 2 :]
            slash = rest.find("/")
            return rest[slash:] if slash != -1 else "/"
    return url


def main() -> None:
    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    evidence = EvidenceStore(EVIDENCE_PATH)
    findings = ingest_zap_report(report, evidence, session_id="zap-smoke-run")

    print(f"Total ZAP alert instances mapped to TRACE's 4 classes: {len(findings)}")
    for f in findings:
        print(f"  - [{f.vuln_class.value}] {f.method} {strip_host(f.endpoint)}: {f.claim}")

    # Normalize ZAP's full-URL endpoints to bare paths before scoring,
    # since bench/GROUND_TRUTH.yaml uses path-only endpoints.
    for f in findings:
        f.endpoint = strip_host(f.endpoint)

    print("\n=== Overall C1 (ZAP baseline) score vs. TRACE-Bench ground truth ===")
    overall = score_findings(findings, GROUND_TRUTH)
    print(f"TP={overall.true_positives} FP={overall.false_positives} FN={overall.false_negatives}")
    print(f"Precision={overall.precision:.2f} Recall={overall.recall:.2f} F1={overall.f1:.2f}")

    print("\n=== Per-class breakdown ===")
    by_class = score_by_class(findings, GROUND_TRUTH)
    for vuln_class, result in by_class.items():
        print(
            f"  {vuln_class.value:28s} "
            f"TP={result.true_positives} FP={result.false_positives} FN={result.false_negatives} "
            f"Recall={result.recall:.2f}"
        )

    print(f"\nEvidence chain verified: {evidence.verify_chain()}")
    print(f"Evidence records written to: {EVIDENCE_PATH}")


if __name__ == "__main__":
    main()
