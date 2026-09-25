"""
Phase 3 smoke-run: C2 (LLM-only scanner) against TRACE-Bench's real,
live OpenAPI spec, using a real Groq completion (cached after the
first call via LLMAdapter's record/replay cache).
"""

import json
import os
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from groq import Groq

from tracesec.evidence import EvidenceStore
from tracesec.findings import VulnerabilityClass
from tracesec.llm_adapter import LLMAdapter
from tracesec.llm_scanner import run_llm_scanner
from tracesec.scoring import score_by_class, score_findings
from tracesec.spec import parse_openapi

RUN_DIR = Path(__file__).parent
MODEL = "openai/gpt-oss-120b"

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


def groq_complete(model: str, prompt: str, temperature: float) -> str:
    api_key = os.environ["GROQ_API_KEY"]
    client = Groq(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
    )
    return response.choices[0].message.content or ""


def main() -> None:
    spec = json.loads(urllib.request.urlopen("http://localhost:9000/openapi.json").read())
    operations = parse_openapi(spec)
    print(f"Loaded {len(operations)} operations from TRACE-Bench's live spec.")

    adapter = LLMAdapter(RUN_DIR / "llm-cache.json", complete_fn=groq_complete)
    evidence = EvidenceStore(RUN_DIR / "evidence.jsonl")

    findings = run_llm_scanner(operations, adapter, evidence, model=MODEL, temperature=0.0)

    print(f"\nLLM (C2) proposed {len(findings)} findings:")
    for f in findings:
        print(f"  - [{f.vuln_class.value}] {f.method} {f.endpoint}: {f.claim}")

    print("\n=== Overall C2 (LLM-only) score vs. TRACE-Bench ground truth ===")
    overall = score_findings(findings, GROUND_TRUTH)
    print(f"TP={overall.true_positives} FP={overall.false_positives} FN={overall.false_negatives}")
    print(f"Precision={overall.precision:.2f} Recall={overall.recall:.2f} F1={overall.f1:.2f}")

    print("\n=== Per-class breakdown ===")
    by_class = score_by_class(findings, GROUND_TRUTH)
    for vuln_class, result in by_class.items():
        print(
            f"  {vuln_class.value:28s} "
            f"TP={result.true_positives} FP={result.false_positives} "
            f"FN={result.false_negatives} Recall={result.recall:.2f}"
        )

    print(f"\nEvidence chain verified: {evidence.verify_chain()}")
    print(f"LLM cache size: {adapter.cache_size}")


if __name__ == "__main__":
    main()
