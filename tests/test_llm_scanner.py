"""
Unit tests for tracesec.llm_scanner: configuration C2. Uses a fake
completer (no real LLM calls, no API key needed) -- same pattern as
tests/test_llm_adapter.py.
"""

import json

from tracesec.evidence import EvidenceStore
from tracesec.findings import VulnerabilityClass
from tracesec.llm_adapter import LLMAdapter
from tracesec.llm_scanner import build_prompt, run_llm_scanner
from tracesec.spec import Operation, Parameter

_OPERATIONS = [
    Operation(
        operation_id="get_patient",
        method="GET",
        path="/patients/{patient_id}",
        parameters=[
            Parameter(name="patient_id", location="path", required=True, schema_type="integer")
        ],
        has_request_body=False,
        tags=["bola-direct-path"],
    ),
    Operation(
        operation_id="health",
        method="GET",
        path="/health",
        parameters=[],
        has_request_body=False,
        tags=["ratelimit-decoy-unlimited-by-design"],
    ),
]


def _fake_completer(response_text):
    def _complete(model, prompt, temperature):
        return response_text

    return _complete


def test_build_prompt_includes_all_operations():
    prompt = build_prompt(_OPERATIONS)
    assert "/patients/{patient_id}" in prompt
    assert "/health" in prompt
    assert "GET" in prompt


def test_run_llm_scanner_parses_valid_jsonl_response(tmp_path):
    response = json.dumps(
        {
            "method": "GET",
            "path": "/patients/{patient_id}",
            "vuln_class": "bola",
            "claim": "no ownership check visible from the spec alone",
        }
    )
    adapter = LLMAdapter(tmp_path / "cache.json", complete_fn=_fake_completer(response))
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")

    findings = run_llm_scanner(_OPERATIONS, adapter, evidence, model="fake-model")

    assert len(findings) == 1
    assert findings[0].vuln_class == VulnerabilityClass.BOLA
    assert findings[0].endpoint == "/patients/{patient_id}"
    assert findings[0].evidence_ids
    assert evidence.verify_chain()


def test_run_llm_scanner_skips_malformed_lines(tmp_path):
    response = "\n".join(
        [
            "not valid json at all",
            json.dumps(
                {
                    "method": "GET",
                    "path": "/health",
                    "vuln_class": "not_a_real_class",
                    "claim": "x",
                }
            ),
            json.dumps(
                {
                    "method": "GET",
                    "path": "/patients/{patient_id}",
                    "vuln_class": "bola",
                    "claim": "valid one",
                }
            ),
        ]
    )
    adapter = LLMAdapter(tmp_path / "cache.json", complete_fn=_fake_completer(response))
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")

    findings = run_llm_scanner(_OPERATIONS, adapter, evidence, model="fake-model")

    assert len(findings) == 1
    assert findings[0].claim == "valid one"


def test_run_llm_scanner_empty_response_yields_no_findings(tmp_path):
    adapter = LLMAdapter(tmp_path / "cache.json", complete_fn=_fake_completer(""))
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")

    findings = run_llm_scanner(_OPERATIONS, adapter, evidence, model="fake-model")

    assert findings == []


def test_run_llm_scanner_uses_cache_on_repeated_call(tmp_path):
    calls = {"count": 0}

    def counting_complete(model, prompt, temperature):
        calls["count"] += 1
        return ""

    cache_path = tmp_path / "cache.json"
    adapter = LLMAdapter(cache_path, complete_fn=counting_complete)
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")

    run_llm_scanner(_OPERATIONS, adapter, evidence, model="fake-model")
    run_llm_scanner(_OPERATIONS, adapter, evidence, model="fake-model")

    assert calls["count"] == 1
