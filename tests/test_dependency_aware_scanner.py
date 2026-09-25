"""
Unit tests for configuration C3 (tracesec.llm_scanner.
run_dependency_aware_scanner / build_prompt_with_dependencies). Uses a
fake completer, same pattern as test_llm_scanner.py -- no real LLM
calls here.
"""

import json

from tracesec.dependency import DependencyEdge
from tracesec.evidence import EvidenceStore
from tracesec.llm_adapter import LLMAdapter
from tracesec.llm_scanner import build_prompt_with_dependencies, run_dependency_aware_scanner
from tracesec.spec import Operation, Parameter

_OPERATIONS = [
    Operation(
        operation_id="get_appointment",
        method="GET",
        path="/appointments/{appointment_id}",
        parameters=[
            Parameter(name="appointment_id", location="path", required=True, schema_type="integer")
        ],
        has_request_body=False,
        tags=["bola-related-object"],
    ),
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
]

_EDGE = DependencyEdge(
    field_name="patient_id",
    producer_method="GET",
    producer_path="/appointments/{appointment_id}",
    consumer_method="GET",
    consumer_path="/patients/{patient_id}",
    consumer_param_location="path",
)


def _fake_completer(response_text):
    def _complete(model, prompt, temperature):
        return response_text

    return _complete


def test_build_prompt_with_dependencies_includes_edge_description():
    prompt = build_prompt_with_dependencies(_OPERATIONS, [_EDGE])
    assert "patient_id" in prompt
    assert "/appointments/{appointment_id}" in prompt
    assert "/patients/{patient_id}" in prompt
    assert "Known relationships" in prompt


def test_build_prompt_with_dependencies_falls_back_when_no_edges():
    with_edges = build_prompt_with_dependencies(_OPERATIONS, [])
    from tracesec.llm_scanner import build_prompt

    assert with_edges == build_prompt(_OPERATIONS)


def test_run_dependency_aware_scanner_produces_c3_findings(tmp_path):
    response = json.dumps(
        {
            "method": "GET",
            "path": "/appointments/{appointment_id}",
            "vuln_class": "bola",
            "claim": "appointment exposes another patient's linked patient_id",
        }
    )
    adapter = LLMAdapter(tmp_path / "cache.json", complete_fn=_fake_completer(response))
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")

    findings = run_dependency_aware_scanner(
        _OPERATIONS, [_EDGE], adapter, evidence, model="fake-model"
    )

    assert len(findings) == 1
    assert findings[0].finding_id == "llm-c3-0"
    assert findings[0].endpoint == "/appointments/{appointment_id}"
    assert "C3" in findings[0].verifier_notes
    assert evidence.verify_chain()


def test_run_dependency_aware_scanner_caches_on_repeated_call(tmp_path):
    calls = {"count": 0}

    def counting_complete(model, prompt, temperature):
        calls["count"] += 1
        return ""

    cache_path = tmp_path / "cache.json"
    adapter = LLMAdapter(cache_path, complete_fn=counting_complete)
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")

    run_dependency_aware_scanner(_OPERATIONS, [_EDGE], adapter, evidence, model="fake-model")
    run_dependency_aware_scanner(_OPERATIONS, [_EDGE], adapter, evidence, model="fake-model")

    assert calls["count"] == 1
