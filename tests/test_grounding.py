"""
Unit tests for tracesec.grounding: configuration C4's evidence-citation
gate. Confirms C2/C1-style synthetic evidence (response_status == 0,
as recorded by llm_scanner.run_llm_scanner and
zap_adapter.ingest_zap_report) is rejected, while evidence from a real
executed request (via tracesec.executor.Executor) passes.
"""

import httpx

from tracesec.evidence import EvidenceStore
from tracesec.executor import Executor
from tracesec.findings import Finding, VulnerabilityClass
from tracesec.grounding import ground_findings, is_grounded
from tracesec.scope import ScopedClient, ScopeGuard


def _finding(evidence_ids, finding_id="f1"):
    return Finding(
        finding_id=finding_id,
        vuln_class=VulnerabilityClass.BOLA,
        endpoint="/patients/{id}",
        method="GET",
        claim="test claim",
        evidence_ids=evidence_ids,
    )


def _add_synthetic(evidence, body="claim"):
    return evidence.add(
        session_id="llm-c2",
        method="GET",
        url="/patients/{id}",
        request_headers={},
        request_body=None,
        response_status=0,
        response_headers={},
        response_body=body,
        elapsed_seconds=0.0,
    )


def test_is_grounded_false_when_evidence_id_does_not_resolve(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    finding = _finding([0])
    ok, reason = is_grounded(finding, evidence)
    assert ok is False
    assert "does not resolve" in reason


def test_is_grounded_false_for_synthetic_evidence_only(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    record = _add_synthetic(evidence)
    finding = _finding([record.index])
    ok, reason = is_grounded(finding, evidence)
    assert ok is False
    assert "synthetic" in reason


def test_is_grounded_true_for_real_executed_request(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1})

    guard = ScopeGuard({"good.test"})
    client = ScopedClient(guard, transport=httpx.MockTransport(handler))
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    executor = Executor(client, evidence, session_id="verifier")

    result = executor.get("https://good.test/patients/1", headers={"X-User-Id": "1"})
    finding = _finding([result.evidence.index])

    ok, reason = is_grounded(finding, evidence)
    assert ok is True
    assert reason == ""


def test_is_grounded_true_if_at_least_one_cited_record_is_real(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1})

    guard = ScopeGuard({"good.test"})
    client = ScopedClient(guard, transport=httpx.MockTransport(handler))
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    executor = Executor(client, evidence, session_id="verifier")

    synthetic = _add_synthetic(evidence)
    real = executor.get("https://good.test/patients/1", headers={"X-User-Id": "1"})

    finding = _finding([synthetic.index, real.evidence.index])
    ok, _ = is_grounded(finding, evidence)
    assert ok is True


def test_ground_findings_splits_grounded_and_rejected(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1})

    guard = ScopeGuard({"good.test"})
    client = ScopedClient(guard, transport=httpx.MockTransport(handler))
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    executor = Executor(client, evidence, session_id="verifier")

    real = executor.get("https://good.test/patients/1", headers={"X-User-Id": "1"})
    grounded_finding = _finding([real.evidence.index], finding_id="grounded")

    synthetic = _add_synthetic(evidence)
    rejected_finding = _finding([synthetic.index], finding_id="rejected")

    result = ground_findings([grounded_finding, rejected_finding], evidence)

    assert result.grounded == [grounded_finding]
    assert len(result.rejected) == 1
    assert result.rejected[0][0] == rejected_finding


def test_ground_findings_empty_input(tmp_path):
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    result = ground_findings([], evidence)
    assert result.grounded == []
    assert result.rejected == []
