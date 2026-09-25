"""
Unit tests for tracesec.pipeline: C4 grounding and C5 verification
orchestration, using hand-made prober/oracle fixtures (no real network
or LLM calls) so these tests document the exact contract
experiments/eval-run-1/'s live run relies on.
"""

import httpx

from tracesec.evidence import EvidenceStore
from tracesec.executor import Executor
from tracesec.findings import Finding, VerifierVerdict, VulnerabilityClass
from tracesec.pipeline import confirmed_only, ground_findings, verify_findings
from tracesec.scope import ScopedClient, ScopeGuard


def _llm_finding(vuln_class=VulnerabilityClass.BOLA, finding_id="f1"):
    # Mirrors what llm_scanner produces: evidence_ids pointing only at
    # a synthetic stand-in id, never actually resolved before grounding.
    return Finding(
        finding_id=finding_id,
        vuln_class=vuln_class,
        endpoint="/patients/{patient_id}",
        method="GET",
        claim="LLM's claim text",
        evidence_ids=[999],
    )


def _executor(handler, tmp_path):
    guard = ScopeGuard({"good.test"})
    client = ScopedClient(guard, transport=httpx.MockTransport(handler))
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    return Executor(client, evidence, session_id="pipeline"), evidence


def test_ground_findings_grounds_a_probeable_finding(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 2})

    executor, evidence = _executor(handler, tmp_path)

    def prober(finding, ex):
        return ex.get("https://good.test/patients/2")

    grounded, rejected = ground_findings([_llm_finding()], executor, evidence, prober)

    assert len(grounded) == 1
    assert rejected == []
    assert grounded[0].evidence_ids != [999]
    cited = evidence.get(grounded[0].evidence_ids[0])
    assert cited is not None
    assert cited.response_status == 200


def test_ground_findings_rejects_when_no_prober_strategy(tmp_path):
    executor, evidence = _executor(lambda r: httpx.Response(200), tmp_path)

    def prober(finding, ex):
        return None

    grounded, rejected = ground_findings([_llm_finding()], executor, evidence, prober)

    assert grounded == []
    assert len(rejected) == 1
    assert "no probe strategy" in rejected[0][1]


def test_verify_findings_dispatches_to_oracle(tmp_path):
    executor, _ = _executor(lambda r: httpx.Response(200), tmp_path)

    def oracle(finding, ex):
        return Finding(
            finding_id=finding.finding_id,
            vuln_class=finding.vuln_class,
            endpoint=finding.endpoint,
            method=finding.method,
            claim=finding.claim,
            evidence_ids=finding.evidence_ids,
            verdict=VerifierVerdict.CONFIRMED,
            verifier_notes="oracle ran",
        )

    verified = verify_findings([_llm_finding()], executor, oracle)
    assert verified[0].verdict == VerifierVerdict.CONFIRMED


def test_confirmed_only_filters_non_confirmed():
    findings = [
        Finding(
            finding_id="a",
            vuln_class=VulnerabilityClass.BOLA,
            endpoint="/x",
            method="GET",
            claim="c",
            evidence_ids=[0],
            verdict=VerifierVerdict.CONFIRMED,
        ),
        Finding(
            finding_id="b",
            vuln_class=VulnerabilityClass.BOLA,
            endpoint="/y",
            method="GET",
            claim="c",
            evidence_ids=[0],
            verdict=VerifierVerdict.REFUTED,
        ),
        Finding(
            finding_id="c",
            vuln_class=VulnerabilityClass.BOLA,
            endpoint="/z",
            method="GET",
            claim="c",
            evidence_ids=[0],
            verdict=VerifierVerdict.INCONCLUSIVE,
        ),
    ]
    result = confirmed_only(findings)
    assert [f.finding_id for f in result] == ["a"]


def test_ground_findings_empty_input(tmp_path):
    executor, evidence = _executor(lambda r: httpx.Response(200), tmp_path)
    grounded, rejected = ground_findings([], executor, evidence, lambda f, e: None)
    assert grounded == []
    assert rejected == []
