"""
tracesec.llm_scanner

Configuration C2: an LLM-only scanner. The LLM is given a target's
normalized OpenAPI operations and asked to name endpoints it suspects
are vulnerable, with no dependency graph, no requirement that it cite
resolvable evidence, and no independent verification -- this is
deliberately the weakest configuration in TRACE's ablation (see
docs/EVALUATION.md), included so later configurations (C4 evidence-
grounded, C5 full TRACE) have something to measurably improve on.

Every Finding this module produces still satisfies the Finding schema's
evidence_ids requirement, but the "evidence" backing a C2 finding is
only the LLM's own claim text, recorded into the EvidenceStore as-is.
This is intentional and is the point of the ablation: C2's evidence is
present but not independently meaningful, unlike C4/C5's, which must
cite a genuine, replayable EvidenceRecord from an executed request
(see tracesec.pipeline, which re-anchors these findings to real
probes).

Configuration C3 (dependency-aware) is also defined here: the same
prompt, plus a section describing producer/consumer relationships from
tracesec.dependency (e.g. "GET /appointments/{id} returns a patient_id
usable against GET /patients/{patient_id}"), so the LLM can reason
about relationships between operations rather than judging each in
isolation -- exactly the relationship the plain C2 run missed (see
docs/lab/llm-baseline-smoke-run.md).
"""

import json
from typing import Any

from tracesec.dependency import DependencyEdge
from tracesec.evidence import EvidenceStore
from tracesec.findings import Finding, VerifierVerdict, VulnerabilityClass
from tracesec.llm_adapter import LLMAdapter
from tracesec.spec import Operation

_VALID_CLASSES = {c.value for c in VulnerabilityClass}

_PROMPT_TEMPLATE = """You are reviewing a REST API for security vulnerabilities.
Below is a list of operations (method, path, parameters) from its OpenAPI spec.

For each operation you suspect is vulnerable, respond with one JSON object
per line (JSON Lines format), each with exactly these fields:
  "method": the HTTP method
  "path": the exact path from the list below
  "vuln_class": one of "bola", "broken_authentication",
                "excessive_data_exposure", "rate_limiting"
  "claim": a one-sentence reason you suspect this endpoint is vulnerable

Only include operations you genuinely suspect. Do not include every
operation. Output nothing else -- no prose, no markdown fences.

Operations:
{operations_block}
"""


def _format_operations(operations: list[Operation]) -> str:
    lines = []
    for op in operations:
        params = ", ".join(p.name for p in op.parameters) or "none"
        lines.append(f"- {op.method} {op.path} (parameters: {params})")
    return "\n".join(lines)


def build_prompt(operations: list[Operation]) -> str:
    return _PROMPT_TEMPLATE.format(operations_block=_format_operations(operations))


def build_prompt_with_dependencies(operations: list[Operation], edges: list[DependencyEdge]) -> str:
    """Configuration C3's prompt: build_prompt's operation list plus a
    section describing known producer/consumer relationships, so the
    LLM can reason about them explicitly rather than guessing from
    endpoint shape alone."""
    base = build_prompt(operations)
    if not edges:
        return base
    lines = [
        f'- {e.producer_method} {e.producer_path} returns a "{e.field_name}" field '
        f"that {e.consumer_method} {e.consumer_path} accepts as a "
        f"{e.consumer_param_location} parameter"
        for e in edges
    ]
    dependencies_block = "\n".join(lines)
    return (
        base + "\n\nKnown relationships between operations (an identifier returned by one "
        "operation can be used as input to another):\n" + dependencies_block
    )


def _parse_llm_response(text: str) -> list[dict[str, Any]]:
    """Parse JSON-Lines output, skipping any line that is not valid
    JSON or is missing a required field. An LLM ignoring formatting
    instructions is expected, not exceptional -- this parser is
    deliberately tolerant of stray blank lines or minor formatting
    slips, but silently drops anything it cannot parse into the
    required shape, since a malformed line is not itself a finding."""
    rows: list[dict[str, Any]] = []
    for line in text.strip().splitlines():
        stripped = line.strip().strip(",")
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        if not {"method", "path", "vuln_class", "claim"} <= obj.keys():
            continue
        if obj["vuln_class"] not in _VALID_CLASSES:
            continue
        rows.append(obj)
    return rows


def run_llm_scanner(
    operations: list[Operation],
    adapter: LLMAdapter,
    evidence: EvidenceStore,
    model: str,
    temperature: float = 0.0,
    session_id: str = "llm-scanner-c2",
) -> list[Finding]:
    """Run configuration C2 against a list of Operations and return the
    Findings the LLM proposed. Every returned Finding cites an
    EvidenceRecord, but that record's content is only the LLM's own
    claim -- see module docstring.
    """
    prompt = build_prompt(operations)
    raw_response = adapter.complete(model=model, prompt=prompt, temperature=temperature)
    parsed_rows = _parse_llm_response(raw_response)

    findings: list[Finding] = []
    for i, row in enumerate(parsed_rows):
        record = evidence.add(
            session_id=session_id,
            method=row["method"],
            url=row["path"],
            request_headers={},
            request_body=None,
            response_status=0,
            response_headers={},
            response_body=json.dumps(row),
            elapsed_seconds=0.0,
        )
        finding = Finding(
            finding_id=f"llm-c2-{i}",
            vuln_class=VulnerabilityClass(row["vuln_class"]),
            endpoint=row["path"],
            method=row["method"],
            claim=row["claim"],
            evidence_ids=[record.index],
            verdict=VerifierVerdict.UNVERIFIED,
            verifier_notes="from LLM-only scanner (C2); no independent verification",
        )
        findings.append(finding)
    return findings


def run_dependency_aware_scanner(
    operations: list[Operation],
    edges: list[DependencyEdge],
    adapter: LLMAdapter,
    evidence: EvidenceStore,
    model: str,
    temperature: float = 0.0,
    session_id: str = "llm-scanner-c3",
) -> list[Finding]:
    """Configuration C3: identical to run_llm_scanner (C2), except the
    prompt includes the dependency graph from tracesec.dependency."""
    prompt = build_prompt_with_dependencies(operations, edges)
    raw_response = adapter.complete(model=model, prompt=prompt, temperature=temperature)
    parsed_rows = _parse_llm_response(raw_response)

    findings: list[Finding] = []
    for i, row in enumerate(parsed_rows):
        record = evidence.add(
            session_id=session_id,
            method=row["method"],
            url=row["path"],
            request_headers={},
            request_body=None,
            response_status=0,
            response_headers={},
            response_body=json.dumps(row),
            elapsed_seconds=0.0,
        )
        finding = Finding(
            finding_id=f"llm-c3-{i}",
            vuln_class=VulnerabilityClass(row["vuln_class"]),
            endpoint=row["path"],
            method=row["method"],
            claim=row["claim"],
            evidence_ids=[record.index],
            verdict=VerifierVerdict.UNVERIFIED,
            verifier_notes="from dependency-aware LLM scanner (C3); no independent verification",
        )
        findings.append(finding)
    return findings
