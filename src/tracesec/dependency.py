"""
tracesec.dependency

Infers producer -> consumer relationships between OpenAPI operations:
an operation "produces" a field if its 2xx response schema includes a
property (e.g. "patient_id"), and another operation "consumes" that
same field if it has a path/query parameter or request-body property
with a matching name. A DependencyEdge records that a value returned
by the producer operation can be used to drive a request to the
consumer operation -- exactly the appointments -> patients
relationship in TRACE-Bench that the C2 LLM smoke-run failed to find
(see docs/lab/llm-baseline-smoke-run.md).

This module resolves schemas from the raw OpenAPI spec dict (needed
for response-field names, which tracesec.spec's Operation does not
carry) combined with the already-parsed Operation list from
tracesec.spec (for parameters).

Known limitations, deliberately out of scope for this pass:
- Only one level of $ref resolution (a response schema that is itself
  a $ref) is followed; refs nested inside a schema's own properties
  are not resolved further.
- Matching is restricted to fields that look like identifiers ("id" or
  ending in "_id"), to avoid spurious edges on common field names
  (e.g. "name") that happen to appear in multiple schemas.
- Sequences are two steps (producer -> consumer); multi-hop (3+ step)
  chaining is a documented extension, not built here.
- Inference is schema-based (static) only; traffic-based inference
  (observing real responses via the Phase 2 executor/evidence store)
  is a documented extension for a later pass.
"""

from dataclasses import dataclass
from typing import Any

from tracesec.findings import VulnerabilityClass
from tracesec.spec import Operation


def _resolve_schema(spec: dict[str, Any], schema: dict[str, Any] | None) -> dict[str, Any]:
    """Resolve one level of $ref against spec['components']['schemas'].
    Returns {} if the ref cannot be resolved; returns the schema
    unchanged if it has no $ref."""
    if not schema:
        return {}
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/components/schemas/"):
        name = ref.rsplit("/", 1)[-1]
        components = spec.get("components")
        if not isinstance(components, dict):
            return {}
        schemas = components.get("schemas")
        if not isinstance(schemas, dict):
            return {}
        resolved = schemas.get(name)
        return resolved if isinstance(resolved, dict) else {}
    return schema


def _schema_field_names(spec: dict[str, Any], schema: dict[str, Any] | None) -> set[str]:
    resolved = _resolve_schema(spec, schema)
    properties = resolved.get("properties")
    if not isinstance(properties, dict):
        return set()
    return {str(key) for key in properties}


def _response_field_names(spec: dict[str, Any], op_dict: dict[str, Any]) -> set[str]:
    """Field names from the first 2xx JSON response schema, if any."""
    responses = op_dict.get("responses")
    if not isinstance(responses, dict):
        return set()
    for status, response in responses.items():
        if not str(status).startswith("2"):
            continue
        if not isinstance(response, dict):
            continue
        content = response.get("content")
        if not isinstance(content, dict):
            continue
        json_content = content.get("application/json")
        if not isinstance(json_content, dict):
            continue
        schema = json_content.get("schema")
        return _schema_field_names(spec, schema)
    return set()


def _request_body_field_names(spec: dict[str, Any], op_dict: dict[str, Any]) -> set[str]:
    request_body = op_dict.get("requestBody")
    if not isinstance(request_body, dict):
        return set()
    content = request_body.get("content")
    if not isinstance(content, dict):
        return set()
    json_content = content.get("application/json")
    if not isinstance(json_content, dict):
        return set()
    schema = json_content.get("schema")
    return _schema_field_names(spec, schema)


def _is_identifier_field(name: str) -> bool:
    """Restrict matching to fields that look like resource identifiers
    (e.g. "patient_id", "id"), rather than any shared field name (e.g.
    "email"), which would flood the graph with unrelated matches."""
    return name == "id" or name.endswith("_id")


def _consumer_fields(
    spec: dict[str, Any], operation: Operation, op_dict: dict[str, Any]
) -> dict[str, str]:
    """Map field_name -> location ("path"/"query"/"body") for every
    field an operation can consume."""
    fields: dict[str, str] = {}
    for param in operation.parameters:
        if param.location in ("path", "query"):
            fields[param.name] = param.location
    for name in _request_body_field_names(spec, op_dict):
        fields.setdefault(name, "body")
    return fields


@dataclass(frozen=True)
class DependencyEdge:
    """A producer operation's response includes a field that a
    consumer operation accepts as a parameter or request-body field --
    e.g. GET /appointments/{id} returns "patient_id", which GET
    /patients/{patient_id} accepts as a path parameter."""

    field_name: str
    producer_method: str
    producer_path: str
    consumer_method: str
    consumer_path: str
    consumer_param_location: str  # "path", "query", or "body"


def build_dependency_graph(
    spec: dict[str, Any], operations: list[Operation]
) -> list[DependencyEdge]:
    """Infer producer -> consumer edges between operations, using only
    the raw OpenAPI spec's schemas (no live traffic). See module
    docstring for the identifier-only matching heuristic and the
    one-level $ref resolution limitation."""
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []

    producers: dict[tuple[str, str], set[str]] = {}
    consumers: dict[tuple[str, str], dict[str, str]] = {}

    for operation in operations:
        path_item = paths.get(operation.path)
        op_dict: dict[str, Any] = {}
        if isinstance(path_item, dict):
            candidate = path_item.get(operation.method.lower())
            if isinstance(candidate, dict):
                op_dict = candidate

        key = (operation.method, operation.path)
        producers[key] = {
            f for f in _response_field_names(spec, op_dict) if _is_identifier_field(f)
        }
        consumers[key] = {
            name: loc
            for name, loc in _consumer_fields(spec, operation, op_dict).items()
            if _is_identifier_field(name)
        }

    edges: list[DependencyEdge] = []
    for producer_key, fields in producers.items():
        for consumer_key, consumer_field_map in consumers.items():
            if producer_key == consumer_key:
                continue
            shared = fields & consumer_field_map.keys()
            for field_name in shared:
                edges.append(
                    DependencyEdge(
                        field_name=field_name,
                        producer_method=producer_key[0],
                        producer_path=producer_key[1],
                        consumer_method=consumer_key[0],
                        consumer_path=consumer_key[1],
                        consumer_param_location=consumer_field_map[field_name],
                    )
                )
    return edges


def dependency_graph_to_dict(edges: list[DependencyEdge]) -> list[dict[str, str]]:
    """Serialize a dependency graph to plain dicts, suitable for
    writing to JSON (an architecture diagram export, or input for
    Phase 5's verifier)."""
    return [
        {
            "field_name": e.field_name,
            "producer_method": e.producer_method,
            "producer_path": e.producer_path,
            "consumer_method": e.consumer_method,
            "consumer_path": e.consumer_path,
            "consumer_param_location": e.consumer_param_location,
        }
        for e in edges
    ]


@dataclass(frozen=True)
class Sequence:
    """A valid two-step request chain: call the producer first to
    obtain a real identifier, then call the consumer using that
    identifier -- the minimum "observe -> reference" pattern needed
    for dependency-aware testing."""

    producer_method: str
    producer_path: str
    consumer_method: str
    consumer_path: str
    linking_field: str


def plan_sequences(edges: list[DependencyEdge]) -> list[Sequence]:
    """Turn dependency edges into two-step sequences. One sequence per
    edge; multi-hop chaining is a documented extension (see module
    docstring), not built here."""
    return [
        Sequence(
            producer_method=edge.producer_method,
            producer_path=edge.producer_path,
            consumer_method=edge.consumer_method,
            consumer_path=edge.consumer_path,
            linking_field=edge.field_name,
        )
        for edge in edges
    ]


def dependency_coverage(operations: list[Operation], edges: list[DependencyEdge]) -> float:
    """Fraction of operations that participate in at least one
    dependency edge (as producer or consumer), out of all operations.
    A scanner testing operations in total isolation scores 0.0 here;
    this metric is what should rise once the dependency mapper is
    used, compared to a baseline that ignores it."""
    if not operations:
        return 0.0
    involved: set[tuple[str, str]] = set()
    for edge in edges:
        involved.add((edge.producer_method, edge.producer_path))
        involved.add((edge.consumer_method, edge.consumer_path))
    total = {(op.method, op.path) for op in operations}
    return len(involved & total) / len(total)


@dataclass(frozen=True)
class BolaProbe:
    """A concrete BOLA test case derived from a dependency edge: an
    identifier obtained via the setup step is replayed against the
    attack step under a different identity. This generalizes the
    manual test performed by hand against crAPI's vehicle-location and
    mechanic-report endpoints (docs/lab/crapi-manual-notes.md) and
    against TRACE-Bench's bola_related_object scenario. param_location
    records where the attacker would place the swapped identifier
    (path/query/body) when crafting the attack step's request."""

    vuln_class: VulnerabilityClass
    setup_method: str
    setup_path: str
    attack_method: str
    attack_path: str
    linking_field: str
    param_location: str


def plan_bola_probes(edges: list[DependencyEdge]) -> list[BolaProbe]:
    """Turn every dependency edge into a concrete BOLA test case. Any
    identifier field an operation is proven to accept (in any
    location: path, query, or body) is a viable place to test
    cross-identity access, since the attacker fully controls the
    request they send."""
    return [
        BolaProbe(
            vuln_class=VulnerabilityClass.BOLA,
            setup_method=edge.producer_method,
            setup_path=edge.producer_path,
            attack_method=edge.consumer_method,
            attack_path=edge.consumer_path,
            linking_field=edge.field_name,
            param_location=edge.consumer_param_location,
        )
        for edge in edges
    ]
