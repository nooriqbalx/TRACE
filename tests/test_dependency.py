"""
Unit tests for tracesec.dependency: producer/consumer edge inference,
sequence planning, coverage measurement, and BOLA probe generation.

The fixture spec below reproduces TRACE-Bench's real appointments ->
patients relationship (the exact dependency a spec-only LLM scan
missed, per docs/lab/llm-baseline-smoke-run.md), plus a doctors
endpoint that shares no genuine dependency with anything, to confirm
ordinary fields like "name" never create spurious edges.
"""

from tracesec.dependency import (
    BolaProbe,
    build_dependency_graph,
    dependency_coverage,
    dependency_graph_to_dict,
    plan_bola_probes,
    plan_sequences,
)
from tracesec.findings import VulnerabilityClass
from tracesec.spec import parse_openapi

_SPEC = {
    "openapi": "3.1.0",
    "info": {"title": "t", "version": "0.1"},
    "components": {
        "schemas": {
            "Patient": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"},
                    "owner_user_id": {"type": "integer"},
                },
            },
            "Appointment": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "patient_id": {"type": "integer"},
                    "doctor_id": {"type": "integer"},
                },
            },
            "PatientLookupRequest": {
                "type": "object",
                "properties": {"patient_id": {"type": "integer"}},
            },
            "Doctor": {
                "type": "object",
                "properties": {"id": {"type": "integer"}, "name": {"type": "string"}},
            },
        }
    },
    "paths": {
        "/patients/{patient_id}": {
            "get": {
                "operationId": "get_patient",
                "parameters": [
                    {
                        "name": "patient_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Patient"}}
                        }
                    }
                },
            }
        },
        "/patients/lookup": {
            "post": {
                "operationId": "lookup_patient",
                "parameters": [],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/PatientLookupRequest"}
                        }
                    }
                },
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Patient"}}
                        }
                    }
                },
            }
        },
        "/appointments/{appointment_id}": {
            "get": {
                "operationId": "get_appointment",
                "parameters": [
                    {
                        "name": "appointment_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Appointment"}
                            }
                        }
                    }
                },
            }
        },
        "/doctors/{doctor_id}": {
            "get": {
                "operationId": "get_doctor",
                "parameters": [
                    {
                        "name": "doctor_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    }
                ],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/Doctor"}}
                        }
                    }
                },
            }
        },
    },
}

_OPERATIONS = parse_openapi(_SPEC)


def test_build_dependency_graph_finds_appointments_to_patients_path_edge():
    edges = build_dependency_graph(_SPEC, _OPERATIONS)
    matches = [
        e
        for e in edges
        if e.field_name == "patient_id"
        and e.producer_path == "/appointments/{appointment_id}"
        and e.consumer_path == "/patients/{patient_id}"
    ]
    assert len(matches) == 1
    assert matches[0].consumer_param_location == "path"


def test_build_dependency_graph_finds_body_based_edge():
    edges = build_dependency_graph(_SPEC, _OPERATIONS)
    matches = [
        e for e in edges if e.field_name == "patient_id" and e.consumer_path == "/patients/lookup"
    ]
    assert len(matches) == 1
    assert matches[0].consumer_param_location == "body"


def test_build_dependency_graph_excludes_non_identifier_fields():
    edges = build_dependency_graph(_SPEC, _OPERATIONS)
    assert all(e.field_name != "name" for e in edges)


def test_build_dependency_graph_no_self_loops():
    edges = build_dependency_graph(_SPEC, _OPERATIONS)
    for e in edges:
        assert (e.producer_method, e.producer_path) != (e.consumer_method, e.consumer_path)


def test_build_dependency_graph_total_edge_count():
    edges = build_dependency_graph(_SPEC, _OPERATIONS)
    # appointments->patients(path), appointments->patients/lookup(body),
    # appointments->doctors(path) via doctor_id
    assert len(edges) == 3


def test_build_dependency_graph_operation_with_no_2xx_response_has_no_producer_fields():
    spec = {
        "openapi": "3.1.0",
        "paths": {
            "/broken": {
                "get": {
                    "operationId": "broken",
                    "parameters": [],
                    "responses": {"404": {"description": "nope"}},
                }
            },
            "/patients/{patient_id}": _SPEC["paths"]["/patients/{patient_id}"],
        },
    }
    ops = parse_openapi(spec)
    edges = build_dependency_graph(spec, ops)
    assert edges == []


def test_dependency_graph_to_dict_round_trips_fields():
    edges = build_dependency_graph(_SPEC, _OPERATIONS)
    serialized = dependency_graph_to_dict(edges)
    assert len(serialized) == len(edges)
    expected_keys = {
        "field_name",
        "producer_method",
        "producer_path",
        "consumer_method",
        "consumer_path",
        "consumer_param_location",
    }
    assert all(set(d.keys()) == expected_keys for d in serialized)


def test_plan_sequences_matches_edge_count_and_fields():
    edges = build_dependency_graph(_SPEC, _OPERATIONS)
    sequences = plan_sequences(edges)
    assert len(sequences) == len(edges)
    for seq, edge in zip(sequences, edges, strict=True):
        assert seq.producer_path == edge.producer_path
        assert seq.consumer_path == edge.consumer_path
        assert seq.linking_field == edge.field_name


def test_dependency_coverage_all_operations_involved():
    edges = build_dependency_graph(_SPEC, _OPERATIONS)
    coverage = dependency_coverage(_OPERATIONS, edges)
    assert coverage == 1.0


def test_dependency_coverage_empty_edges_is_zero():
    coverage = dependency_coverage(_OPERATIONS, [])
    assert coverage == 0.0


def test_dependency_coverage_empty_operations_is_zero():
    coverage = dependency_coverage([], [])
    assert coverage == 0.0


def test_plan_bola_probes_wraps_every_edge_as_bola():
    edges = build_dependency_graph(_SPEC, _OPERATIONS)
    probes = plan_bola_probes(edges)
    assert len(probes) == len(edges)
    assert all(p.vuln_class == VulnerabilityClass.BOLA for p in probes)
    assert all(isinstance(p, BolaProbe) for p in probes)


def test_plan_bola_probes_records_param_location_per_target():
    edges = build_dependency_graph(_SPEC, _OPERATIONS)
    probes = plan_bola_probes(edges)

    path_probes = [p for p in probes if p.attack_path == "/patients/{patient_id}"]
    assert len(path_probes) == 1
    assert path_probes[0].param_location == "path"
    assert path_probes[0].setup_path == "/appointments/{appointment_id}"

    body_probes = [p for p in probes if p.attack_path == "/patients/lookup"]
    assert len(body_probes) == 1
    assert body_probes[0].param_location == "body"
