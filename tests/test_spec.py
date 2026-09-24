"""
Unit tests for tracesec.spec: OpenAPI 3.x -> normalized Operation list.
"""

import pytest

from tracesec.spec import InvalidSpecError, parse_openapi

_MINIMAL_SPEC = {
    "openapi": "3.0.2",
    "info": {"title": "Test", "version": "0.1.0"},
    "paths": {
        "/patients/{patient_id}": {
            "get": {
                "operationId": "get_patient",
                "tags": ["bola-direct-path"],
                "parameters": [
                    {
                        "name": "patient_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "integer"},
                    },
                    {
                        "name": "x_user_id",
                        "in": "header",
                        "required": False,
                        "schema": {"type": "integer"},
                    },
                ],
            }
        },
        "/patients/lookup": {
            "post": {
                "operationId": "lookup_patient",
                "tags": ["bola-body-id"],
                "requestBody": {"content": {"application/json": {"schema": {}}}},
                "parameters": [],
            }
        },
    },
}


def test_parse_openapi_extracts_operations():
    operations = parse_openapi(_MINIMAL_SPEC)
    assert len(operations) == 2

    get_patient = next(op for op in operations if op.operation_id == "get_patient")
    assert get_patient.method == "GET"
    assert get_patient.path == "/patients/{patient_id}"
    assert get_patient.has_request_body is False
    assert "bola-direct-path" in get_patient.tags

    path_params = [p for p in get_patient.parameters if p.location == "path"]
    assert len(path_params) == 1
    assert path_params[0].name == "patient_id"
    assert path_params[0].required is True
    assert path_params[0].schema_type == "integer"


def test_parse_openapi_detects_request_body():
    operations = parse_openapi(_MINIMAL_SPEC)
    lookup = next(op for op in operations if op.operation_id == "lookup_patient")
    assert lookup.method == "POST"
    assert lookup.has_request_body is True


def test_parse_openapi_rejects_non_openapi3():
    with pytest.raises(InvalidSpecError):
        parse_openapi({"swagger": "2.0", "paths": {}})


def test_parse_openapi_rejects_missing_paths():
    with pytest.raises(InvalidSpecError):
        parse_openapi({"openapi": "3.0.2"})


def test_parse_openapi_ignores_non_method_keys_in_path_item():
    spec = {
        "openapi": "3.1.0",
        "paths": {
            "/health": {
                "get": {"operationId": "health"},
                "parameters": [],
                "summary": "health path",
            }
        },
    }
    operations = parse_openapi(spec)
    assert len(operations) == 1
    assert operations[0].operation_id == "health"
