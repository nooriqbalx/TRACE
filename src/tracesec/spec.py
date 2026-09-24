"""
tracesec.spec

Parses an OpenAPI 3.x document (as a Python dict, e.g. loaded from a
target's /openapi.json) into a normalized list of Operations that the
rest of TRACE reasons about, independent of the OpenAPI JSON shape.
"""

from dataclasses import dataclass, field
from typing import Any

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


class InvalidSpecError(Exception):
    """Raised when the input does not look like a usable OpenAPI 3.x
    document."""


@dataclass(frozen=True)
class Parameter:
    name: str
    location: str
    required: bool
    schema_type: str | None


@dataclass(frozen=True)
class Operation:
    operation_id: str | None
    method: str
    path: str
    parameters: list[Parameter]
    has_request_body: bool
    tags: list[str] = field(default_factory=list)


def parse_openapi(spec: dict[str, Any]) -> list[Operation]:
    """Parse an OpenAPI 3.x document dict into a list of Operations.

    Only the fields TRACE currently needs are extracted; unknown or
    extra fields in the spec are ignored rather than rejected, since
    target specs are not under our control.
    """
    if "openapi" not in spec or not str(spec["openapi"]).startswith("3."):
        raise InvalidSpecError("expected an OpenAPI 3.x document with an 'openapi' field")
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        raise InvalidSpecError("OpenAPI document has no usable 'paths' object")

    operations: list[Operation] = []
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, op in path_item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            parameters = [
                Parameter(
                    name=p.get("name", ""),
                    location=p.get("in", "query"),
                    required=bool(p.get("required", False)),
                    schema_type=(p.get("schema") or {}).get("type"),
                )
                for p in op.get("parameters", [])
                if isinstance(p, dict)
            ]
            operations.append(
                Operation(
                    operation_id=op.get("operationId"),
                    method=method.upper(),
                    path=path,
                    parameters=parameters,
                    has_request_body="requestBody" in op,
                    tags=list(op.get("tags", [])),
                )
            )
    return operations
