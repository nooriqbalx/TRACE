"""
Unit tests for tracesec.executor: ties ScopedClient to EvidenceStore,
enforcing a request cap and an explicit kill switch.
"""

import httpx
import pytest

from tracesec.evidence import EvidenceStore
from tracesec.executor import Executor, ExecutorStopped, RequestCapExceeded
from tracesec.scope import ScopedClient, ScopeError, ScopeGuard


def _make_executor(tmp_path, handler, max_requests=1000):
    guard = ScopeGuard({"good.test"})
    client = ScopedClient(guard, transport=httpx.MockTransport(handler))
    evidence = EvidenceStore(tmp_path / "evidence.jsonl")
    executor = Executor(client, evidence, session_id="user-a", max_requests=max_requests)
    return executor, evidence


def test_executor_logs_request_and_response(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"id": 1})

    executor, evidence = _make_executor(tmp_path, handler)
    result = executor.get("https://good.test/patients/1", headers={"X-User-Id": "1"})

    assert result.response.status_code == 200
    assert len(evidence.records) == 1
    record = evidence.records[0]
    assert record.method == "GET"
    assert record.url == "https://good.test/patients/1"
    assert record.response_status == 200
    assert evidence.verify_chain()


def test_executor_respects_request_cap(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    executor, _ = _make_executor(tmp_path, handler, max_requests=2)
    executor.get("https://good.test/a")
    executor.get("https://good.test/b")
    with pytest.raises(RequestCapExceeded):
        executor.get("https://good.test/c")
    assert executor.sent_count == 2


def test_executor_stop_blocks_further_requests(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    executor, _ = _make_executor(tmp_path, handler)
    executor.get("https://good.test/a")
    executor.stop()
    with pytest.raises(ExecutorStopped):
        executor.get("https://good.test/b")
    assert executor.sent_count == 1


def test_executor_redacts_authorization_header_in_evidence(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200)

    executor, evidence = _make_executor(tmp_path, handler)
    executor.get(
        "https://good.test/secure",
        headers={"Authorization": "Bearer super-secret-token"},
    )
    record = evidence.records[0]
    assert record.request_headers["Authorization"] == "[REDACTED]"
    assert "super-secret-token" not in str(evidence.records)


def test_executor_off_scope_request_is_blocked_and_not_logged(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("off-scope host must never be called")

    executor, evidence = _make_executor(tmp_path, handler)
    with pytest.raises(ScopeError):
        executor.get("https://evil.test/data")
    assert len(evidence.records) == 0
    assert executor.sent_count == 0
