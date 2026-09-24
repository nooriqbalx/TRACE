"""
tracesec.executor

Ties the ScopeGuard-enforced HTTP client to the EvidenceStore: every
request the executor sends is timed, recorded (with secrets redacted),
and chained into the store before the response is handed back to the
caller. A per-run request cap and an explicit kill switch bound how
much traffic a run can generate, per THREAT_MODEL.md T6 (accidental
DoS) and RESPONSIBLE_USE.md.
"""

import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

from tracesec.evidence import EvidenceRecord, EvidenceStore
from tracesec.scope import ScopedClient


class RequestCapExceeded(Exception):
    """Raised when a run would exceed its configured max_requests."""


class ExecutorStopped(Exception):
    """Raised when a request is attempted after stop() has been called."""


@dataclass
class ExecutionResult:
    response: httpx.Response
    evidence: EvidenceRecord


class Executor:
    """Sends HTTP requests through a ScopedClient, logging every one
    (request + response, redacted) to an EvidenceStore.

    max_requests bounds the total number of requests this executor will
    send in its lifetime; the (max_requests + 1)th call raises
    RequestCapExceeded before any request is sent. stop() is an
    explicit kill switch: once called, every subsequent call raises
    ExecutorStopped, also before any request is sent.
    """

    def __init__(
        self,
        client: ScopedClient,
        evidence: EvidenceStore,
        session_id: str,
        max_requests: int = 1000,
    ) -> None:
        self._client = client
        self._evidence = evidence
        self._session_id = session_id
        self._max_requests = max_requests
        self._sent = 0
        self._stopped = False

    @property
    def sent_count(self) -> int:
        return self._sent

    def stop(self) -> None:
        self._stopped = True

    def _extract_request_body(self, kwargs: dict[str, Any]) -> str | None:
        content = kwargs.get("content")
        if content is not None:
            if isinstance(content, bytes):
                return content.decode("utf-8", errors="replace")
            return str(content)
        json_body = kwargs.get("json")
        if json_body is not None:
            return json.dumps(json_body)
        return None

    def request(self, method: str, url: str, **kwargs: Any) -> ExecutionResult:
        if self._stopped:
            raise ExecutorStopped("executor has been stopped")
        if self._sent >= self._max_requests:
            raise RequestCapExceeded(f"request cap of {self._max_requests} reached")

        request_headers = dict(kwargs.get("headers") or {})
        request_body = self._extract_request_body(kwargs)

        start = time.monotonic()
        response = self._client.request(method, url, **kwargs)
        elapsed = time.monotonic() - start
        self._sent += 1

        evidence = self._evidence.add(
            session_id=self._session_id,
            method=method,
            url=url,
            request_headers=request_headers,
            request_body=request_body,
            response_status=response.status_code,
            response_headers=dict(response.headers),
            response_body=response.text,
            elapsed_seconds=elapsed,
        )
        return ExecutionResult(response=response, evidence=evidence)

    def get(self, url: str, **kwargs: Any) -> ExecutionResult:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> ExecutionResult:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> ExecutionResult:
        return self.request("PUT", url, **kwargs)
