"""
tracesec.evidence

A tamper-evident, content-addressed store for request/response evidence.

Every record's hash chains from the hash of the record before it (a
simple hash chain), so any modification to a past record -- including
deleting or reordering records, or editing one record's content without
also updating everything chained after it -- changes the recomputed
hash and is detectable by EvidenceStore.verify_chain().

Secrets (tokens, passwords, API keys) are redacted from headers and
bodies before a record is ever written to disk. Redaction happens once,
at write time, not as an afterthought at read time.
"""

import hashlib
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64
_REDACTED = "[REDACTED]"

_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-session-token",
    "proxy-authorization",
}

_KV_SECRET_PATTERN = re.compile(
    r'("(?:password|token|secret|api_key|otp)"\s*:\s*")([^"]*)(")',
    re.IGNORECASE,
)
_BEARER_PATTERN = re.compile(r"(Bearer\s+)([A-Za-z0-9\-_.]+)")


def redact_body(text: str | None) -> str | None:
    """Return a copy of text with recognizable secret patterns replaced.

    This is deliberately conservative pattern matching, not a general
    secret scanner: structured fields named password/token/secret/
    api_key/otp are redacted, as are bearer tokens. It will not catch
    every possible secret shape; it exists to keep the common cases
    (the ones TRACE itself generates and handles) out of the evidence
    store.
    """
    if not text:
        return text
    result = _KV_SECRET_PATTERN.sub(rf"\1{_REDACTED}\3", text)
    result = _BEARER_PATTERN.sub(rf"\1{_REDACTED}", result)
    return result


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with sensitive values replaced."""
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in _SENSITIVE_HEADER_NAMES:
            redacted[key] = _REDACTED
        else:
            scanned = redact_body(value)
            redacted[key] = scanned if scanned is not None else value
    return redacted


def _compute_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvidenceRecord:
    """One request/response pair, with its position in the hash chain."""

    index: int
    timestamp: float
    session_id: str
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str | None
    response_status: int
    response_headers: dict[str, str]
    response_body: str | None
    elapsed_seconds: float
    prev_hash: str
    content_hash: str

    def payload(self) -> dict[str, Any]:
        """The fields this record's own hash is computed over --
        everything except content_hash itself."""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "elapsed_seconds": self.elapsed_seconds,
            "prev_hash": self.prev_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.payload()
        data["content_hash"] = self.content_hash
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceRecord:
        return cls(
            index=data["index"],
            timestamp=data["timestamp"],
            session_id=data["session_id"],
            method=data["method"],
            url=data["url"],
            request_headers=data["request_headers"],
            request_body=data["request_body"],
            response_status=data["response_status"],
            response_headers=data["response_headers"],
            response_body=data["response_body"],
            elapsed_seconds=data["elapsed_seconds"],
            prev_hash=data["prev_hash"],
            content_hash=data["content_hash"],
        )


class EvidenceStore:
    """An append-only, hash-chained store of EvidenceRecords, persisted
    as JSON Lines (one record per line) at `path`.

    Records are written to disk immediately as they are added, so a
    crash mid-run loses at most the record currently being written,
    never a previously-committed one.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._records: list[EvidenceRecord] = []
        if self._path.exists():
            self._load()

    def _load(self) -> None:
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    self._records.append(EvidenceRecord.from_dict(json.loads(stripped)))

    @property
    def records(self) -> list[EvidenceRecord]:
        return list(self._records)

    def add(
        self,
        *,
        session_id: str,
        method: str,
        url: str,
        request_headers: dict[str, str],
        request_body: str | None,
        response_status: int,
        response_headers: dict[str, str],
        response_body: str | None,
        elapsed_seconds: float,
    ) -> EvidenceRecord:
        prev_hash = self._records[-1].content_hash if self._records else GENESIS_HASH
        index = len(self._records)
        timestamp = time.time()
        req_headers = redact_headers(request_headers)
        req_body = redact_body(request_body)
        resp_headers = redact_headers(response_headers)
        resp_body = redact_body(response_body)

        payload: dict[str, Any] = {
            "index": index,
            "timestamp": timestamp,
            "session_id": session_id,
            "method": method,
            "url": url,
            "request_headers": req_headers,
            "request_body": req_body,
            "response_status": response_status,
            "response_headers": resp_headers,
            "response_body": resp_body,
            "elapsed_seconds": elapsed_seconds,
            "prev_hash": prev_hash,
        }
        content_hash = _compute_hash(payload)

        record = EvidenceRecord(
            index=index,
            timestamp=timestamp,
            session_id=session_id,
            method=method,
            url=url,
            request_headers=req_headers,
            request_body=req_body,
            response_status=response_status,
            response_headers=resp_headers,
            response_body=resp_body,
            elapsed_seconds=elapsed_seconds,
            prev_hash=prev_hash,
            content_hash=content_hash,
        )
        self._records.append(record)
        self._append_to_disk(record)
        return record

    def _append_to_disk(self, record: EvidenceRecord) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_dict(), sort_keys=True, default=str))
            f.write("\n")

    def verify_chain(self) -> bool:
        """Return True if every record's stored content_hash matches a
        freshly recomputed hash of its payload, and every record's
        prev_hash correctly points at the previous record's hash.
        Returns True for an empty store.
        """
        expected_prev = GENESIS_HASH
        for record in self._records:
            if record.prev_hash != expected_prev:
                return False
            if _compute_hash(record.payload()) != record.content_hash:
                return False
            expected_prev = record.content_hash
        return True

    def get(self, index: int) -> EvidenceRecord | None:
        if 0 <= index < len(self._records):
            return self._records[index]
        return None
