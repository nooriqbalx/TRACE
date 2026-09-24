"""
Unit tests for tracesec.evidence: hash-chained, redacted evidence store.
"""

import dataclasses
import json

from tracesec.evidence import GENESIS_HASH, EvidenceStore, redact_body, redact_headers


def _add_sample(store, session_id="user-a", url="https://good.test/a"):
    return store.add(
        session_id=session_id,
        method="GET",
        url=url,
        request_headers={"Authorization": "Bearer secret-token-123"},
        request_body=None,
        response_status=200,
        response_headers={"Content-Type": "application/json"},
        response_body='{"id": 1, "name": "Alice"}',
        elapsed_seconds=0.01,
    )


def test_first_record_chains_from_genesis(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    record = _add_sample(store)
    assert record.prev_hash == GENESIS_HASH
    assert record.index == 0


def test_records_chain_sequentially(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    r1 = _add_sample(store, url="https://good.test/a")
    r2 = _add_sample(store, url="https://good.test/b")
    assert r2.prev_hash == r1.content_hash
    assert r2.index == 1


def test_verify_chain_true_for_untouched_store(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    _add_sample(store)
    _add_sample(store)
    assert store.verify_chain() is True


def test_verify_chain_true_for_empty_store(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    assert store.verify_chain() is True


def test_verify_chain_false_after_in_memory_tampering(tmp_path):
    store = EvidenceStore(tmp_path / "evidence.jsonl")
    _add_sample(store)
    _add_sample(store)

    tampered = dataclasses.replace(store._records[0], response_body="tampered data")
    store._records[0] = tampered

    assert store.verify_chain() is False


def test_persistence_round_trip(tmp_path):
    path = tmp_path / "evidence.jsonl"
    store1 = EvidenceStore(path)
    _add_sample(store1)
    _add_sample(store1)

    store2 = EvidenceStore(path)
    assert len(store2.records) == 2
    assert store2.verify_chain() is True
    assert store2.records[0].content_hash == store1.records[0].content_hash


def test_tampering_on_disk_is_detected(tmp_path):
    path = tmp_path / "evidence.jsonl"
    store1 = EvidenceStore(path)
    _add_sample(store1)
    _add_sample(store1)

    lines = path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["response_body"] = '{"id": 1, "name": "Mallory"}'
    lines[0] = json.dumps(first)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    store2 = EvidenceStore(path)
    assert store2.verify_chain() is False


def test_redact_headers_authorization():
    headers = redact_headers({"Authorization": "Bearer secret-token-123"})
    assert headers["Authorization"] == "[REDACTED]"


def test_redact_headers_cookie():
    headers = redact_headers({"Cookie": "session=abc123"})
    assert headers["Cookie"] == "[REDACTED]"


def test_redact_headers_leaves_ordinary_headers_alone():
    headers = redact_headers({"Content-Type": "application/json"})
    assert headers["Content-Type"] == "application/json"


def test_redact_body_password_field():
    body = '{"email": "a@example.com", "password": "hunter2"}'
    result = redact_body(body)
    assert "hunter2" not in result
    assert "a@example.com" in result


def test_redact_body_bearer_token_inline():
    body = "the header was Bearer abc.def-123_xyz sent with the request"
    result = redact_body(body)
    assert "abc.def-123_xyz" not in result
    assert "[REDACTED]" in result


def test_redact_body_none_and_empty_are_passthrough():
    assert redact_body(None) is None
    assert redact_body("") == ""


def test_add_redacts_before_writing_to_disk(tmp_path):
    path = tmp_path / "evidence.jsonl"
    store = EvidenceStore(path)
    _add_sample(store)

    raw = path.read_text(encoding="utf-8")
    assert "secret-token-123" not in raw
    assert "[REDACTED]" in raw
