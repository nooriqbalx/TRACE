"""
Unit tests for tracesec.scope: the allowlist-enforcing HTTP client.

Uses httpx.MockTransport so these tests make no real network calls and
need no testbed running. The redirect tests are the important ones:
they exercise THREAT_MODEL.md's T1 (scope escape).
"""

import httpx
import pytest

from tracesec.scope import ScopedClient, ScopeError, ScopeGuard


def test_scopeguard_rejects_empty_allowlist():
    with pytest.raises(ValueError, match="at least one allowed host"):
        ScopeGuard(set())


def test_scopeguard_allows_listed_host():
    guard = ScopeGuard({"example.com"})
    assert guard.is_allowed("https://example.com/foo")


def test_scopeguard_blocks_unlisted_host():
    guard = ScopeGuard({"example.com"})
    assert not guard.is_allowed("https://evil.com/foo")


def test_scopeguard_host_match_is_case_insensitive():
    guard = ScopeGuard({"Example.COM"})
    assert guard.is_allowed("https://example.com/foo")


def test_scopeguard_port_specific_entry():
    guard = ScopeGuard({"example.com:8888"})
    assert guard.is_allowed("https://example.com:8888/foo")
    assert not guard.is_allowed("https://example.com:9999/foo")


def test_scopeguard_check_raises_on_unlisted_host():
    guard = ScopeGuard({"example.com"})
    with pytest.raises(ScopeError):
        guard.check("https://evil.com/foo")


def _transport(handler):
    return httpx.MockTransport(handler)


def test_scopedclient_sends_direct_in_scope_request():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "good.test"
        return httpx.Response(200, json={"ok": True})

    guard = ScopeGuard({"good.test"})
    with ScopedClient(guard, transport=_transport(handler)) as client:
        r = client.get("https://good.test/data")
    assert r.status_code == 200


def test_scopedclient_blocks_direct_off_scope_request():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("transport must not be called for an off-scope host")

    guard = ScopeGuard({"good.test"})
    with (
        ScopedClient(guard, transport=_transport(handler)) as client,
        pytest.raises(ScopeError),
    ):
        client.get("https://evil.test/data")


def test_scopedclient_follows_in_scope_redirect():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://good.test/end"})
        return httpx.Response(200, json={"ok": True})

    guard = ScopeGuard({"good.test"})
    with ScopedClient(guard, transport=_transport(handler)) as client:
        r = client.get("https://good.test/start")
    assert r.status_code == 200


def test_scopedclient_blocks_redirect_to_off_scope_host():
    """The core threat-model test: a target that tries to redirect the
    scanner off its allowlist (T1) must be blocked before the
    off-scope request is ever sent."""
    called_off_scope = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called_off_scope
        if request.url.host == "evil.test":
            called_off_scope = True
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "https://evil.test/steal"})
        return httpx.Response(200)

    guard = ScopeGuard({"good.test"})
    with (
        ScopedClient(guard, transport=_transport(handler)) as client,
        pytest.raises(ScopeError),
    ):
        client.get("https://good.test/start")

    assert not called_off_scope, "the off-scope host must never receive a request"
