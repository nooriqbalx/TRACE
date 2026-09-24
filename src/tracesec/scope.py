"""
tracesec.scope

Enforces TRACE's target allowlist at the HTTP client layer. No request
this client sends -- including any redirect hop -- reaches a host
outside the explicit allowlist. This is the mechanical backstop for the
allowlist requirement in RESPONSIBLE_USE.md and mitigates threat T1
(scope escape) in THREAT_MODEL.md.

Design choices:
- Redirects are followed manually, one hop at a time, with every
  resulting URL re-checked against the allowlist. httpx's built-in
  follow_redirects=True would perform the redirect before we get a
  chance to inspect it, which defeats the purpose.
- Allowlist entries match on hostname (case-insensitive), optionally
  with an exact port ("host" or "host:port"). Wildcards are not
  supported by design: a pattern-based allowlist is easy to
  misconfigure into something broader than intended.
- The same HTTP method is reused across every redirect hop in this
  first cut. A stricter implementation would downgrade to GET on a
  303, per RFC 7231; noted here as a known simplification.
"""

from typing import Any
from urllib.parse import urlsplit

import httpx

MAX_REDIRECTS = 5


class ScopeError(Exception):
    """Raised when a request, or a redirect hop, would leave the
    target allowlist."""


class ScopeGuard:
    """Checks whether a URL's host (and optional port) is on the
    allowlist.

    allowed_hosts entries look like "host" (any port) or "host:port"
    (exact port only). Hostname comparison is case-insensitive.
    """

    def __init__(self, allowed_hosts: set[str]) -> None:
        if not allowed_hosts:
            raise ValueError(
                "ScopeGuard requires at least one allowed host; refusing to run unscoped"
            )
        self._allowed_hosts = {h.lower() for h in allowed_hosts}

    def is_allowed(self, url: str) -> bool:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if not host:
            return False
        if host in self._allowed_hosts:
            return True
        if parts.port is not None:
            return f"{host}:{parts.port}" in self._allowed_hosts
        return False

    def check(self, url: str) -> None:
        if not self.is_allowed(url):
            raise ScopeError(f"URL is outside the target allowlist: {url}")


class ScopedClient:
    """An httpx.Client wrapper that enforces a ScopeGuard on every
    request, including every hop of a redirect chain."""

    def __init__(
        self,
        guard: ScopeGuard,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._guard = guard
        # follow_redirects is deliberately False: we follow manually
        # below so every hop can be scope-checked before it is sent.
        self._client = httpx.Client(transport=transport, follow_redirects=False, timeout=timeout)

    def __enter__(self) -> ScopedClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        self._guard.check(url)
        response = self._client.request(method, url, **kwargs)

        hops = 0
        while response.is_redirect and hops < MAX_REDIRECTS:
            location = response.headers.get("location")
            if location is None:
                break
            next_url = str(response.url.join(location))
            self._guard.check(next_url)
            response = self._client.request(method, next_url, **kwargs)
            hops += 1

        return response

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> httpx.Response:
        return self.request("PUT", url, **kwargs)
