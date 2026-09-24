"""
tracesec.llm_adapter

A thin, provider-agnostic wrapper around an LLM completion call, with a
mandatory record/replay cache: every (model, prompt, temperature) tuple
is hashed to a cache key, and a cached response is returned verbatim
without any network call. This makes LLM-involving runs reproducible
(the same key always returns the same completion) and means a full
evaluation run needs to hit the network only once per unique prompt,
not once per run.

The adapter takes a `complete_fn` callable rather than importing any
specific provider's SDK, so it can be pointed at any OpenAI-compatible
API (or a test double) without a hard dependency here.
"""

import hashlib
import json
from pathlib import Path
from typing import Protocol


class CompletionError(Exception):
    """Raised when a completion is needed but no cached entry exists
    and no live completion function was configured."""


class CompleteFn(Protocol):
    def __call__(self, model: str, prompt: str, temperature: float) -> str: ...


def _cache_key(model: str, prompt: str, temperature: float) -> str:
    payload = json.dumps(
        {"model": model, "prompt": prompt, "temperature": temperature},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class LLMAdapter:
    """Wraps an LLM completion call with a mandatory record/replay
    cache, persisted as JSON at `cache_path`.

    complete_fn is optional: if omitted, this adapter can only replay
    from an existing cache and raises CompletionError on any cache
    miss. This makes "replay-only" mode (used in CI, and for
    reproducing a past evaluation run exactly) an explicit, safe
    default rather than something that accidentally makes live network
    calls.
    """

    def __init__(
        self,
        cache_path: str | Path,
        complete_fn: CompleteFn | None = None,
    ) -> None:
        self._cache_path = Path(cache_path)
        self._complete_fn = complete_fn
        self._cache: dict[str, str] = {}
        if self._cache_path.exists():
            self._cache = json.loads(self._cache_path.read_text(encoding="utf-8"))

    def complete(self, model: str, prompt: str, temperature: float = 0.0) -> str:
        key = _cache_key(model, prompt, temperature)
        if key in self._cache:
            return self._cache[key]

        if self._complete_fn is None:
            raise CompletionError(
                "no cached completion for this (model, prompt, temperature) "
                f"and no live completion function configured (key={key[:12]}...)"
            )

        result = self._complete_fn(model=model, prompt=prompt, temperature=temperature)
        self._cache[key] = result
        self._save()
        return result

    def _save(self) -> None:
        self._cache_path.parent.mkdir(parents=True, exist_ok=True)
        self._cache_path.write_text(
            json.dumps(self._cache, indent=2, sort_keys=True), encoding="utf-8"
        )

    @property
    def cache_size(self) -> int:
        return len(self._cache)
