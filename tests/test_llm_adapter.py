"""
Unit tests for tracesec.llm_adapter: mandatory record/replay cache.

No real network calls or API keys are used here -- completions are
supplied by a small counting fake, which is exactly the point: the
adapter's job is to make LLM-involving runs reproducible and to avoid
redundant network calls, not to talk to any specific provider.
"""

import pytest

from tracesec.llm_adapter import CompletionError, LLMAdapter


class _FakeCompleter:
    def __init__(self, response="fake completion"):
        self.calls = 0
        self._response = response

    def __call__(self, model, prompt, temperature):
        self.calls += 1
        return self._response


def test_cache_miss_calls_complete_fn_and_caches(tmp_path):
    fake = _FakeCompleter()
    adapter = LLMAdapter(tmp_path / "cache.json", complete_fn=fake)

    result = adapter.complete(model="m1", prompt="hello", temperature=0.0)

    assert result == "fake completion"
    assert fake.calls == 1
    assert adapter.cache_size == 1


def test_cache_hit_does_not_call_complete_fn_again(tmp_path):
    fake = _FakeCompleter()
    adapter = LLMAdapter(tmp_path / "cache.json", complete_fn=fake)

    adapter.complete(model="m1", prompt="hello", temperature=0.0)
    adapter.complete(model="m1", prompt="hello", temperature=0.0)

    assert fake.calls == 1


def test_raises_without_complete_fn_on_cache_miss(tmp_path):
    adapter = LLMAdapter(tmp_path / "cache.json", complete_fn=None)
    with pytest.raises(CompletionError):
        adapter.complete(model="m1", prompt="hello", temperature=0.0)


def test_cache_persists_to_disk_and_reloads(tmp_path):
    cache_path = tmp_path / "cache.json"
    fake = _FakeCompleter(response="first answer")
    adapter1 = LLMAdapter(cache_path, complete_fn=fake)
    adapter1.complete(model="m1", prompt="hello", temperature=0.0)

    adapter2 = LLMAdapter(cache_path, complete_fn=None)
    result = adapter2.complete(model="m1", prompt="hello", temperature=0.0)
    assert result == "first answer"


def test_different_prompts_get_different_cache_entries(tmp_path):
    fake = _FakeCompleter()
    adapter = LLMAdapter(tmp_path / "cache.json", complete_fn=fake)

    adapter.complete(model="m1", prompt="prompt A", temperature=0.0)
    adapter.complete(model="m1", prompt="prompt B", temperature=0.0)

    assert fake.calls == 2
    assert adapter.cache_size == 2
