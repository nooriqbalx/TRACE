# Phase 8: Full Evaluation Run (C1-C5) — TRACE-Bench

**Date:** 25 September 2026
**Target:** TRACE-Bench (unpatched/vulnerable mode)
**Model:** openai/gpt-oss-120b via Groq, temperature 0.0, 3 seeds per LLM config

## Results

| Config | TP | FP | FN | Precision | Recall | F1 |
|--------|----|----|----|-----------|--------|-----|
| C1 (ZAP, reused from prior live run) | 0 | 0 | 16 | 0.00 | 0.00 | 0.00 |
| C2 (LLM-only) | 6 | 9 | 10 | 0.40 | 0.38 | 0.39 |
| C3 (dependency-aware LLM) | 4 | 11 | 12 | 0.27 | 0.25 | 0.26 |
| C4 (evidence-grounded) | 1 | 0 | 15 | 1.00 | 0.06 | 0.12 |
| C5 (full TRACE, verified) | 1 | 0 | 15 | 1.00 | 0.06 | 0.12 |

C1's row is reused from a prior independently-run, documented live ZAP
scan (docs/lab/zap-baseline-smoke-run.md), not re-executed this run.

## Critical finding: dependency graph was empty on this run (0 edges)

`build_dependency_graph` returned zero edges against TRACE-Bench's
real, live-generated OpenAPI spec, despite finding 3 edges (including
the appointments -> patients relationship) against a hand-built
fixture spec in tests/test_dependency.py.

**Root cause:** TRACE-Bench's endpoints are typed to return
`dict[str, object]` in Python (see bench/tracebench/main.py). FastAPI
cannot enumerate specific field names from an untyped dict return
type, so it emits an open-ended schema
(`{"type": "object", "additionalProperties": true}`) with no
`properties` key, rather than naming fields like `patient_id`.
tracesec.dependency's inference is schema-based (static) only, reading
exclusively from each operation's declared `properties` — exactly the
limitation already flagged in that module's own docstring. This is the
first concrete, real-world case of that documented limitation actually
firing, not a new bug.

**Consequence:** C3 (dependency-aware) ran this pass with an empty
dependency graph, so `build_prompt_with_dependencies` correctly fell
back to the same prompt as C2 (per its own tested fallback behavior).
**C3's numbers above do not measure dependency-awareness** — they
reflect a second, independently-cached C2-equivalent run at the same
temperature and are reported here for completeness, not as evidence
about C3's actual mechanism. A genuine C3 test requires either (a)
typing TRACE-Bench's response models with concrete Pydantic schemas
so FastAPI can enumerate fields, or (b) extending
tracesec.dependency to infer edges from real observed response
content (traffic-based inference), which the module's docstring
already lists as a documented future extension. Neither has been done
yet; this is an open item, not a silent gap.

## C4/C5: precision 1.00, recall 0.06 — narrow prober coverage, as designed

C4 only grounds a finding if this run's prober can construct a real
probe for it; PROBE_STRATEGIES in
experiments/eval-run-1/run_full_evaluation.py covers exactly 2 of the
16 ground-truth endpoints (direct-path BOLA on /patients/{id} and
/appointments/{id}). All 14 other C3-proposed findings were correctly
rejected as unprobeable — tracesec.pipeline working exactly as
designed (see its own docstring: "TRACE only reports what it can
actually probe"). This yields perfect precision (every grounded,
verified finding was real) at the cost of very low recall (most
ground-truth vulnerabilities have no prober yet).

This is the expected, correct shape of an evidence-grounded system
with incomplete prober coverage: it should never be wrong, but it will
under-report until every vulnerability class has a real probe
strategy. Building out PROBE_STRATEGIES for the remaining classes
(broken auth, exposure, rate-limiting — verify_exposure and
verify_unthrottled already exist and are tested in
tracesec.verifier, they are simply not yet wired into this run's
prober) is the direct next step, not a design flaw.

## What this run actually demonstrates

- C1 vs C2: a generic fuzzer finds none of these bugs; spec-reasoning
  finds some, confirming last night's smoke-run result.
- C4/C5 vs C2/C3: grounding and verification trade recall for
  precision, exactly as intended — zero false positives, at the cost
  of only reporting what could be actually proven this run.
- The empty dependency graph is itself a genuine, worked example of
  why tracesec.dependency's docstring already scopes static schema
  inference as limited, and motivates the traffic-based extension
  named there.

## Open items for a follow-up run

- [ ] Type TRACE-Bench's response models with concrete Pydantic
      schemas (or extend dependency.py to infer from live response
      content) so C3 gets a genuine dependency graph to reason over.
- [ ] Extend PROBE_STRATEGIES to cover broken-authentication,
      excessive-exposure, and rate-limiting endpoints so C4/C5's
      recall reflects verifier coverage, not just prober coverage.
- [ ] Re-run with the above in place before this table is treated as
      final for REPORT.md.
