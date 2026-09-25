# C2 (LLM-only scanner) Baseline Smoke-Run — TRACE-Bench

**Date:** 25 September 2026
**Target:** TRACE-Bench (unpatched/vulnerable mode), http://localhost:9000
**Model:** openai/gpt-oss-120b via Groq (free tier)
**Temperature:** 0.0
**Input:** 29 operations parsed from TRACE-Bench's live OpenAPI spec via `tracesec.spec.parse_openapi`

## Command

```bash
uv run python experiments/llm-run-1/run_llm_smoke.py
```

## Result

The LLM proposed 15 findings from the operation list alone (no
dependency graph, no evidence requirement, no execution) — this is
configuration C2 exactly as specified in docs/EVALUATION.md.

## Comparison to C1 (ZAP)

| Config | TP | FP | Precision | Recall |
|--------|----|----|-----------|--------|
| C1 (ZAP, automated fuzzing) | 0 | 0 | 0.00 | 0.00 |
| C2 (LLM-only, spec reasoning) | 6 | 9 | 0.40 | 0.38 |

The LLM found real vulnerabilities a generic fuzzer structurally
cannot: BOLA and broken-auth bugs it inferred from endpoint naming and
parameter shape. This is expected and useful — it is also exactly why
C2 is the weakest LLM-involving configuration in the ablation, not the
best. Precision of 0.40 means more than half its claims were wrong.

## False positives: 3 of 9 landed directly on TRACE-Bench's decoys

- `GET /doctors/{doctor_id}` and `GET /doctors` — flagged as
  BOLA/exposure. These are the **decoy-public** scenarios, intentionally
  unauthenticated by design.
- `GET /patients/{patient_id}/billing` — flagged as exposure. This is
  the **decoy-protected** scenario, always ownership-checked in every
  build.

This is precisely the failure mode TRACE-Bench's decoys were built to
surface: an LLM reasoning from endpoint shape alone has no way to
distinguish "looks suspicious" from "is actually unprotected," because
it never observes real request/response behavior. Evidence-grounding
(C4) and independent verification (C5) are the parts of TRACE designed
to eliminate exactly this class of false positive.

The remaining 6 false positives (`/admin/reset`, `/patients/search`,
`/auth/request-otp`, `/auth/request-reset`, `/auth/login`,
`/support/contact`) are plausible-sounding but fall outside this run's
16-item ground truth scope (either out-of-scope endpoints or a
different variant of a class already covered elsewhere).

## False negatives: every miss required observing behavior, not just shape

All 10 missed vulnerabilities share one property: none are inferable
from the OpenAPI spec's structure alone.

- `POST /patients/lookup` (BOLA via body ID, not path ID)
- `GET /appointments/{appointment_id}` (BOLA via a related object —
  the patient is nested inside the appointment response)
- `POST /auth/verify-otp` (requires knowing the OTP is only 4 digits
  and unthrottled — invisible from the schema)
- `GET /me/expiring` (requires knowing sessions never expire — a
  runtime/temporal property)
- 3 excessive-exposure misses and 3 of 4 rate-limiting misses (all
  require inspecting actual response content or repeated-request
  behavior, not endpoint shape)

This is the clearest evidence yet for why TRACE's later phases exist:
C3 (dependency mapper) is needed to see the `appointments → patients`
relationship; C4/C5 (evidence + verification) are needed to observe
and confirm behavior a static spec cannot reveal.

## Interpretation

C2 establishes the second data point in the ablation: better than a
pure fuzzer at finding authorization-logic bugs, but with a false
positive rate too high to trust unverified, and blind to any
vulnerability that requires observing runtime behavior rather than
endpoint naming. This is exactly the gap C3–C5 are built to close, and
this run gives concrete, per-finding evidence of both failure modes
(false positives on decoys, false negatives on behavior-dependent
bugs) rather than a single aggregate number.

## Caveats

- Single run at temperature 0.0; docs/EVALUATION.md calls for 3 runs
  per LLM config in the full evaluation (Phase 8) to capture residual
  nondeterminism, not yet done here.
- One model (GPT-OSS-120B) tested; the secondary model comparison
  from EVALUATION.md is deferred to Phase 8.
- `POST /admin/reset` and `POST /auth/login` count as false positives
  under strict ground-truth matching, but reflect genuine design gaps
  in TRACE-Bench outside this run's defined scope — worth revisiting
  when TRACE-Bench's ground truth is finalized.
