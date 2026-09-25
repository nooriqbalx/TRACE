# TRACE: Technical Report

**Author:** Noor-ul-ain Iqbal
**Repository:** https://github.com/nooriqbalx/TRACE

## Abstract

TRACE is an evidence-grounded, dependency-aware REST API security
testing tool. It targets four vulnerability classes — broken
object-level authorization (BOLA), broken authentication, excessive
data exposure, and rate-limiting failures — that automated fuzzers
structurally cannot find, because each requires reasoning about
identity and ownership, not input validation. LLMs can reason about
these classes from an API's shape, but produce false positives and
miss behavior that only manifests at runtime. TRACE's contribution is
a pipeline that gates every LLM-proposed finding on a real, replayable
probe (grounding) and an independent, deterministic, LLM-free oracle
(verification) before it is ever reported. Across a 5-configuration
ablation on a 16-vulnerability benchmark, grounding and verification
take precision from 0.41 (LLM-only) to a clean 1.00, at the cost of
recall dropping from 0.44 to 0.31 — a real, measured trade-off, not an
assumed one.

## Motivation

This project follows GroundedTriage (an evaluation of LLM confidence
vs. correctness in malware classification), extending the same
"trust the evidence, not the claim" principle to a different domain.
The initial manual exploitation phase — reproducing BOLA, broken
authentication, and excessive-exposure bugs by hand against OWASP
crAPI (see `docs/lab/crapi-manual-notes.md`) — surfaced the exact
pattern TRACE automates: the same missing-ownership-check bug recurred
across two unrelated crAPI endpoints (vehicle location and mechanic
reports), and a 4-digit OTP endpoint accepted 201 brute-force guesses
in 4 seconds with zero rate-limiting.

## Related work

See `docs/RELATED_WORK.md`. In brief: RESTler (Atlidakis et al., ICST
2020) established stateful REST fuzzing with security-rule checkers,
including a user-namespace BOLA-style rule; this is TRACE's C1-adjacent
baseline conceptually, and OWASP ZAP is used as the actual C1 baseline
here. LLM-driven REST testing (LogiAgent, ARMeta) has documented false
positives in the 30-45% range from LLM hallucination, validated by
manual review after the fact — TRACE's contribution is gating that
before reporting, via execution rather than manual review.

## Method

### Engine

TRACE's engine (`src/tracesec/`) has four layers:

1. **Ingestion**: `spec.py` normalizes an OpenAPI 3.x document; `dependency.py`
   infers producer/consumer relationships between operations, falling
   back to one live probe per operation when a target's response
   schema can't express field names statically (discovered as a real
   limitation against TRACE-Bench's FastAPI-generated spec; see
   Results below).
2. **Proposal**: `llm_scanner.py` implements C2 (LLM-only) and C3
   (dependency-aware LLM); `zap_adapter.py` converts a ZAP scan into
   the same finding schema for C1.
3. **Grounding and verification**: `pipeline.py` re-anchors every
   LLM-proposed finding to a real probe via `grounding.py` (C4); grounded
   findings are then dispatched to a deterministic oracle in
   `verifier.py` (C5) — differential BOLA checks, excessive-exposure
   field checks, and bounded unthrottled-burst checks.
4. **Evidence and defense**: `evidence.py` is a SHA-256 hash-chained,
   tamper-evident store with secret redaction at write time;
   `executor.py` ties it to a scope-guarded HTTP client
   (`scope.py`) with a per-run request cap; `detection.py` recognizes
   TRACE's own attack traffic (enumeration, burst patterns) in the
   evidence log; `fix_and_prove.py` confirms a finding's verdict
   actually flips from CONFIRMED to REFUTED once a target is patched.

### Testbeds

- **OWASP crAPI**: development target for manual exploitation.
- **TRACE-Bench**: a custom FastAPI app, author-built, with 24
  vulnerable/patched scenario pairs (6 per class) plus decoys
  (intentionally-protected and intentionally-public endpoints, to
  test for false positives). Ground truth is true by construction —
  each scenario's vulnerable/patched behavior is a code-level toggle.
- **vAPI**: external validation target, configured but not the
  primary evaluation target for this report.

## Results

Full run: `docs/lab/phase8-full-evaluation-run.md` (two runs are
documented there — the first found a real bug in the dependency
mapper, the second is the one reported below).

| Config | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| C1 (ZAP) | 0 | 0 | 16 | 0.00 | 0.00 | 0.00 |
| C2 (LLM-only) | 7 | 10 | 9 | 0.41 | 0.44 | 0.42 |
| C3 (dependency-aware) | 8 | 6 | 8 | 0.57 | 0.50 | 0.53 |
| C4 (evidence-grounded) | 6 | 0 | 10 | 1.00 | 0.38 | 0.55 |
| C5 (full TRACE, verified) | 5 | 0 | 11 | 1.00 | 0.31 | 0.48 |

**C1 vs. C2**: a generic DAST scanner found none of TRACE-Bench's 16
seeded vulnerabilities; an LLM reasoning over the same spec found 7,
with roughly 60% of its claims wrong.

**C2 vs. C3**: giving the LLM a real dependency graph (14 edges,
including the appointments→patients relationship C2 consistently
missed) raised precision from 0.41 to 0.57 and cut false positives
from 10 to 6.

**C3 vs. C4/C5**: gating every proposed finding on a genuine executed
probe eliminates false positives entirely — precision 1.00 at both
stages — at the cost of recall, since C4/C5 can only report what this
project has built a working prober/oracle for (11 of 16 ground-truth
endpoints; see Limitations).

**C4 vs. C5**: the deterministic oracle refuted one finding that had
passed grounding (TP dropped from 6 to 5), demonstrating the verifier
catches cases grounding alone cannot.

## Threats to validity

- **Small benchmark.** 16 ground-truth vulnerabilities across one
  author-built app. Results should not be read as a general claim
  about LLM API-testing accuracy.
- **Single run, single model, temperature 0.** `docs/EVALUATION.md`
  calls for 3 seeded runs to capture nondeterminism; at temperature 0,
  three runs mostly confirmed determinism rather than surfacing
  variance. A genuine multi-seed, multi-model comparison is future
  work.
- **Prober/oracle coverage bounds C4/C5 recall independently of
  verifier correctness.** A finding with no prober is correctly
  rejected as unprobeable — this is `pipeline.py` working as designed
  — but it means C4/C5's recall reflects engineering coverage as much
  as the underlying method's ceiling.
- **TRACE-Bench is author-built.** Per `docs/EVALUATION.md`, its
  results are not treated as equivalent evidence to a third-party
  target; crAPI and vAPI labels come from published challenge
  documentation, not the author.

## Limitations

See `README.md`'s Limitations section — restated briefly: single
author/evaluator; 11/16 oracle coverage (5 endpoints explicitly out of
scope, named in `KNOWN_UNCOVERED`); single-model, single-seed LLM
runs in this report; AWS cloud-layer extension scoped and then cut.

## Ethics

TRACE enforces scope at the code level (`scope.py`'s allowlist blocks
even a malicious redirect off-target) and caps request volume
(`executor.py`'s per-run limit; `verifier.py`'s bounded burst budget),
per `docs/THREAT_MODEL.md` and `docs/RESPONSIBLE_USE.md`. All testing
in this report was performed against local, deliberately-vulnerable
targets the author controls (crAPI, vAPI, TRACE-Bench) — no
third-party system was tested.

## Reproducibility

```bash
uv sync
uv run pytest                                    # 135 unit/integration tests
cd bench && uv run uvicorn tracebench.main:app --port 9000  # separate terminal
uv run python experiments/eval-run-1/run_full_evaluation.py  # needs GROQ_API_KEY
```

LLM calls are cached (`experiments/eval-run-1/c2-cache.json`,
`c3-cache.json`, gitignored) — a rerun after the first costs no
further API calls for identical prompts. The evidence store
(`experiments/eval-run-1/evidence.jsonl`) is regenerated each run and
its hash chain is verified at the end of every run's output.
