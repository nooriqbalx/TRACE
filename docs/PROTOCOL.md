# TRACE Experimental Protocol (v0.2 DRAFT)

Status: draft. Frozen as `protocol-v1.0` at the end of Phase 1, before any
configuration is run on the locked test split. Post-freeze changes are logged
in DEVIATIONS.md.

## 1. Research question
Does evidence traceability plus independent deterministic verification reduce
false positives in automated REST API security testing, without an
unacceptable loss of recall?

## 2. Scope of the contribution claim
TRACE does not claim to be the first LLM-assisted API security tester. It
claims to (a) isolate, via ablation, the effect of evidence-gating and
independent verification on false positives, (b) measure this against
labelled negative controls and decoys, and (c) extend evidence to cloud-layer
configuration. The exact wording of the novelty claim is fixed after the
literature review (docs/RELATED_WORK.md).

## 3. Configurations (ablation)
- C1: Baseline DAST (OWASP ZAP, OpenAPI import, pinned version, fixed policy)
- C2: LLM scanner (LLM proposes tests and reports findings; no dependency
  graph, no evidence requirement, no verifier)
- C3: Dependency-aware (C2 + operation dependency graph and stateful
  sequences)
- C4: Evidence-grounded (C3 + every finding must cite resolvable evidence
  that supports the claim; ungrounded findings are rejected)
- C5: Full TRACE (C4 + independent deterministic verifier; only confirmed
  findings are reported)

## 4. Hypotheses
- H1: C4 and C5 have a lower false-positive rate than C2.
- H2: C3 has higher recall than C1 on stateful classes (BOLA, broken auth).
- H3: C5 has the highest precision, with recall non-inferior to the best of
  C1-C4 (margin: 5 percentage points).
- H4 (exploratory): cloud-layer evidence (IAM, security groups) improves
  finding classification or impact assessment.

## 5. Vulnerability classes
BOLA/IDOR (API1, CWE-639); broken authentication (API2, CWE-287);
excessive data exposure (API3, CWE-213); rate-limit failures
(API4, CWE-770).

## 6. Targets and splits
- Development: OWASP crAPI (all tuning happens here)
- Locked test split: TRACE-Bench, custom, 12 paired vulnerable/patched
  scenarios per class (48 pairs) plus decoys. Not used for tuning.
- External validation: vAPI
- Exact versions and commit hashes of all targets and tools are pinned in
  docs/VERSIONS.md before freeze.

## 7. Ground truth and scoring rules
- A finding is a true positive if it matches a labelled vulnerability on:
  same class, same normalised method + path.
- Duplicate findings for the same vulnerability collapse into one.
- A finding on a negative control, patched variant or decoy is a false
  positive.
- Right endpoint but wrong class = one FP and one FN.
- A labelled vulnerability with no matching finding is a false negative.
- Rate-limit ground truth: an endpoint is vulnerable if it accepts 60
  requests within 10 seconds with no 429, no Retry-After header and no
  measurable throttling.
- Labels are fixed before any configuration is run. A second labeller
  independently labels a random 20% sample; agreement is reported as
  Cohen's kappa, disagreements are resolved and logged.

## 8. Metrics
Primary: precision, recall, F1, false-positive rate (overall and per class).
Secondary: evidence completeness, verifier replay success rate, requests per
finding, LLM tokens per finding, wall-clock time, dependency coverage.
Verifier verdict "inconclusive" is not a reported finding and is tallied
separately.

## 9. Statistical analysis plan
- Unit of analysis: scenario (endpoint-level).
- Paired comparisons: exact McNemar test.
- Uncertainty: bootstrap 95% CIs, resampling by scenario.
- Primary comparisons (Holm-corrected together):
  P1: C5 vs C2 precision
  P2: C3 vs C1 recall on stateful classes
  P3: C4 vs C2 false-positive count
- All other comparisons are exploratory and labelled as such.
- LLM configs: 5 runs per config, temperature 0, seeds logged where the
  provider supports them. Report variance across runs.
- A simulation-based power analysis is run in Phase 1 to justify the
  benchmark size; if underpowered, the benchmark is enlarged before freeze.
- Robustness (exploratory): repeat C2-C5 with the secondary model.

## 10. Reproducibility controls
- Prompts versioned in the repo and frozen at tag `v0.9-experiments`.
- All LLM calls cached (record/replay). Models and versions logged.
- Tool versions, seeds and timestamps logged per run.
- Testbed state is reset to a snapshot between runs.
- Any discarded run is listed with the reason.

## 11. Verifier independence
The verifier shares no prompts, no model calls and no code path with the
finding generator. It is unit-tested against known-true and known-false
cases, and an error-injection run (fabricated findings) must be rejected.

## 12. Rules for interpretation
- Results are reported whether or not hypotheses are supported.
- Unsupported hypotheses are stated as such; explanations are offered as
  hypotheses, not conclusions.
- No changes to prompts, verifier rules or ground truth after the test split
  is first run, except logged bug fixes that do not depend on test results.

## 13. Safety limits
- Only own, isolated testbeds; target allowlist enforced in code.
- Rate-limit tests capped at 100 requests per endpoint per burst, plus a
  global per-run request cap.
- State-changing tests run only against resettable testbeds.
- No third-party systems, ever.

## 14. Known limitations (to be expanded)
Small benchmark; synthetic and intentionally vulnerable targets; free-tier
LLM nondeterminism; ground-truth labelling by the authors.