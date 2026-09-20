# TRACE Experimental Protocol (v0.1 DRAFT)

Status: draft. Frozen (tagged `protocol-v1.0`) before any experiment on the
locked test split is run. Changes after freeze are logged in DEVIATIONS.md.

## 1. Research question
Does evidence traceability plus independent verification reduce false
positives in automated REST API security testing, without an unacceptable
loss of recall?

## 2. Configurations (ablation)
- C1: Baseline DAST (OWASP ZAP, OpenAPI import, pinned version, fixed policy)
- C2: LLM scanner (LLM proposes tests and reports findings; no dependency
  graph, no evidence requirement, no verifier)
- C3: Dependency-aware (C2 + operation dependency graph and stateful
  sequences; no evidence requirement, no verifier)
- C4: Evidence-grounded (C3 + every finding must cite resolvable evidence
  that supports the claim; ungrounded findings are rejected)
- C5: Full TRACE (C4 + independent deterministic verifier; only confirmed
  findings are reported)

## 3. Hypotheses
- H1: C4 and C5 have a lower false-positive rate than C2.
- H2: C3 has higher recall than C1 on stateful classes (BOLA, broken auth).
- H3: C5 has the highest precision, with recall non-inferior to the best
  baseline (margin: [DECIDE, e.g. 5 percentage points]).
- H4 (exploratory): cloud-layer evidence (IAM, security groups) improves
  finding classification or impact assessment.

## 4. Vulnerability classes
BOLA/IDOR (API1, CWE-639); broken authentication (API2, CWE-287);
excessive data exposure (API3, CWE-213); rate-limit failures
(API4, CWE-770).

## 5. Targets and splits
- Development: OWASP crAPI (all tuning happens here)
- Locked test split: TRACE-Bench (custom, paired vulnerable/patched
  scenarios, plus decoys). Not used for tuning.
- External validation: vAPI
- Version pins for every target: [DECIDE at Phase 1]

## 6. Ground truth and scoring rules
- A finding is a true positive if it matches a labelled vulnerability on:
  same class, same normalised method + path.
- Duplicate findings for the same vulnerability collapse into one.
- A finding on a negative control or patched variant is a false positive.
- Right endpoint but wrong class = one FP and one FN.
- A labelled vulnerability with no matching finding is a false negative.
- Rate-limit ground truth: an endpoint is vulnerable if it accepts
  [DECIDE: N requests in T seconds] without throttling.
- Ground-truth labels are set before running any configuration and reviewed
  by a second person on a sample.

## 7. Metrics
Primary: precision, recall, F1, false-positive rate (overall and per class).
Secondary: evidence completeness, verifier replay success rate, requests per
finding, LLM tokens per finding, wall-clock time, dependency coverage.
Verifier verdict "inconclusive" is not counted as a reported finding and is
tallied separately.

## 8. Statistical analysis plan
- Unit of analysis: scenario (endpoint-level).
- Paired comparisons: exact McNemar test.
- Uncertainty: bootstrap 95% CIs, resampling by scenario.
- Primary comparisons (Holm-corrected together):
  P1: C5 vs C2 precision
  P2: C3 vs C1 recall on stateful classes
  P3: C4 vs C2 false-positive count
- All other comparisons are exploratory and labelled as such.
- LLM configs: at least 5 runs per config, fixed prompts, temperature
  [DECIDE], seeds logged. Report variance across runs.

## 9. Reproducibility controls
- Prompts versioned in the repo and frozen at tag `v0.9-experiments`.
- All LLM calls cached (record/replay). Models and versions logged:
  [DECIDE: model list; verify availability on the free tier].
- Tool versions, seeds and timestamps logged per run.
- Any run that is discarded is listed with the reason.

## 10. Rules for interpretation
- Results are reported whether or not hypotheses are supported.
- If a hypothesis is not supported, the report says so and offers
  explanations as hypotheses, not conclusions.
- No changes to prompts, verifier rules or ground truth after the test split
  is first run, except logged bug fixes that do not depend on test results.

## 11. Safety limits
- Only own, isolated testbeds; target allowlist enforced in code.
- Rate-limit tests capped at [DECIDE: max requests per burst] per endpoint.
- No third-party systems, ever.

## 12. Known limitations (to be expanded)
Small benchmark; synthetic and intentionally vulnerable targets; free-tier
LLM nondeterminism; ground-truth labelling by the authors.