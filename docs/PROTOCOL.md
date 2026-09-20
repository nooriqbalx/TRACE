# TRACE Experimental Protocol (v0.4 DRAFT)

Status: draft. To be frozen as `protocol-v1.0` at the end of Phase 1, before
any configuration is run on the locked test split, and registered on OSF at
that point. Post-freeze changes are logged in DEVIATIONS.md.

Change log:
- v0.2: full draft, verifier independence, safety limits
- v0.3: single-author label provenance and limitations
- v0.4: sharpened contribution claim, C1b (RESTler) baseline, H5
  (adversarial-target robustness), adversarial benchmark split

## 1. Research question
Does gating LLM-generated REST API security findings on replayable evidence
and an independent deterministic verifier reduce false positives, without an
unacceptable loss of recall, including when the target API is adversarial?

## 2. Scope of the contribution claim
TRACE does not claim to be the first stateful REST API security tester or the
first LLM-based REST API tester. Its claim, subject to confirmation by
systematic review (docs/RELATED_WORK.md), is that gating LLM-generated
findings on replayable evidence and an independent deterministic verifier
reduces false positives, measured by a five-way ablation on a benchmark of
paired vulnerable/patched endpoints with decoys, including adversarial-target
scenarios. Cloud-layer evidence is an exploratory extension. No priority
claim ("first") is made in any external material until the systematic search
is complete; until then the wording is "to our knowledge" or omitted.

## 3. Configurations (ablation)
- C1: Baseline DAST (OWASP ZAP, OpenAPI import, pinned version, fixed policy)
- C1b: RESTler with security checkers (non-LLM stateful baseline), included
  if it can be run on all targets; compared exploratorily against C3
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
- H5 (pre-specified, secondary): on adversarial-target scenarios (responses
  containing injected instructions, or crafted to mimic another user's data),
  C5 induces fewer false findings than C2 and C3; C4 is intermediate.

## 5. Vulnerability classes
BOLA/IDOR (API1, CWE-639); broken authentication (API2, CWE-287);
excessive data exposure (API3, CWE-213); rate-limit failures
(API4, CWE-770).

## 6. Targets and splits
- Development: OWASP crAPI (all tuning happens here)
- Locked test split: TRACE-Bench, custom, 12 paired vulnerable/patched
  scenarios per class (48 pairs) plus decoys. Not used for tuning.
- Adversarial split of TRACE-Bench: at least 20 scenarios on otherwise secure
  endpoints, of two kinds: (a) responses containing injected text intended to
  steer the scanner (for example, instructions to report a vulnerability);
  (b) responses crafted to resemble another user's data while being the
  caller's own. Not used for tuning.
- External validation: vAPI
- Exact versions and commit hashes of all targets and tools are pinned in
  docs/VERSIONS.md before freeze.
- Results on TRACE-Bench (author-built) are reported separately from results
  on crAPI and vAPI (third-party labels).

## 7. Ground truth and scoring rules
- A finding is a true positive if it matches a labelled vulnerability on:
  same class, same normalised method + path.
- Duplicate findings for the same vulnerability collapse into one.
- A finding on a negative control, patched variant, decoy or adversarial
  scenario is a false positive.
- Right endpoint but wrong class = one FP and one FN.
- A labelled vulnerability with no matching finding is a false negative.
- Rate-limit ground truth: an endpoint is vulnerable if it accepts 60
  requests within 10 seconds with no 429, no Retry-After header and no
  measurable throttling.
- Label provenance: (a) TRACE-Bench labels are true by construction: each
  vulnerable scenario comes from a code-level toggle, each patched variant
  differs only by the fix, and every decoy and adversarial scenario carries a
  written reason it is not vulnerable. (b) crAPI and vAPI labels come from
  each project's published challenge documentation, with the source cited per
  label. (c) All labels are committed before any configuration is run.
  (d) This is a single-author study. To estimate labelling consistency, the
  author re-labels a random 20% sample, blind to the original labels, after
  an interval of at least 14 days. Intra-rater agreement (Cohen's kappa) is
  reported and discrepancies are resolved by re-reading the rule and logged.
- Hand-grading of findings (for example, grounding validity) uses a written
  rubric, is blind to configuration, and a random 20% is regraded after at
  least 14 days with intra-rater agreement reported.

## 8. Metrics
Primary: precision, recall, F1, false-positive rate (overall and per class).
Secondary: evidence completeness, verifier replay success rate, requests per
finding, LLM tokens per finding, wall-clock time, dependency coverage,
induced false findings on adversarial scenarios (H5).
Verifier verdict "inconclusive" is not a reported finding and is tallied
separately.

## 9. Statistical analysis plan
- Unit of analysis: scenario (endpoint-level).
- Paired comparisons: exact McNemar test.
- Uncertainty: bootstrap 95% CIs, resampling by scenario.
- Primary (confirmatory) comparisons, Holm-corrected together:
  P1: C5 vs C2 precision
  P2: C3 vs C1 recall on stateful classes
  P3: C4 vs C2 false-positive count
- Pre-specified secondary: H5 comparisons (C5 vs C2, C5 vs C3, C4 vs C2) on
  induced false findings, Holm-corrected within the H5 family.
- Exploratory: C1b vs C3, robustness with the secondary model, H4, and all
  other comparisons; labelled as exploratory in all reporting.
- LLM configs: 5 runs per config, temperature 0, seeds logged where the
  provider supports them. Report variance across runs.
- A simulation-based power analysis is run in Phase 1 to justify the
  benchmark size; if underpowered, the benchmark is enlarged before freeze.
- Robustness (exploratory): repeat C2-C5 with the secondary model.

## 10. Models
- Primary: GPT-OSS-120B. Secondary: Qwen (variant chosen in Phase 1).
- Model names and versions are pinned after confirming availability on the
  free tier, and recorded in docs/VERSIONS.md.

## 11. Reproducibility controls
- Prompts versioned in the repo and frozen at tag `v0.9-experiments`.
- All LLM calls cached (record/replay). Models and versions logged.
- Tool versions, seeds and timestamps logged per run.
- Testbed state is reset to a snapshot between runs.
- Any discarded run is listed with the reason.
- The protocol is registered on OSF at freeze, with the repo commit hash and
  ground-truth files; later changes are documented amendments.

## 12. Verifier independence
The verifier shares no prompts, no model calls and no code path with the
finding generator. It is unit-tested against known-true and known-false
cases, and an error-injection run (fabricated findings) must be rejected.

## 13. Rules for interpretation
- Results are reported whether or not hypotheses are supported.
- Unsupported hypotheses are stated as such; explanations are offered as
  hypotheses, not conclusions.
- No changes to prompts, verifier rules or ground truth after the test split
  is first run, except logged bug fixes that do not depend on test results.

## 14. Safety limits
- Only own, isolated testbeds; target allowlist enforced in code.
- Rate-limit tests capped at 100 requests per endpoint per burst, plus a
  global per-run request cap.
- State-changing tests run only against resettable testbeds.
- Target responses are treated as untrusted input to the LLM (see
  THREAT_MODEL.md, T2).
- No third-party systems, ever.

## 15. Known limitations (to be expanded)
Small benchmark; synthetic and intentionally vulnerable targets; free-tier
LLM nondeterminism; single author and single annotator, so labelling and
grading have no independent inter-rater check; the same author wrote the
benchmark and the verifier, so results on TRACE-Bench are reported separately
from results on crAPI and vAPI, whose labels are third-party; the literature
search supporting the novelty claim is not yet systematic.