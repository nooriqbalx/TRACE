# TRACE Evaluation Plan

Purpose: measure what each TRACE component contributes, honestly and
reproducibly. This is an engineering evaluation on a small benchmark, not a
statistical claim about all APIs.

## Targets
- Development: OWASP crAPI (all tuning happens here)
- Held-out test: TRACE-Bench (own app, paired vulnerable/patched endpoints
  plus decoys and adversarial responses); not used for tuning
- External check: vAPI
- Versions and image tags pinned in docs/VERSIONS.md

## Vulnerability classes
BOLA/IDOR, broken authentication, excessive data exposure, rate-limit failures.

## Ground truth
- Written before any scan and committed.
- TRACE-Bench labels are true by construction (code-level toggles; each decoy
  has a written reason it is not vulnerable).
- crAPI and vAPI labels come from their published challenge documentation,
  cited per label.
- Scoring: a finding is a true positive if class and normalised method+path
  match a labelled vulnerability; anything on a patched, decoy or adversarial
  endpoint is a false positive; unmatched labelled vulnerabilities are false
  negatives; duplicates collapse.
- Rate-limit ground truth: vulnerable if 60 requests in 10 s get no 429, no
  Retry-After and no throttling.

## Configurations
- C1: OWASP ZAP baseline (pinned version, fixed policy)
- C2: LLM-only scanner (no dependency graph, no evidence requirement, no verifier)
- C3: Dependency-aware (C2 plus operation dependency graph)
- C4: Evidence-grounded (C3 plus mandatory evidence citation)
- C5: Full TRACE (C4 plus independent deterministic verifier)
- Extra row: TRACE in deterministic mode, no LLM at all

## Metrics
Precision, recall, false-positive count, per class and overall; verifier
outcomes (confirmed, refuted, inconclusive); requests and LLM tokens per
finding; runtime.

## Runs
LLM configurations: 3 runs, temperature 0, seeds logged, all calls cached.
Testbeds reset between runs.

## Reporting rules
- Results are reported whether or not they flatter TRACE.
- TRACE-Bench is author-built, so its results are reported separately from
  crAPI and vAPI.
- Every false positive and false negative gets a one-line cause.

## Safety
Own isolated testbeds only; allowlist enforced in code; rate-limit tests
capped at 100 requests per endpoint; targets bound to localhost.

## Limitations
Small benchmark; intentionally vulnerable targets; free-tier LLM
nondeterminism; single author.
