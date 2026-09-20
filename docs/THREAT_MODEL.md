# TRACE Threat Model (v0.1)

Scope: threats to and from the TRACE tool itself, not to the targets.

## Assets
Evidence store, API credentials and tokens used in tests, LLM API keys, AWS
credentials, ground-truth labels, experiment results.

## Trust boundaries
1. TRACE core <-> target API (target responses are UNTRUSTED input)
2. TRACE core <-> LLM provider (data leaves the machine)
3. TRACE core <-> AWS (cloud credentials)
4. TRACE core <-> local disk (evidence, cache)

## Threats and mitigations

| ID | Threat | Category | Mitigation | Test |
|----|--------|----------|------------|------|
| T1 | Scope escape: tool sends requests to a non-allowlisted host, including via redirects or DNS rebinding | Elevation / abuse | Allowlist enforced in the HTTP client; redirects disabled or re-checked per hop; resolved IP checked against allowlist | Unit tests with off-scope host, redirect chain and rebinding stub |
| T2 | Prompt injection: malicious text in an API response steers the LLM | Tampering | Responses passed as delimited data, never as instructions; structured outputs only; grounding check plus deterministic verifier as backstop | Test target that returns injection strings; assert no false finding is confirmed |
| T3 | Secrets leak into evidence, logs or LLM prompts | Information disclosure | Redaction at write time; secrets never included in prompts; `.gitignore` for evidence and cache | Unit tests for redaction; grep-based CI check |
| T4 | Evidence tampering after collection | Tampering / repudiation | Content-addressed records in a SHA-256 hash chain; chain verified before reporting | Test that modifying one record fails chain verification |
| T5 | Fabricated or hallucinated finding accepted | Spoofing | Evidence-citation check plus independent verifier (C4, C5) | Error-injection run |
| T6 | Unintended DoS from rate-limit tests | Denial of service | Per-endpoint burst cap, global request cap, kill switch, testbeds only | Test that caps trip |
| T7 | Destructive requests (DELETE, bulk updates) against non-owned or non-resettable data | Tampering | State-changing tests only on resettable testbeds; verifier limited to canary objects; snapshot reset between runs | Test that verifier refuses non-canary targets |
| T8 | AWS credential exposure or over-broad IAM | Elevation | No long-lived keys committed; SSO or short-lived credentials; least-privilege read-only collectors; SSM instead of open SSH | Terraform review; IAM policy checked with Access Analyzer or Prowler |
| T9 | Supply-chain compromise via dependencies | Tampering | Pinned lockfile, `pip-audit`, Dependabot, SBOM, image scan | CI checks |
| T10 | Misuse of the tool against systems the user does not own | Abuse | RESPONSIBLE_USE.md, allowlist required at startup, no default targets | Startup fails without an allowlist |

## Residual risks
Free-tier LLM providers may log prompts; only synthetic testbed data is ever
sent to them. Intentionally vulnerable targets are network-isolated.