# C1 (OWASP ZAP) Baseline Smoke-Run — TRACE-Bench

**Date:** 24 September 2026
**Target:** TRACE-Bench (unpatched/vulnerable mode), http://localhost:9000
**Tool:** OWASP ZAP 2.17.0, `zap-api-scan.py`, Docker image `zaproxy/zap-stable`
**Import method:** OpenAPI spec (`/openapi.json`), 36 imported URLs, 103 total URLs scanned

## Command

```bash
docker run --rm \
  -v "$(pwd):/zap/wrk/:rw" \
  -t zaproxy/zap-stable \
  zap-api-scan.py \
  -t http://host.docker.internal:9000/openapi.json \
  -f openapi \
  -J zap-report.json \
  -I
```

## Result

115 checks passed, 0 new failures, 3 WARN-NEW categories (all generic
header-hygiene issues), 9 total alert entries in the JSON report.

**Alerts by CWE (none map to TRACE's 4 target classes):**

| CWE | Alert | TRACE class? |
|-----|-------|---------------|
| 89  | SQL Injection (on `/auth/login`, likely false positive) | No |
| 693 | CORP Header Missing | No |
| 693 | X-Content-Type-Options Header Missing | No |
| 388 | Client Error response code | No (informational) |
| -1  | Authentication Request Identified | No (informational) |
| 598 | Sensitive Info in URL | No |
| 524 | Non-Storable Content | No |
| -1  | Session Management Response Identified | No (informational) |
| 524 | Storable and Cacheable Content | No |

**Score against TRACE-Bench's 16 vulnerable (non-decoy) endpoints,**
via `tracesec.zap_adapter.ingest_zap_report` + `tracesec.scoring`:

## Interpretation

ZAP's automated API scan found zero of TRACE-Bench's 16 seeded
vulnerabilities across all four classes. This is consistent with the
nature of these vulnerabilities: they are authorization-logic and
rate-limiting-policy flaws (does this caller own this resource? is
this endpoint throttled?), not injection or header-hygiene issues that
automated fuzzing is built to detect. ZAP's own rate limiter (the
`support-contact` decoy scenario) correctly returned 429 responses
during the scan's fuzzing pass, independently confirming that specific
scenario behaves as designed under real automated traffic, not just
under TRACE-Bench's own test suite.

This result is the empirical basis for C1's role in the evaluation:
it establishes the floor that C2 (LLM-only), C4 (evidence-grounded),
and C5 (full TRACE with verifier) are meant to improve on.

## Caveats

- Single run, no repeated seeds (ZAP's scan is largely deterministic
  for a given target and ruleset, unlike the LLM configs).
- `zap-api-scan.py`'s default active-scan policy was used as-is; no
  custom ruleset was written for TRACE-Bench's specific classes,
  matching how a real-world "install ZAP, point it at the API, run
  the default scan" baseline would actually be used.
- Only 4 of the 16 vulnerable scenarios per class were exercised in
  this smoke run (all were reachable and scanned; none were flagged).
