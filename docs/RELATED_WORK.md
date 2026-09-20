# Related Work (working draft)

Status: found via targeted search, abstracts and snippets only. Each entry
must be read in full and its citation verified before use.

| Work | Relevance | Notes |
|------|-----------|-------|
| Atlidakis et al., "Checking Security Properties of Cloud Service REST APIs" (ICST 2020), RESTler | Stateful REST fuzzing with security-rule checkers, including a user-namespace rule | Use as baseline C1b |
| LogiAgent, arXiv 2503.15079 | Multi-agent LLM REST testing | Reports ~34% false positives, validated manually |
| ARMeta, arXiv 2605.28321 | Multi-agent LLM metamorphic REST testing | TPR varies by system; FP reduction listed as future work |
| QASecClaw, arXiv 2605.01885 | LLM filter for SAST false positives | Closest conceptual neighbour; LLM judge, static analysis, not API |
| Links2CPN (Springer, doi 10.1007/s10207-024-00970-5) | BOLA detection from logs via Petri nets | Passive, log-based |
| LLM-enhanced BOLA/auth testing with Karate (Springer, doi 10.1007/978-3-031-75010-6_23) | Fine-tuned LLM generates BOLA/auth tests | Test generation, no verification |
| PentestEval, arXiv 2512.14233 | Stage-level benchmark for LLM pentesting | Motivates the reliability problem |
| "Hackers or Hallucinators?", arXiv 2604.05719 | LLM pentesting analysis | Read before citing |

## Systematic search log (to complete in Phase 0)
Databases: arXiv, ACM DL, IEEE Xplore, DBLP, Google Scholar.
Record per query: date, database, exact string, hit count, screened count.
Inclusion: 2019 onwards; REST/HTTP API security testing, LLM-assisted or
stateful; findings validation or false-positive handling; adversarial inputs
to LLM scanners; API-to-cloud evidence correlation.

## Gap statement (finalise after the search)
To our knowledge, no prior work ...