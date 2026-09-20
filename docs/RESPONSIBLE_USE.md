# Responsible Use

TRACE is a research tool for authorized security testing.

- Use it only against systems you own or have explicit written permission to
  test.
- TRACE requires an explicit target allowlist and refuses to run without one.
- Rate-limit and state-changing tests are designed for isolated, resettable
  testbeds. Do not point them at production systems.
- The included testbeds (crAPI, vAPI, TRACE-Bench) are intentionally
  vulnerable. Run them only in isolated environments, never exposed to the
  public internet.
- Findings about third-party software should follow coordinated disclosure.
- The authors accept no responsibility for misuse.