# TRACE-Bench

A small, self-contained FastAPI app with 24 deliberately vulnerable/patched
scenario pairs across four vulnerability classes: BOLA, broken
authentication, excessive data exposure, and rate limiting. Used as a
labeled ground-truth benchmark for TRACE's automated scanner and verifier.

## Run the automated ground-truth tests

    uv run pytest bench/tests/ -v

All 24 scenarios are checked in both vulnerable and patched modes in a
single run, no server process needed (uses FastAPI's TestClient).

## Run the app manually (for exploring by hand)

    cd bench
    uv run uvicorn tracebench.main:app --reload --port 9000

Toggle any single scenario's patched behavior with its environment
variable, e.g.:

    TRACEBENCH_PATCH_BOLA_DIRECT_PATH=1 uv run uvicorn tracebench.main:app --reload --port 9000

See GROUND_TRUTH.yaml for the full list of scenario IDs and their
toggle_env variable names. Six of the 24 are decoys (toggle_env: null):
they behave identically in every build and exist to test that TRACE's
verifier does not produce false positives on correctly-protected or
intentionally-public endpoints.

## Reset in-memory data

    curl -X POST http://localhost:9000/admin/reset

Useful when testing manually; the automated tests reset state
automatically between runs.
