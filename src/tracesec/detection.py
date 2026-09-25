"""
tracesec.detection

Detection rules that recognize TRACE's own attack traffic in
EvidenceRecords -- the automated form of the "How a defender would
detect it" notes written by hand for every manual finding in
docs/lab/crapi-manual-notes.md. Two patterns are covered here, both
observed for real during this project:

1. Enumeration: one identity (one set of request headers) touching
   many distinct resource IDs on the same endpoint shape in a short
   window. This is exactly the signature noted after the crAPI
   vehicle-location and mechanic-report findings -- a single token
   walking through report_id=1,2,3... or vehicle IDs harvested from
   the community forum.

2. Burst/brute-force: many requests to the same endpoint failing (or
   simply repeating) in a short window from the same identity. This
   matches the crAPI OTP finding (201 guesses in 4 seconds, no
   lockout) and TRACE-Bench's authn_otp_bruteforce / ratelimit_*
   scenarios.

These rules are intentionally simple and stateless (pure functions
over a list of records) rather than a running service: TRACE is a
scanner producing evidence, not a production intrusion-detection
system, so "would a defender reviewing this evidence log notice
something suspicious" is the right bar, not real-time alerting.
"""

import re
from dataclasses import dataclass

from tracesec.evidence import EvidenceRecord

# Matches a path segment that looks like a resource identifier: an
# integer, or a UUID. Used to reduce a concrete URL like
# "/patients/17/notes" to a shape like "/patients/{id}/notes" so
# requests to the same *kind* of endpoint, with different concrete
# IDs, are grouped together.
_ID_SEGMENT = re.compile(
    r"^\d+$|^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _endpoint_shape(url: str) -> str:
    """Reduce a concrete URL to a shape with identifier segments
    replaced by a placeholder, e.g. "/patients/17" -> "/patients/{id}".
    Query strings are dropped; only the path shape is used for
    grouping."""
    path = url.split("?", 1)[0]
    segments = path.split("/")
    shaped = ["{id}" if _ID_SEGMENT.match(seg) else seg for seg in segments]
    return "/".join(shaped)


def _identity_key(record: EvidenceRecord) -> str:
    """A stand-in for 'the same caller': TRACE's own session_id, or
    (as a fallback for evidence not produced by TRACE's own Executor,
    e.g. a ZAP-ingested record) the Authorization header value if
    present, redacted evidence notwithstanding this is still a stable
    grouping key since redaction replaces the value with a constant
    placeholder shared by all requests using the same auth scheme."""
    if record.session_id:
        return record.session_id
    return record.request_headers.get("Authorization", "unknown")


@dataclass(frozen=True)
class DetectionAlert:
    rule: str
    identity: str
    endpoint_shape: str
    evidence_ids: list[int]
    detail: str


def detect_enumeration(
    records: list[EvidenceRecord], *, min_distinct_ids: int = 3
) -> list[DetectionAlert]:
    """Flag (identity, endpoint_shape) pairs where the same caller hit
    at least min_distinct_ids different concrete URLs matching the
    same endpoint shape -- the enumeration signature from the crAPI
    BOLA findings (one token, many report_id / vehicle_id values)."""
    groups: dict[tuple[str, str], dict[str, list[int]]] = {}

    for record in records:
        identity = _identity_key(record)
        shape = _endpoint_shape(record.url)
        key = (identity, shape)
        by_url = groups.setdefault(key, {})
        by_url.setdefault(record.url, []).append(record.index)

    alerts: list[DetectionAlert] = []
    for (identity, shape), by_url in groups.items():
        if len(by_url) >= min_distinct_ids:
            evidence_ids = [i for ids in by_url.values() for i in ids]
            alerts.append(
                DetectionAlert(
                    rule="enumeration",
                    identity=identity,
                    endpoint_shape=shape,
                    evidence_ids=sorted(evidence_ids),
                    detail=(
                        f"{len(by_url)} distinct URLs matching {shape!r} "
                        f"requested by the same identity"
                    ),
                )
            )
    return alerts


def detect_burst(
    records: list[EvidenceRecord], *, min_requests: int = 5, window_seconds: float = 10.0
) -> list[DetectionAlert]:
    """Flag (identity, endpoint_shape) pairs where at least
    min_requests requests landed within any window_seconds-wide window
    -- the brute-force signature from the crAPI OTP finding (201
    guesses in 4 seconds) and TRACE-Bench's authn_otp_bruteforce /
    ratelimit_* scenarios. Detects the burst regardless of the
    responses' status codes: an unthrottled endpoint returning 200s or
    401s just as fast is equally suspicious as one returning 429s
    late."""
    groups: dict[tuple[str, str], list[EvidenceRecord]] = {}
    for record in records:
        key = (_identity_key(record), _endpoint_shape(record.url))
        groups.setdefault(key, []).append(record)

    alerts: list[DetectionAlert] = []
    for (identity, shape), group_records in groups.items():
        timestamps = sorted(r.timestamp for r in group_records)
        for i in range(len(timestamps) - min_requests + 1):
            window = timestamps[i : i + min_requests]
            if window[-1] - window[0] <= window_seconds:
                evidence_ids = sorted(r.index for r in group_records)
                alerts.append(
                    DetectionAlert(
                        rule="burst",
                        identity=identity,
                        endpoint_shape=shape,
                        evidence_ids=evidence_ids,
                        detail=(
                            f"{min_requests}+ requests to {shape!r} within "
                            f"{window_seconds}s by the same identity"
                        ),
                    )
                )
                break  # one alert per (identity, shape) is enough
    return alerts


def run_detection(
    records: list[EvidenceRecord],
    *,
    min_distinct_ids: int = 3,
    min_requests: int = 5,
    window_seconds: float = 10.0,
) -> list[DetectionAlert]:
    """Run all detection rules and return their combined alerts."""
    return detect_enumeration(records, min_distinct_ids=min_distinct_ids) + detect_burst(
        records, min_requests=min_requests, window_seconds=window_seconds
    )
