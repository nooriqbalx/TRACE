"""
Unit tests for tracesec.detection: enumeration and burst rules,
constructed from hand-made EvidenceRecords so the tests double as
documentation of exactly which traffic pattern each rule targets.
"""

from tracesec.detection import detect_burst, detect_enumeration, run_detection
from tracesec.evidence import EvidenceRecord


def _record(index, session_id, url, timestamp=0.0, status=200):
    return EvidenceRecord(
        index=index,
        timestamp=timestamp,
        session_id=session_id,
        method="GET",
        url=url,
        request_headers={},
        request_body=None,
        response_status=status,
        response_headers={},
        response_body=None,
        elapsed_seconds=0.01,
        prev_hash="0" * 64,
        content_hash="1" * 64,
    )


def test_detect_enumeration_flags_many_distinct_ids_same_identity():
    records = [
        _record(0, "attacker", "https://t/reports?report_id=1"),
        _record(1, "attacker", "https://t/reports?report_id=2"),
        _record(2, "attacker", "https://t/reports?report_id=3"),
    ]
    alerts = detect_enumeration(records, min_distinct_ids=3)
    assert len(alerts) == 1
    assert alerts[0].rule == "enumeration"
    assert alerts[0].identity == "attacker"


def test_detect_enumeration_ignores_below_threshold():
    records = [
        _record(0, "attacker", "https://t/reports?report_id=1"),
        _record(1, "attacker", "https://t/reports?report_id=2"),
    ]
    alerts = detect_enumeration(records, min_distinct_ids=3)
    assert alerts == []


def test_detect_enumeration_groups_by_path_shape_not_query_string():
    records = [
        _record(0, "attacker", "https://t/patients/1"),
        _record(1, "attacker", "https://t/patients/2"),
        _record(2, "attacker", "https://t/patients/3"),
    ]
    alerts = detect_enumeration(records, min_distinct_ids=3)
    assert len(alerts) == 1
    assert alerts[0].endpoint_shape == "https://t/patients/{id}"


def test_detect_enumeration_separate_identities_not_combined():
    records = [
        _record(0, "user-a", "https://t/patients/1"),
        _record(1, "user-b", "https://t/patients/2"),
        _record(2, "user-c", "https://t/patients/3"),
    ]
    alerts = detect_enumeration(records, min_distinct_ids=3)
    assert alerts == []


def test_detect_enumeration_repeated_same_url_does_not_count_as_distinct():
    records = [
        _record(0, "attacker", "https://t/patients/1"),
        _record(1, "attacker", "https://t/patients/1"),
        _record(2, "attacker", "https://t/patients/1"),
    ]
    alerts = detect_enumeration(records, min_distinct_ids=3)
    assert alerts == []


def test_detect_burst_flags_many_requests_in_short_window():
    records = [
        _record(i, "attacker", "https://t/auth/verify-otp", timestamp=float(i)) for i in range(5)
    ]
    alerts = detect_burst(records, min_requests=5, window_seconds=10.0)
    assert len(alerts) == 1
    assert alerts[0].rule == "burst"


def test_detect_burst_ignores_requests_spread_outside_window():
    records = [
        _record(0, "attacker", "https://t/auth/verify-otp", timestamp=0.0),
        _record(1, "attacker", "https://t/auth/verify-otp", timestamp=20.0),
        _record(2, "attacker", "https://t/auth/verify-otp", timestamp=40.0),
        _record(3, "attacker", "https://t/auth/verify-otp", timestamp=60.0),
        _record(4, "attacker", "https://t/auth/verify-otp", timestamp=80.0),
    ]
    alerts = detect_burst(records, min_requests=5, window_seconds=10.0)
    assert alerts == []


def test_detect_burst_ignores_below_threshold_count():
    records = [
        _record(i, "attacker", "https://t/auth/verify-otp", timestamp=float(i)) for i in range(3)
    ]
    alerts = detect_burst(records, min_requests=5, window_seconds=10.0)
    assert alerts == []


def test_detect_burst_fires_regardless_of_response_status():
    records = [
        _record(i, "attacker", "https://t/auth/login", timestamp=float(i) * 0.1, status=401)
        for i in range(5)
    ]
    alerts = detect_burst(records, min_requests=5, window_seconds=10.0)
    assert len(alerts) == 1


def test_run_detection_combines_both_rules():
    enumeration_records = [
        _record(0, "attacker", "https://t/patients/1"),
        _record(1, "attacker", "https://t/patients/2"),
        _record(2, "attacker", "https://t/patients/3"),
    ]
    burst_records = [
        _record(3 + i, "attacker2", "https://t/auth/verify-otp", timestamp=float(i))
        for i in range(5)
    ]
    alerts = run_detection(enumeration_records + burst_records)
    rules_fired = {a.rule for a in alerts}
    assert rules_fired == {"enumeration", "burst"}


def test_run_detection_empty_input():
    assert run_detection([]) == []
