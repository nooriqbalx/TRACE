"""
Unit tests for tracesec.scoring: Finding vs. ground-truth comparison,
per docs/EVALUATION.md's scoring rules. Hand-made fixtures throughout.
"""

from tracesec.findings import Finding, VulnerabilityClass
from tracesec.scoring import score_by_class, score_findings


def _finding(vuln_class, method, path, finding_id="f"):
    return Finding(
        finding_id=finding_id,
        vuln_class=vuln_class,
        endpoint=path,
        method=method,
        claim="test claim",
        evidence_ids=[0],
    )


def test_exact_match_is_true_positive():
    gt = [(VulnerabilityClass.BOLA, "GET", "/patients/{id}")]
    findings = [_finding(VulnerabilityClass.BOLA, "GET", "/patients/{id}")]

    result = score_findings(findings, gt)

    assert result.true_positives == 1
    assert result.false_positives == 0
    assert result.false_negatives == 0
    assert result.precision == 1.0
    assert result.recall == 1.0


def test_finding_not_in_ground_truth_is_false_positive():
    gt = [(VulnerabilityClass.BOLA, "GET", "/patients/{id}")]
    findings = [
        _finding(VulnerabilityClass.BOLA, "GET", "/patients/{id}"),
        _finding(VulnerabilityClass.BOLA, "GET", "/patients/{id}/billing"),
    ]

    result = score_findings(findings, gt)

    assert result.true_positives == 1
    assert result.false_positives == 1
    assert result.false_negatives == 0


def test_unmatched_ground_truth_is_false_negative():
    gt = [
        (VulnerabilityClass.BOLA, "GET", "/patients/{id}"),
        (VulnerabilityClass.BROKEN_AUTHENTICATION, "POST", "/auth/verify-otp"),
    ]
    findings = [_finding(VulnerabilityClass.BOLA, "GET", "/patients/{id}")]

    result = score_findings(findings, gt)

    assert result.true_positives == 1
    assert result.false_negatives == 1
    assert result.fn_items == [
        (VulnerabilityClass.BROKEN_AUTHENTICATION, "POST", "/auth/verify-otp")
    ]


def test_right_endpoint_wrong_class_is_one_fp_and_one_fn():
    gt = [(VulnerabilityClass.BOLA, "GET", "/patients/{id}")]
    findings = [_finding(VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE, "GET", "/patients/{id}")]

    result = score_findings(findings, gt)

    assert result.true_positives == 0
    assert result.false_positives == 1
    assert result.false_negatives == 1


def test_duplicate_findings_collapse_before_scoring():
    gt = [(VulnerabilityClass.BOLA, "GET", "/patients/{id}")]
    findings = [
        _finding(VulnerabilityClass.BOLA, "GET", "/patients/{id}", finding_id="a"),
        _finding(VulnerabilityClass.BOLA, "GET", "/patients/{id}", finding_id="b"),
    ]

    result = score_findings(findings, gt)

    assert result.true_positives == 1
    assert result.false_positives == 0


def test_method_matching_is_case_insensitive():
    gt = [(VulnerabilityClass.BOLA, "GET", "/patients/{id}")]
    findings = [_finding(VulnerabilityClass.BOLA, "get", "/patients/{id}")]

    result = score_findings(findings, gt)

    assert result.true_positives == 1


def test_empty_findings_and_empty_ground_truth():
    result = score_findings([], [])
    assert result.true_positives == 0
    assert result.precision == 0.0
    assert result.recall == 0.0
    assert result.f1 == 0.0


def test_f1_computed_correctly():
    gt = [
        (VulnerabilityClass.BOLA, "GET", "/a"),
        (VulnerabilityClass.BOLA, "GET", "/b"),
    ]
    findings = [
        _finding(VulnerabilityClass.BOLA, "GET", "/a"),
        _finding(VulnerabilityClass.BOLA, "GET", "/c"),
    ]
    result = score_findings(findings, gt)
    assert result.precision == 0.5
    assert result.recall == 0.5
    assert result.f1 == 0.5


def test_score_by_class_separates_results():
    gt = [
        (VulnerabilityClass.BOLA, "GET", "/patients/{id}"),
        (VulnerabilityClass.RATE_LIMITING, "POST", "/auth/login"),
    ]
    findings = [_finding(VulnerabilityClass.BOLA, "GET", "/patients/{id}")]

    results = score_by_class(findings, gt)

    assert results[VulnerabilityClass.BOLA].true_positives == 1
    assert results[VulnerabilityClass.RATE_LIMITING].false_negatives == 1
    assert results[VulnerabilityClass.EXCESSIVE_DATA_EXPOSURE].true_positives == 0
