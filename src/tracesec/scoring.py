"""
tracesec.scoring

Scores a list of Findings against a ground-truth set of vulnerable
(vuln_class, method, path) tuples, per the rules in docs/EVALUATION.md
("Ground truth and scoring rules"):

- A finding is a true positive if its (vuln_class, method, path) exactly
  matches an item in ground truth.
- Duplicate findings for the same (vuln_class, method, path) collapse
  into one before scoring.
- A finding whose (vuln_class, method, path) is not in ground truth is
  a false positive -- this covers findings on patched, decoy, or
  negative-control endpoints, since those are simply absent from ground
  truth for that run.
- A ground-truth item with no matching finding is a false negative.
- Right endpoint, wrong class counts as one FP (the wrong claim) and
  one FN (the real vulnerability was missed) -- this falls out
  naturally from tuple matching that includes vuln_class, no special
  casing needed.

Path matching is exact, not templated. Callers are expected to pass
ground truth and findings using the same path convention (TRACE-Bench's
GROUND_TRUTH.yaml and TRACE's own spec ingestion both use OpenAPI-style
templated paths, e.g. "/patients/{patient_id}", so in practice this is
consistent without extra normalization). Method comparison is
case-insensitive. The ground_truth list passed in is expected to be
pre-deduplicated by the caller (each scenario appears once).
"""

from dataclasses import dataclass

from tracesec.findings import Finding, VulnerabilityClass

type GroundTruthItem = tuple[VulnerabilityClass, str, str]


def _key(vuln_class: VulnerabilityClass, method: str, path: str) -> tuple[str, str, str]:
    return (vuln_class.value, method.upper(), path)


@dataclass(frozen=True)
class ScoreResult:
    true_positives: int
    false_positives: int
    false_negatives: int
    fp_findings: list[Finding]
    fn_items: list[GroundTruthItem]

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return self.true_positives / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def score_findings(findings: list[Finding], ground_truth: list[GroundTruthItem]) -> ScoreResult:
    """Score findings against ground truth. Duplicate findings for the
    same (vuln_class, method, path) are collapsed before scoring."""
    gt_keys = {_key(*item) for item in ground_truth}

    seen: set[tuple[str, str, str]] = set()
    deduped: list[Finding] = []
    for finding in findings:
        key = _key(finding.vuln_class, finding.method, finding.endpoint)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)

    matched_gt_keys: set[tuple[str, str, str]] = set()
    fp_findings: list[Finding] = []
    tp_count = 0

    for finding in deduped:
        key = _key(finding.vuln_class, finding.method, finding.endpoint)
        if key in gt_keys:
            tp_count += 1
            matched_gt_keys.add(key)
        else:
            fp_findings.append(finding)

    fn_items = [item for item in ground_truth if _key(*item) not in matched_gt_keys]

    return ScoreResult(
        true_positives=tp_count,
        false_positives=len(fp_findings),
        false_negatives=len(fn_items),
        fp_findings=fp_findings,
        fn_items=fn_items,
    )


def score_by_class(
    findings: list[Finding], ground_truth: list[GroundTruthItem]
) -> dict[VulnerabilityClass, ScoreResult]:
    """Same as score_findings, but broken out per VulnerabilityClass."""
    results: dict[VulnerabilityClass, ScoreResult] = {}
    for vuln_class in VulnerabilityClass:
        class_findings = [f for f in findings if f.vuln_class == vuln_class]
        class_gt = [item for item in ground_truth if item[0] == vuln_class]
        results[vuln_class] = score_findings(class_findings, class_gt)
    return results
