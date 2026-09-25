"""
tracesec.fix_and_prove

Runs a verifier oracle against the same live target twice -- once
while a scenario is vulnerable, once after it has been patched -- and
confirms the verdict actually flips from CONFIRMED to REFUTED via
tracesec.verifier.check_regression. This proves an oracle is genuinely
sensitive to the target's real behavior, not merely returning the same
verdict regardless of what is actually running.

This is the automated form of what was done by hand across this
project: manually reproducing the BOLA bug on crAPI's vehicle-location
endpoint, then manually confirming the patched build in TRACE-Bench's
bola_direct_path scenario blocks the same attack (see
docs/lab/crapi-manual-notes.md and bench/GROUND_TRUTH.yaml).

TRACE-Bench is a natural fit for this workflow specifically because
every scenario there is controlled by a single environment variable
(TRACEBENCH_PATCH_<SCENARIO>), so "patch the target" is something this
module can trigger, in-process, by mutating os.environ around the
second verification pass -- no redeploy needed.
"""

import os
from collections.abc import Callable
from dataclasses import dataclass

from tracesec.executor import Executor
from tracesec.findings import Finding


class RegressionCheckFailed(Exception):
    """Raised when a fix-and-prove run's pre/post verdicts did not
    flip from CONFIRMED to REFUTED as expected."""


@dataclass(frozen=True)
class FixAndProveResult:
    scenario_id: str
    pre_patch_finding: Finding
    post_patch_finding: Finding
    regression_confirmed: bool


def run_fix_and_prove(
    scenario_id: str,
    patch_env_var: str,
    verify_fn: Callable[[Executor], Finding],
    executor: Executor,
) -> FixAndProveResult:
    """Run verify_fn once with patch_env_var unset (vulnerable) and
    once with it set to "1" (patched), restoring the environment
    variable's original state afterward regardless of outcome.

    verify_fn is a caller-supplied closure over one of
    tracesec.verifier's oracles (verify_bola, verify_exposure, or a
    wrapper around verify_unthrottled), e.g.:

        run_fix_and_prove(
            "bola_direct_path",
            "TRACEBENCH_PATCH_BOLA_DIRECT_PATH",
            lambda ex: verify_bola(ex, url, "GET", owner, other,
                                    finding_id="f", endpoint="/patients/{id}"),
            executor,
        )

    Raises RegressionCheckFailed if the pre/post verdicts do not flip
    from CONFIRMED to REFUTED as tracesec.verifier.check_regression
    defines a valid regression.
    """
    from tracesec.verifier import check_regression

    original_value = os.environ.get(patch_env_var)

    try:
        os.environ.pop(patch_env_var, None)
        pre_patch_finding = verify_fn(executor)

        os.environ[patch_env_var] = "1"
        post_patch_finding = verify_fn(executor)
    finally:
        if original_value is None:
            os.environ.pop(patch_env_var, None)
        else:
            os.environ[patch_env_var] = original_value

    regression_confirmed = check_regression(pre_patch_finding, post_patch_finding)
    if not regression_confirmed:
        raise RegressionCheckFailed(
            f"{scenario_id}: expected CONFIRMED -> REFUTED, got "
            f"{pre_patch_finding.verdict.value} -> {post_patch_finding.verdict.value}"
        )

    return FixAndProveResult(
        scenario_id=scenario_id,
        pre_patch_finding=pre_patch_finding,
        post_patch_finding=post_patch_finding,
        regression_confirmed=regression_confirmed,
    )
