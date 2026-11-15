"""Conservative, backend-independent audit of claimed qualification.

This is an evidence audit, not a proof of semantic equivalence. A successful
build/fuzz run must never be presented as original/harness equivalence.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..models import VerificationResult, ScenarioStatus, ScenarioWitness


@dataclass(frozen=True)
class QualificationAudit:
    accepted: bool
    blockers: tuple[str, ...]
    observed: tuple[str, ...]


def audit_qualification(
    result: VerificationResult, witness: ScenarioWitness | None = None,
    *, differential_evidence: bool = False,
) -> QualificationAudit:
    """Check if qualification is substantiated, never elevate a failed result.

    ``differential_evidence`` must be supplied by an independent original-vs-
    harness executor after an actual comparison; callers must not infer it from
    coverage, source citations, or GDB breakpoint order.
    """
    blockers: list[str] = []
    observed: list[str] = []
    if result.build_ok and result.build is not None and result.build.returncode == 0 and not result.build.timed_out:
        observed.append('build')
    else:
        blockers.append('BUILD_NOT_VERIFIED')
    if result.reachable_seed_count > 0:
        observed.append('target_reach')
    else:
        blockers.append('TARGET_REACH_NOT_VERIFIED')
    if result.fuzz is not None and result.fuzz.returncode == 0 and not result.fuzz.timed_out:
        observed.append('fuzz_execution')
    else:
        blockers.append('FUZZ_EXECUTION_NOT_VERIFIED')
    if result.coverage_grew is True:
        observed.append('coverage_growth')
    elif not result.target_findings:
        blockers.append('NO_COVERAGE_OR_ATTRIBUTED_FINDING')
    if result.harness_faults or result.infrastructure_error:
        blockers.append('HARNESS_OR_INFRASTRUCTURE_FAULT')
    if witness is None or witness.status is not ScenarioStatus.PROVEN_RUNTIME:
        blockers.append('ORIGINAL_RUNTIME_NOT_PROVEN')
    else:
        observed.append('original_runtime')
    if not differential_evidence:
        blockers.append('ORIGINAL_HARNESS_EQUIVALENCE_NOT_VERIFIED')
    else:
        observed.append('differential_comparison')
    if not result.qualified:
        blockers.append('VERIFIER_DID_NOT_QUALIFY')
    return QualificationAudit(not blockers, tuple(blockers), tuple(observed))
