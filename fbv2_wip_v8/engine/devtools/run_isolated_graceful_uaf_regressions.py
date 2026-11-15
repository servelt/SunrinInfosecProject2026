#!/usr/bin/env python3
"""Run FBv2 integration and product Runtime regressions in fresh processes.

The two groups intentionally do not share ``sys.modules``.  Evaluation-tools
modules are pinned by path during product Runtime tests, so reusing imports
from the FBv2 integration group would make the result order-dependent.
No Provider, model, FullScan, or Target process is started by this runner.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
INTEGRATION_TESTS = (
    "tests/test_campaign_candidate_states.py",
    "tests/test_campaign_model_gate.py",
    "tests/test_fullscan_client_factory.py",
    "tests/test_graceful_public_stop.py",
    "tests/test_ledgered_provider.py",
    "tests/test_model_candidate_lineage.py",
    "tests/test_original_no_seed_phase.py",
    "tests/test_original_no_seed_worker_vertical.py",
    "tests/test_original_public_live_admission.py",
    "tests/test_original_public_live_entry.py",
    "tests/test_pov_admission_order.py",
    "tests/test_pov_local_json_failure.py",
    "tests/test_qualified_gate_early_stop.py",
    "tests/test_qualified_pov_generator_account.py",
    "tests/test_qualified_pov_no_crash_terminal.py",
    "tests/test_qualified_pov_runtime_callback.py",
    "tests/test_qualified_pov_runtime_pending.py",
    "tests/test_sp_dev_queue_drain.py",
)
UAF_TESTS = (
    "tests/test_md4c_uaf_instrumentation_source.py",
    "tests/test_md4c_uaf_trace_emitter.py",
    "tests/test_uaf_gate_reevaluation.py",
)
PRODUCT_TESTS = ("tests/test_product_qualified_runtime.py",)


def _run(paths: tuple[str, ...]) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", *paths], cwd=ROOT,
        check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def main() -> None:
    _run(INTEGRATION_TESTS)
    # The UAF runner requires the current evaluation envelope with explicit
    # LOCAL wall isolation.  Keep it out of any process that may have imported
    # an older product-bundled evaluation-tools module.
    _run(UAF_TESTS)
    _run(PRODUCT_TESTS)


if __name__ == "__main__":
    main()
