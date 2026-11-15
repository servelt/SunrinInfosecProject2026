"""Development-only SP/HP physical callback admission for one product Scan.

The caller supplies the ledger path and total from an independently frozen
contract. This module checks callback identity and the live checkpoint before
entering ``scan_selected``. It does not authorize Global Fuzzing, establish
Freeze pins, or protect a checkpoint from rollback by another same-UID writer.
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Mapping

from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger
from dev_product_fuzz_physical_adapter import ProductFuzzPhysicalRunner
from vulnerabilityanalysis import scan


class SharedPhysicalPreflightError(ValueError):
    """Do not enter product Scan with an unproven SP/HP callback pair."""


def _validate_ledger(ledger: object, *, contract_ledger_path: Path,
                     contract_total_seconds: float) -> PersistentPhysicalFuzzLedger:
    if (type(ledger) is not PersistentPhysicalFuzzLedger or
            not isinstance(contract_ledger_path, Path) or
            not contract_ledger_path.is_absolute() or
            '..' in contract_ledger_path.parts or
            contract_ledger_path.resolve(strict=False) != contract_ledger_path or
            type(contract_total_seconds) not in (int, float) or
            not math.isfinite(contract_total_seconds) or
            contract_total_seconds <= 0):
        raise SharedPhysicalPreflightError('invalid contracted physical ledger')
    expected_lock = contract_ledger_path.with_name(contract_ledger_path.name + '.lock')
    if ledger.path != contract_ledger_path or ledger.lock_path != expected_lock:
        raise SharedPhysicalPreflightError('physical ledger path differs from contract')
    try:
        # The ledger checks owner PID, lock ownership/mode, and disk CAS even
        # when no reservation is requested. A corrupt low-balance checkpoint
        # must never be mistaken for ordinary budget exhaustion.
        ledger._verify_checkpoint_current()
        state = ledger.snapshot()
    except (OSError, ValueError, RuntimeError) as exc:
        raise SharedPhysicalPreflightError(
            'physical ledger checkpoint or owner is untrusted') from exc
    if (state['total_seconds'] != float(contract_total_seconds) or
            state['stop_status'] is not None or state['active']):
        raise SharedPhysicalPreflightError(
            'physical ledger contract, stop state, or active jobs differ')
    return ledger


def preflight_shared_sp_hp_callbacks(*, contract_ledger_path: Path,
                                     contract_total_seconds: float,
                                     sp_runner: object,
                                     hp_runner: object
                                     ) -> PersistentPhysicalFuzzLedger:
    """Require exact callback classes, roles, one live ledger, and one path."""
    if (type(sp_runner) is not ProductFuzzPhysicalRunner or
            type(hp_runner) is not ProductFuzzPhysicalRunner or
            sp_runner is hp_runner or
            sp_runner.kind != 'SP' or hp_runner.kind != 'HP' or
            sp_runner.ledger is not hp_runner.ledger or
            type(sp_runner.cleanup_envelope_seconds) not in (int, float) or
            type(hp_runner.cleanup_envelope_seconds) not in (int, float) or
            not math.isfinite(sp_runner.cleanup_envelope_seconds) or
            not math.isfinite(hp_runner.cleanup_envelope_seconds) or
            min(sp_runner.cleanup_envelope_seconds,
                hp_runner.cleanup_envelope_seconds) < 9.5):
        raise SharedPhysicalPreflightError(
            'SP and HP require distinct trusted callbacks sharing one ledger')
    return _validate_ledger(sp_runner.ledger,
                            contract_ledger_path=contract_ledger_path,
                            contract_total_seconds=contract_total_seconds)


def make_shared_sp_hp_runners(
        ledger: PersistentPhysicalFuzzLedger, *,
        contract_ledger_path: Path, contract_total_seconds: float
        ) -> tuple[ProductFuzzPhysicalRunner, ProductFuzzPhysicalRunner]:
    """Construct the two callbacks only after checking the contracted ledger."""
    checked = _validate_ledger(
        ledger, contract_ledger_path=contract_ledger_path,
        contract_total_seconds=contract_total_seconds)
    return (ProductFuzzPhysicalRunner(checked, kind='SP'),
            ProductFuzzPhysicalRunner(checked, kind='HP'))


def _scan_options(scan_options: Mapping[str, Any], *,
                  sp_runner: ProductFuzzPhysicalRunner,
                  hp_runner: ProductFuzzPhysicalRunner) -> dict[str, Any]:
    if not isinstance(scan_options, Mapping):
        raise SharedPhysicalPreflightError('product Scan options must be a mapping')
    options = dict(scan_options)
    if ({'targeted_fuzz_guarded_runner', 'hp_guided_guarded_runner'} &
            options.keys()):
        raise SharedPhysicalPreflightError('physical callbacks may not be overridden')
    if (options.get('global_fuzz_enabled', False) is not False or
            type(options.get('global_fuzz_seconds', 0)) is not int or
            options.get('global_fuzz_seconds', 0) != 0 or
            options.get('global_fuzzer_binary') is not None):
        raise SharedPhysicalPreflightError('Global Fuzzing is outside this handoff')
    if (type(options.get('max_candidates')) is not int or
            options['max_candidates'] != 1 or
            options.get('candidate_budget_policy') not in
            {'DRAIN_RANKED_DEV', 'QUEUE_FIRST_DEV'} or
            options.get('official_qualification') is None or
            options.get('targeted_fuzzer_binary') is None or
            type(options.get('targeted_fuzz_seconds')) is not int or
            options['targeted_fuzz_seconds'] < 1 or
            type(options.get('assertion_fuzz_seconds')) is not int or
            options['assertion_fuzz_seconds'] < 1):
        raise SharedPhysicalPreflightError(
            'shared SP/HP callbacks require serial official development Scan')
    options['global_fuzz_enabled'] = False
    options['global_fuzz_seconds'] = 0
    options['targeted_fuzz_guarded_runner'] = sp_runner
    options['hp_guided_guarded_runner'] = hp_runner
    return options


async def scan_selected_with_shared_sp_hp_physical(
        run_dir: Path, provider: Any, *,
        contract_ledger_path: Path, contract_total_seconds: float,
        sp_runner: ProductFuzzPhysicalRunner,
        hp_runner: ProductFuzzPhysicalRunner,
        scan_options: Mapping[str, Any]) -> Path:
    """Reject an invalid pair before product Scan can call the provider."""
    preflight_shared_sp_hp_callbacks(
        contract_ledger_path=contract_ledger_path,
        contract_total_seconds=contract_total_seconds,
        sp_runner=sp_runner, hp_runner=hp_runner)
    options = _scan_options(scan_options, sp_runner=sp_runner,
                            hp_runner=hp_runner)
    return await scan.scan_selected(run_dir, provider, **options)
