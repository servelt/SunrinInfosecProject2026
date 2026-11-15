"""Public toy SP followup: real bounded libFuzzer mutation through the formal handoff.

This development check uses no model, blind target, or Oracle. It leaves a
receipt even when mutation fails to discover a Crash within the bound.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import shutil
import sys
import time
from typing import Any
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PREP = HERE.parent
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
sys.path[:0] = [str(HERE), str(PRODUCT / 'src'), str(PRODUCT / 'tests')]

import blind2_runner_draft as runner  # noqa: E402
from test_formal_sp_crash_e2e_dev import FormalSpCrashEndToEndDevTest  # noqa: E402
from vulnerabilityanalysis.runtime import _guarded_run  # noqa: E402


FUZZ_SECONDS = 5
PROCESS_TIMEOUT_SECONDS = 8
CONSUMER_WALL_SECONDS = 120


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    path.chmod(0o600)


def run_case(root: Path, *, fixed: bool) -> dict[str, Any]:
    root.mkdir(mode=0o700)
    receipt: dict[str, Any] = {
        'kind': 'PUBLIC_SP_FOLLOWUP_ACTUAL_MUTATION_DEV_V1',
        'build': 'FIXED_NEGATIVE' if fixed else 'VULNERABLE_POSITIVE',
        'status': 'INCONCLUSIVE_NOT_STARTED',
        'fuzz_max_total_time_seconds': FUZZ_SECONDS,
        'fuzzer_process_timeout_seconds': PROCESS_TIMEOUT_SECONDS,
        'provider_calls': 0, 'oracle_access': False,
        'scope': 'public toy only; not Blind 3 or target performance evidence',
    }
    compiler = shutil.which('clang')
    if compiler and Path(compiler).is_file():
        receipt['compiler_path'] = compiler
        receipt['compiler_sha256'] = sha(Path(compiler))
    try:
        fixture, token, run = FormalSpCrashEndToEndDevTest()._prepare(root, fixed=fixed)
        receipt['binary_sha256'] = sha(fixture.binary)
        receipt['official_contract_sha256'] = token.contract_sha256
        receipt['initial_clean_seed_sha256'] = sha(run / 'poc/POV1/input.bin')
        receipt['initial_crash_files'] = len(list((run / 'corpus').glob('**/crash-*')))
        if receipt['initial_crash_files']:
            raise ValueError('public toy already has a Crash before mutation')
        ledger = runner.Ledger(started_at=time.time())
        checkpoint = root / 'BUDGET_CHECKPOINT.json'
        calls: list[dict[str, int]] = []

        class NoModelProvider:
            def __init__(self):
                self.ledger = ledger
            def begin_function(self, _function_id):
                pass
            def end_function(self):
                pass

        async def prepared_scan(folder: Path, *_args, **_kwargs):
            if folder.resolve() != run.resolve():
                raise ValueError('public toy Scan run changed')
            save(run / 'scan.json', {
                'selected_function_id': 'fn-toy', 'sp_llm_calls': 0,
                'hp_llm_calls': 0, 'effective_sp_llm_call_limit': 4,
                'combined_llm_call_limit': 8,
            })

        real_targeted_fuzz = runner.scan_mod.run_targeted_fuzz

        def capped_process(argv, *, cwd, timeout):
            if f'-max_total_time={FUZZ_SECONDS}' not in argv:
                raise ValueError('public toy Fuzzer argv exceeded physical time cap')
            return _guarded_run(argv, cwd=cwd,
                                timeout=min(timeout, PROCESS_TIMEOUT_SECONDS))

        def actual_fuzzer(point, binary, folder, retry_ledger, evidence_ids,
                          *, seconds: int):
            calls.append({'meter_requested_seconds': seconds,
                          'actual_fuzz_seconds': min(seconds, FUZZ_SECONDS)})
            return real_targeted_fuzz(
                point, binary, folder, retry_ledger, evidence_ids,
                seconds=min(seconds, FUZZ_SECONDS), guarded_runner=capped_process)

        def uncapped_fuzzer_forbidden(*_args, **_kwargs):
            raise ValueError('public toy default Fuzzer path is forbidden')

        original_followups = runner.run_failed_pov_followups

        def bounded_followups(folder, binary, meter, *, replay_command):
            return original_followups(
                folder, binary, meter, fuzzer_call=actual_fuzzer,
                replay_command=replay_command)

        started = time.monotonic()
        with patch.object(runner.scan_mod, 'scan_selected', prepared_scan), \
             patch.object(runner.scan_mod, 'run_targeted_fuzz',
                          uncapped_fuzzer_forbidden), \
             patch.object(runner, 'run_failed_pov_followups', bounded_followups):
            rows = asyncio.run(runner.run_sequence(
                run, NoModelProvider(), ledger, fixture.upstream, checkpoint,
                max_functions=1,
                scan_options={
                    'run_command': [str(fixture.binary), '{input}'],
                    'target_binary': fixture.binary,
                    'official_qualification': token,
                },
                followup_fuzzer=fixture.binary,
                consumer_budget={
                    'per_item_wall_seconds': CONSUMER_WALL_SECONDS,
                    'combined_wall_seconds': CONSUMER_WALL_SECONDS,
                }))
        receipt['elapsed_seconds'] = max(0.0, time.monotonic() - started)
        receipt['fuzzer_calls'] = calls
        receipt['function_status'] = rows[0]['status'] if rows else 'NO_FUNCTION_ROW'
        followup = json.loads((run / 'runtime/runner_sp_followup_fuzz.json').read_text())
        receipt['new_fuzzer_crash_count'] = sum(
            int(row.get('new_fuzzer_crash_count') or 0) for row in followup)
        receipt['fuzzer_termination_reasons'] = [
            row.get('termination_reason') for row in followup]
        fuzz_runtime_path = run / 'runtime/SP1.targeted_fuzz.json'
        fuzz_seed_path = run / 'runtime/SP1.targeted_fuzz.seeds.json'
        if fuzz_runtime_path.is_file() and fuzz_seed_path.is_file():
            fuzz_runtime = json.loads(fuzz_runtime_path.read_text())
            fuzz_seeds = json.loads(fuzz_seed_path.read_text())
            receipt['fuzzer_runtime_artifact_sha256'] = sha(fuzz_runtime_path)
            receipt['fuzzer_seed_artifact_sha256'] = sha(fuzz_seed_path)
            receipt['fuzzer_exit_code'] = fuzz_runtime.get('exit_code')
            receipt['fuzzer_timed_out'] = fuzz_runtime.get('timed_out')
            receipt['fuzzer_sanitizer_observed'] = bool(fuzz_runtime.get('sanitizer'))
            receipt['mutation_proven_by_progress'] = fuzz_seeds.get('mutation_proven')
            receipt['fuzzer_requested_seconds'] = fuzz_seeds.get('requested_seconds')
            receipt['new_crash_input_sha256'] = [
                row.get('sha256') for row in fuzz_seeds.get('crash_inputs', [])]
            receipt['fuzzer_stderr_recorded_at'] = str(fuzz_runtime_path)
        receipt['mutated_crash_differs_from_seed'] = all(
            replay.get('sha256') != receipt['initial_clean_seed_sha256']
            for row in followup for replay in row.get('original_replays', []))
        consumer_path = run / 'runtime/runner_sp_followup_consumer.json'
        consumer = json.loads(consumer_path.read_text()) if consumer_path.is_file() else []
        receipt['consumer_statuses'] = [row.get('status') for row in consumer]
        gate_artifacts_complete = False
        for row in consumer:
            if row.get('status') != 'VERIFIED':
                continue
            result = row.get('consumer_result') or {}
            canonical_path = Path(result.get('canonical_crash_artifact') or '')
            if not canonical_path.is_file():
                continue
            canonical = json.loads(canonical_path.read_text())
            gate_artifacts_complete = (
                canonical.get('independent_verification_status') == 'VERIFIED' and
                all(Path(canonical.get(key) or '').is_file() for key in (
                    'independent_root_cause_artifact',
                    'independent_replay_artifact',
                    'independent_security_artifact')))
            if gate_artifacts_complete:
                receipt['canonical_crash_artifact_sha256'] = sha(canonical_path)
                break
        receipt['gate_artifacts_complete'] = gate_artifacts_complete
        receipt['original_replay_statuses'] = [
            replay.get('status') for row in followup
            for replay in row.get('original_replays', [])]
        receipt['original_replay_artifact_sha256'] = [
            sha(Path(replay['artifact'])) for row in followup
            for replay in row.get('original_replays', [])
            if isinstance(replay.get('artifact'), str) and
            Path(replay['artifact']).is_file()]
        summary = json.loads((run / 'scan.json').read_text())
        receipt['observed_count'] = len(summary.get('fuzzer_observed_crash_ids', []))
        receipt['reproduced_count'] = len(summary.get('runtime_reproduced_crash_ids', []))
        receipt['verified_count'] = len(summary.get('verified_crash_ids', []))
        receipt['checkpoint_sha256'] = sha(checkpoint)
        if fixed:
            receipt['status'] = ('PASS_FIXED_NEGATIVE' if
                receipt['new_fuzzer_crash_count'] == 0 and
                receipt['verified_count'] == 0 and len(calls) == 1 and
                calls[0]['actual_fuzz_seconds'] <= FUZZ_SECONDS and
                receipt.get('fuzzer_requested_seconds') == FUZZ_SECONDS else
                'INCONCLUSIVE_FIXED_NEGATIVE')
        else:
            receipt['status'] = ('PASS_AUTONOMOUS_MUTATION_TO_GATE' if
                receipt['new_fuzzer_crash_count'] > 0 and
                receipt['mutated_crash_differs_from_seed'] and
                'VERIFIED' in receipt['consumer_statuses'] and
                receipt['gate_artifacts_complete'] and
                receipt['verified_count'] > 0 and len(calls) == 1 and
                calls[0]['actual_fuzz_seconds'] <= FUZZ_SECONDS and
                receipt.get('fuzzer_requested_seconds') == FUZZ_SECONDS else
                'INCONCLUSIVE_NO_AUTONOMOUS_VERIFIED_CRASH')
    except BaseException as exc:
        receipt['status'] = 'INCONCLUSIVE_EXECUTION_ERROR'
        receipt['error_type'] = type(exc).__name__
        receipt['error'] = str(exc)[:500]
    finally:
        save(root / 'RECEIPT.json', receipt)
    return receipt


def main() -> None:
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        raise SystemExit('use an isolated Python with -I -B')
    if len(sys.argv) > 2:
        raise SystemExit('at most one fresh review output path is allowed')
    output = (Path(sys.argv[1]) if len(sys.argv) == 2 else
              PREP / 'review' / 'PUBLIC_SP_FOLLOWUP_MUTATION_DEV_20261031')
    if (not output.is_absolute() or output.parent != PREP / 'review' or
            any(parent.is_symlink() for parent in output.parents)):
        raise ValueError('development output must be a new direct review child')
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    output.mkdir(mode=0o700)
    positive = run_case(output / 'positive', fixed=False)
    negative = run_case(output / 'fixed_negative', fixed=True)
    status = ('PASS' if positive['status'] == 'PASS_AUTONOMOUS_MUTATION_TO_GATE'
              and negative['status'] == 'PASS_FIXED_NEGATIVE' else 'INCONCLUSIVE')
    summary = {
        'kind': 'PUBLIC_SP_FOLLOWUP_MUTATION_DEV_SUMMARY_V1',
        'status': status, 'positive_status': positive['status'],
        'fixed_negative_status': negative['status'],
        'script_sha256': sha(Path(__file__)),
        'provider_calls': 0, 'oracle_access': False,
    }
    save(output / 'SUMMARY.json', summary)
    print(json.dumps({'summary': str(output / 'SUMMARY.json'),
                      'summary_sha256': sha(output / 'SUMMARY.json'),
                      'status': status}, sort_keys=True))


if __name__ == '__main__':
    main()
