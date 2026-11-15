"""Public toy check for the opt-in SP followup physical ledger bridge.

No model, Blind 3 target, or Oracle is used. A 35-second external supervisor
guards the complete child including builds and libFuzzer's -help=1 probe.
The product's physical runner reserves 2+15+9.5 seconds per mutation while
the exact libFuzzer argv is pinned to -max_total_time=2.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sys
import time
from typing import Any
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
PREP = HERE.parent
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis')
sys.path[:0] = [str(HERE), str(PRODUCT / 'src'), str(PRODUCT / 'tests')]

import blind2_runner_draft as formal  # noqa: E402
from dev_persistent_physical_fuzz_ledger import PersistentPhysicalFuzzLedger  # noqa: E402
from dev_product_fuzz_physical_adapter import ProductFuzzPhysicalRunner  # noqa: E402
from dev_sp_followup_physical_bridge import DevSpFollowupPhysicalCall  # noqa: E402
from test_formal_sp_crash_e2e_dev import FormalSpCrashEndToEndDevTest  # noqa: E402


FUZZ_SECONDS = 2
PHYSICAL_TOTAL_SECONDS = 30
EXTERNAL_WALL_SECONDS = 35


def sha(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    path.chmod(0o600)


def one_case(root: Path, physical: ProductFuzzPhysicalRunner,
             *, fixed: bool) -> dict[str, Any]:
    root.mkdir(mode=0o700)
    row: dict[str, Any] = {'status': 'INCONCLUSIVE_NOT_STARTED',
                           'build': 'FIXED_NEGATIVE' if fixed else 'VULNERABLE_POSITIVE'}
    try:
        fixture, token, run = FormalSpCrashEndToEndDevTest()._prepare(
            root, fixed=fixed)
        call = DevSpFollowupPhysicalCall(
            physical_runner=physical,
            contract_ledger_path=physical.ledger.path,
            contract_total_seconds=PHYSICAL_TOTAL_SECONDS,
            expected_run=run, expected_binary=fixture.binary,
            expected_binary_sha256=sha(fixture.binary),
            expected_sp_id='SP1', fuzz_seconds=FUZZ_SECONDS)
        logical = formal.Ledger(started_at=time.time())

        class NoModelProvider:
            def __init__(self):
                self.ledger = logical
            def begin_function(self, _function_id):
                pass
            def end_function(self):
                pass

        async def prepared_scan(folder: Path, *_args, **_kwargs):
            if folder != run:
                raise ValueError('public toy Scan run changed')
            save(run / 'scan.json', {
                'selected_function_id': 'fn-toy', 'sp_llm_calls': 0,
                'hp_llm_calls': 0, 'effective_sp_llm_call_limit': 4,
                'combined_llm_call_limit': 8})

        original_followups = formal.run_failed_pov_followups

        def physical_followups(folder, binary, meter, *, replay_command):
            return original_followups(
                folder, binary, meter, fuzzer_call=call,
                replay_command=replay_command)

        with patch.object(formal.scan_mod, 'scan_selected', prepared_scan), \
             patch.object(formal, 'run_failed_pov_followups', physical_followups):
            rows = asyncio.run(formal.run_sequence(
                run, NoModelProvider(), logical, fixture.upstream,
                root / 'BUDGET_CHECKPOINT.json', max_functions=1,
                scan_options={
                    'run_command': [str(fixture.binary), '{input}'],
                    'target_binary': fixture.binary,
                    'official_qualification': token},
                followup_fuzzer=fixture.binary,
                consumer_budget={'per_item_wall_seconds': 120,
                                 'combined_wall_seconds': 120}))
        followups = json.loads((run / 'runtime/runner_sp_followup_fuzz.json').read_text())
        scans = json.loads((run / 'scan.json').read_text())
        seed_path = run / 'runtime/SP1.targeted_fuzz.seeds.json'
        seeds = json.loads(seed_path.read_text())
        runtime_path = run / 'runtime/SP1.targeted_fuzz.json'
        runtime = json.loads(runtime_path.read_text())
        crashes = seeds.get('crash_inputs', [])
        new_sha = [item['sha256'] for item in crashes]
        original_seed_sha = sha(run / 'poc/POV1/input.bin')
        consumers_path = run / 'runtime/runner_sp_followup_consumer.json'
        consumers = (json.loads(consumers_path.read_text())
                     if consumers_path.is_file() else [])
        physical_state = physical.ledger.snapshot()
        row.update({
            'status': 'INCONCLUSIVE_RESULT',
            'provider_calls': 0, 'oracle_access': False,
            'binary_sha256': sha(fixture.binary),
            'initial_clean_seed_sha256': original_seed_sha,
            'new_crash_input_sha256': new_sha,
            'new_crash_input_matches_file': all(
                Path(item['candidate_path']).is_file() and
                sha(Path(item['candidate_path'])) == item['sha256']
                for item in crashes),
            'new_crash_differs_from_seed': bool(new_sha) and all(
                value != original_seed_sha for value in new_sha),
            'new_fuzzer_crash_count': sum(
                int(item.get('new_fuzzer_crash_count') or 0)
                for item in followups),
            'fuzzer_requested_seconds': seeds.get('requested_seconds'),
            'fuzzer_exit_code': runtime.get('exit_code'),
            'fuzzer_timed_out': runtime.get('timed_out'),
            'fuzzer_runtime_artifact_sha256': sha(runtime_path),
            'fuzzer_seed_artifact_sha256': sha(seed_path),
            'original_replay_statuses': [
                replay.get('status') for item in followups
                for replay in item.get('original_replays', [])],
            'consumer_statuses': [item.get('status') for item in consumers],
            'observed_count': len(scans.get('fuzzer_observed_crash_ids', [])),
            'reproduced_count': len(scans.get('runtime_reproduced_crash_ids', [])),
            'verified_count': len(scans.get('verified_crash_ids', [])),
            'formal_function_status': rows[0].get('status') if rows else None,
            'guarded_invocations': call.guarded_invocations,
            'physical_finished_count': len(physical_state['finished']),
            'physical_spent_seconds': physical_state['spent_seconds'],
            'physical_stop_status': physical_state['stop_status'],
        })
        common = (row['fuzzer_requested_seconds'] == FUZZ_SECONDS and
                  row['guarded_invocations'] == 1 and
                  physical_state['stop_status'] is None and
                  all(item['kind'] == 'SP' and not item['overrun'] and
                      item['cleanup_complete'] for item in physical_state['finished']))
        if fixed:
            if (common and row['new_fuzzer_crash_count'] == 0 and
                    row['verified_count'] == 0 and
                    row['fuzzer_exit_code'] == 0 and
                    row['fuzzer_timed_out'] is False):
                row['status'] = 'PASS_FIXED_NEGATIVE'
        elif (common and row['new_fuzzer_crash_count'] > 0 and
              row['new_crash_input_matches_file'] and
              row['new_crash_differs_from_seed'] and
              row['original_replay_statuses'] == ['REPLAYED'] and
              'VERIFIED' in row['consumer_statuses'] and
              row['verified_count'] > 0 and
              row['fuzzer_timed_out'] is False):
            row['status'] = 'PASS_SP_PHYSICAL_MUTATION_TO_GATE'
    except BaseException as exc:
        row['status'] = 'INCONCLUSIVE_EXECUTION_ERROR'
        row['error_type'] = type(exc).__name__
        row['error'] = str(exc)[:500]
    finally:
        save(root / 'RECEIPT.json', row)
    return row


def child(output: Path) -> None:
    ledger_path = output / 'PHYSICAL_FUZZ_LEDGER.json'
    ledger = PersistentPhysicalFuzzLedger.create(
        ledger_path, total_seconds=PHYSICAL_TOTAL_SECONDS)
    physical = ProductFuzzPhysicalRunner(ledger, kind='SP')
    positive = one_case(output / 'positive', physical, fixed=False)
    negative = one_case(output / 'fixed_negative', physical, fixed=True)
    state = ledger.snapshot()
    status = ('PASS' if positive['status'] == 'PASS_SP_PHYSICAL_MUTATION_TO_GATE'
              and negative['status'] == 'PASS_FIXED_NEGATIVE' and
              len(state['finished']) == 2 and
              state['spent_seconds'] <= PHYSICAL_TOTAL_SECONDS and
              state['stop_status'] is None else 'INCONCLUSIVE')
    summary = {
        'status': status,
        'scope': 'public toy development only; no formal Blind 3 readiness claim',
        'positive_status': positive['status'],
        'fixed_negative_status': negative['status'],
        'physical_ledger_path': str(ledger_path),
        'physical_ledger_sha256': sha(ledger_path),
        'physical_total_seconds': PHYSICAL_TOTAL_SECONDS,
        'physical_spent_seconds': state['spent_seconds'],
        'physical_finished_count': len(state['finished']),
        'physical_roles': [item['kind'] for item in state['finished']],
        'physical_stop_status': state['stop_status'],
        'fuzz_max_total_time_seconds_each': FUZZ_SECONDS,
        'external_wall_seconds': EXTERNAL_WALL_SECONDS,
        'script_sha256': sha(Path(__file__)),
        'provider_calls': 0, 'oracle_access': False,
    }
    save(output / 'SUMMARY.json', summary)
    save(output / 'RUNNER_RESULT.json', {'status': status,
                                        'summary_sha256': sha(output / 'SUMMARY.json')})


def main() -> None:
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        raise SystemExit('use /usr/bin/python3.12 -I -B')
    if len(sys.argv) == 3 and sys.argv[1] == '--child':
        child(Path(sys.argv[2]))
        return
    if len(sys.argv) != 2:
        raise SystemExit('usage: run_dev_sp_followup_physical_toy.py NEW_REVIEW_DIR')
    output = Path(sys.argv[1])
    if (not output.is_absolute() or output.parent != PREP / 'review' or
            output.exists() or output.is_symlink()):
        raise ValueError('public toy output must be a fresh direct review child')
    output.mkdir(mode=0o700)
    supervised = formal.supervise_child(
        [sys.executable, '-I', '-B', str(Path(__file__).resolve()),
         '--child', str(output)], output, timeout_seconds=EXTERNAL_WALL_SECONDS)
    summary_path = output / 'SUMMARY.json'
    summary_status = (json.loads(summary_path.read_text()).get('status')
                      if summary_path.is_file() else 'INCONCLUSIVE_NO_SUMMARY')
    print(json.dumps({'supervisor_status': supervised,
                      'summary_status': summary_status,
                      'summary': str(summary_path) if summary_path.is_file() else None,
                      'summary_sha256': sha(summary_path)
                      if summary_path.is_file() else None}, sort_keys=True))


if __name__ == '__main__':
    main()
