"""Bounded replay of a real new md4c Fuzzer input through product Runtime."""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys

EVAL = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027')
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src')
sys.path.insert(0, str(EVAL / 'evaluation_tools'))
sys.path.insert(0, str(PRODUCT))

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from vulnerabilityanalysis.official_harness import (
    _qualification_pins_ok, issue_official_pinned_qualification,
)
from vulnerabilityanalysis.runtime import RuntimeExecutor


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    campaign = Path('/tmp/fbv2-md4c-corpus-continuation-20261102-run')
    root = Path('/tmp/md4c-fuzzer-new-seed-replay-20261102-run')
    if root.exists():
        raise ValueError('fresh negative replay output required')
    contract_path = EVAL / 'public/OFFICIAL_HARNESS_CONTRACT.json'
    contract = json.loads(contract_path.read_text())
    local = contract['local']
    q = issue_official_pinned_qualification(
        contract_path=contract_path, approved_contract_sha256=sha(contract_path),
        source_root=Path(contract['target']['source_root']),
        harness=Path(local['harness_file']), binary=Path(local['binary']),
        normal_seed=Path(local['normal_seed']),
        oss_fuzz_checkout=EVAL / 'oss_fuzz_checkout',
        upstream_checkout=EVAL / 'upstream_asan_final')
    if q is None or not _qualification_pins_ok(q):
        raise ValueError('official md4c qualification changed')
    result_path = campaign / 'BASELINE_RESULT.json'
    report_path = campaign / 'global_campaign/runtime/global_fuzz.json'
    result = json.loads(result_path.read_text())
    report = json.loads(report_path.read_text())
    if (result.get('status') != 'RAN' or
            result.get('seed_provenance') != 'HARNESS_NORMAL_SEED_FUZZ_CONTINUATION' or
            result.get('observed_crash_count') != 0 or
            report.get('status') != 'RAN' or
            report.get('binary_sha256') != q.binary_sha256 or
            report.get('observed_crashes') != [] or
            not report.get('new_seed_hashes')):
        raise ValueError('completed new-input campaign is unavailable')
    chosen_sha = sorted(report['new_seed_hashes'])[0]
    corpus = campaign / 'global_campaign/corpus/global'
    matches = [path for path in corpus.iterdir()
               if path.is_file() and not path.is_symlink() and sha(path) == chosen_sha]
    if len(matches) != 1:
        raise ValueError('new Fuzzer input is not unique in preserved corpus')
    data = matches[0].read_bytes()
    root.mkdir(mode=0o700)
    input_path = root / 'input.bin'
    input_path.write_bytes(data)
    input_path.chmod(0o600)
    ledger = PersistentProcessLedgerV2.create(
        root / 'process-ledger.json', wall_total_seconds=60,
        fuzz_total_seconds=0)

    def pin(_phase: str, _command: list[str]) -> None:
        if not _qualification_pins_ok(q) or sha(input_path) != chosen_sha:
            raise ValueError('qualified source, binary, Harness or input changed')

    envelope = DevelopmentProcessEnvelopeV2(
        ledger, work_item_id='md4c-fuzzer-new-seed',
        assertion_id='NO_CRASH_CONTROL', attempt_id='new-seed-replay-20261102',
        output_limit_bytes=1_000_000, total_wall_seconds=60, pin_hook=pin)
    runtime = RuntimeExecutor(timeout_seconds=5)
    observations = []
    for segment in ('new_input_observation', 'independent_replay'):
        observed = runtime.run([str(q.binary), '{input}'], input_path,
                               process_envelope=envelope, process_segment=segment)
        observations.append({'segment': segment, **asdict(observed)})
    ledger_data, ledger_sha = ledger.receipt_snapshot()
    no_crash = all(row['exit_code'] == 0 and not row['timed_out'] and
                   row['sanitizer'] is None for row in observations)
    if (len(ledger_data['finished']) != 2 or ledger_data['active'] or
            ledger_data['stop_status'] is not None):
        raise RuntimeError('Runtime replay did not settle twice')
    receipt = {
        'kind': 'MD4C_NEW_FUZZER_INPUT_PRODUCT_RUNTIME_NEGATIVE_REPLAY_V1',
        'campaign_result_sha256': sha(result_path),
        'campaign_global_report_sha256': sha(report_path),
        'binary_sha256': q.binary_sha256,
        'harness_sha256': q.harness_sha256,
        'input_sha256': chosen_sha,
        'input_source_path': str(matches[0]),
        'input_size': len(data),
        'source_kind': 'GLOBAL_FUZZ_NEW_SEED',
        'model_calls': 0,
        'automatic_discovery_credit': 'NOT_CREDITED',
        'observations': observations,
        'gate_status': 'NOT_STARTED_NO_CRASH' if no_crash else 'PENDING_OBSERVED_CRASH',
        'process_ledger_sha256': ledger_sha,
        'process_finished': len(ledger_data['finished']),
        'process_active': len(ledger_data['active']),
        'process_stop': ledger_data['stop_status'],
    }
    (root / 'result.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    print(json.dumps({'input_sha256': chosen_sha, 'no_crash': no_crash,
                      'gate_status': receipt['gate_status'],
                      'process_finished': receipt['process_finished']}, sort_keys=True))


if __name__ == '__main__':
    main()
