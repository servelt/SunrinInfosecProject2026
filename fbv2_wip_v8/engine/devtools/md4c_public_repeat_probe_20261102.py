"""Bounded, model-free md4c probe using repeated public syntax examples.

Every generated Seed is a mechanical repetition of a pinned CommonMark spec
example. This is a development experiment, not an official FBv2 model Seed or
an automatic discovery credit issuer. Crash artifacts require product review.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import traceback


BASE = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027')
sys.path[:0] = [str(BASE / 'evaluation_tools'),
                '/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src']

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from vulnerabilityanalysis.official_harness import (
    issue_official_pinned_qualification, _qualification_pins_ok)
from vulnerabilityanalysis.runtime import _guarded_run


CONTRACT_SHA = 'a1c6217b2daf73ccc97d3efd92b3125690b1316246208ae8fce72e2a29ef9b10'
HANDOFF_SHA = '374d9a2c5702d53cf5ce4b8393800b7614b69dbbfc30b3d5c1ed34e04b37e5be'
SPEC_SHA = '257c41ad946f7a1414a499aca402a1aa8fdac3678532266611348c1cf54f4b80'
EXCLUDED = {
    '9de288250d625a75471a2da8f876d22472f871190eec592664fcd201130d5613',
    '92bec7016603ecbe922a2f365f83fbddb4dacf874a47c8758e6440fed681cf63',
    '0b45653c1f2dde121767938145c4a6e83c0c0bfff33238c6e72ef29940d722e2',
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, value: object) -> None:
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def main() -> None:
    contract = BASE / 'public/OFFICIAL_HARNESS_CONTRACT.json'
    if sha(contract) != CONTRACT_SHA:
        raise ValueError('official contract pin changed')
    qualified = issue_official_pinned_qualification(
        contract_path=contract, approved_contract_sha256=CONTRACT_SHA,
        source_root=BASE / 'model_target',
        harness=BASE / 'v2_artifact_stage/attempt/fuzz-mdhtml.c',
        binary=BASE / 'build/asan',
        normal_seed=BASE / 'public/normal_seed_corpus/seed_00.bin',
        oss_fuzz_checkout=BASE / 'oss_fuzz_checkout',
        upstream_checkout=BASE / 'upstream_asan_final')
    if qualified is None or not _qualification_pins_ok(qualified):
        raise ValueError('official md4c qualification unavailable')
    handoff_path = Path('/tmp/fbv2-md4c-spec-flags-20261102-run/global_campaign/'
                        'UPSTREAM_SPEC_FLAG_PROFILES_HANDOFF.json')
    if qualified.upstream_checkout is None:
        raise ValueError('qualified upstream checkout unavailable')
    spec_path = qualified.upstream_checkout / 'test/spec.txt'
    if sha(handoff_path) != HANDOFF_SHA or sha(spec_path) != SPEC_SHA:
        raise ValueError('pinned public spec handoff changed')
    handoff = json.loads(handoff_path.read_text())
    if handoff.get('seed_count') != 766 or len(handoff.get('seeds', [])) != 766:
        raise ValueError('pinned public spec handoff changed')
    originals = [row for row in handoff['seeds']
                 if row['source_kind'] == 'UPSTREAM_PINNED_SPEC_EXAMPLES']
    normal = [row for row in handoff['seeds']
              if row['source_kind'] == 'HARNESS_NORMAL_SEED']
    if len(originals) != 255 or len(normal) != 1:
        raise ValueError('public example source count changed')

    output = Path(tempfile.mkdtemp(prefix='fbv2-md4c-public-repeat-20261102-'))
    corpus = output / 'corpus'
    artifacts = output / 'artifacts'
    corpus.mkdir(mode=0o700)
    artifacts.mkdir(mode=0o700)
    rows = []
    seen = set()
    for row in [*normal, *originals]:
        source = Path(row['stored'])
        if (source.is_symlink() or not source.is_file() or
                sha(source) != row['stored_sha256']):
            raise ValueError('public source Seed changed')
        original = source.read_bytes()
        if len(original) < 9:
            raise ValueError('public spec Seed has no payload')
        variants = [(1, original)]
        if row['source_kind'] == 'UPSTREAM_PINNED_SPEC_EXAMPLES':
            body = original[8:]
            if not body.endswith(b'\n'):
                body += b'\n'
            variants.extend((count, original[:8] + body * count)
                            for count in (2, 4, 8, 16, 32)
                            if len(body) * count + 8 <= 4096)
        for count, content in variants:
            digest = hashlib.sha256(content).hexdigest()
            if digest in EXCLUDED or digest in seen:
                raise ValueError('known Crash, manual PoC, or duplicate Seed')
            seen.add(digest)
            destination = corpus / f"spec_{row['example_number']:04d}_repeat_{count:02d}_{digest[:16]}"
            destination.write_bytes(content)
            rows.append({'example_number': row['example_number'],
                         'source_sha256': row['stored_sha256'],
                         'repeat_count': count, 'stored': str(destination),
                         'stored_sha256': digest, 'size': len(content)})
    if len(rows) != 1530:
        raise ValueError(f'public repeat corpus changed: {len(rows)}')
    write(output / 'preflight.json', {
        'kind': 'MD4C_PUBLIC_SPEC_REPEAT_PROBE_V1',
        'contract_sha256': CONTRACT_SHA,
        'binary_sha256': qualified.binary_sha256,
        'harness_sha256': sha(qualified.harness),
        'source_handoff_sha256': HANDOFF_SHA,
        'source_spec_sha256': SPEC_SHA,
        'corpus_derivation': 'all 255 pinned public spec examples repeated 1,2,4,8,16,32 times when at most 4096 bytes, plus one qualified normal Seed',
        'seeds': rows, 'seed_count': len(rows),
        'excluded_sha256': sorted(EXCLUDED),
        'model_calls': 0, 'discovery_claim': 'NONE',
    })
    command = [str(qualified.binary), str(corpus), '-fork=1',
               '-ignore_crashes=1', '-max_len=4096', '-max_total_time=30',
               '-print_final_stats=1', f'-artifact_prefix={artifacts}/']
    ledger = PersistentProcessLedgerV2.create(
        output / 'process-ledger.json', wall_total_seconds=75,
        fuzz_total_seconds=60)

    def pin(_phase: str, _command: list[str]) -> None:
        if (not _qualification_pins_ok(qualified) or
                sha(contract) != CONTRACT_SHA or
                sha(handoff_path) != HANDOFF_SHA or
                sha(spec_path) != SPEC_SHA or
                any(sha(Path(row['stored'])) != row['stored_sha256'] for row in rows)):
            raise ValueError('qualification or initial corpus pin changed')

    envelope = DevelopmentProcessEnvelopeV2(
        ledger, work_item_id='MD4C_PUBLIC_REPEAT', assertion_id='GLOBAL',
        attempt_id='RUN1', output_limit_bytes=2_097_152,
        total_wall_seconds=65, pin_hook=pin)
    result: dict[str, object] = {'status': 'UNKNOWN', 'output': str(output)}
    try:
        done = _guarded_run(command, cwd=output, timeout=45,
                            process_envelope=envelope,
                            process_kind='GLOBAL_FUZZ',
                            process_segment='public_spec_repeat')
        (output / 'stdout.txt').write_text(done.stdout)
        (output / 'stderr.txt').write_text(done.stderr)
        result.update(status='RETURNED', returncode=done.returncode)
    except BaseException as exc:
        result.update(status='EXCEPTION', exception_type=type(exc).__name__,
                      exception_text=str(exc))
        (output / 'exception.txt').write_text(traceback.format_exc())
    final_hashes = {sha(path) for path in corpus.iterdir()
                    if path.is_file() and not path.is_symlink()}
    artifact_rows = [
        {'path': str(path), 'sha256': sha(path), 'size': path.stat().st_size,
         'initial_seed': sha(path) in seen}
        for path in sorted(artifacts.iterdir())
        if path.is_file() and not path.is_symlink()]
    result.update(initial_seed_count=len(rows),
                  final_corpus_count=len(final_hashes),
                  new_corpus_count=len(final_hashes - seen),
                  artifacts=artifact_rows,
                  ledger=ledger.snapshot())
    write(output / 'result.json', result)
    print(json.dumps({key: value for key, value in result.items()
                      if key != 'ledger'}, sort_keys=True))
    print('ledger', json.dumps({key: result['ledger'][key] for key in
                                ('fuzz_spent_seconds', 'active', 'stop_status')},
                               sort_keys=True))


if __name__ == '__main__':
    main()
