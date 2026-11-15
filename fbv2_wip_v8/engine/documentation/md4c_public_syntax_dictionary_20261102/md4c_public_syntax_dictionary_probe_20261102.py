"""Bounded, model-free md4c fork probe with a public-spec syntax dictionary.

Development observation only. It does not grant automatic discovery credit or
change the qualified product Global campaign. Existing public Seed bytes are
the sole dictionary source; no known Crash or PoC is staged.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import traceback


BASE = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027')
EVAL = BASE / 'evaluation_tools'
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src')
sys.path[:0] = [str(EVAL), str(PRODUCT)]

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from vulnerabilityanalysis.official_harness import (
    issue_official_pinned_qualification, _qualification_pins_ok)
from vulnerabilityanalysis.runtime import _guarded_run


SECONDS = 30
CONTRACT_SHA = 'a1c6217b2daf73ccc97d3efd92b3125690b1316246208ae8fce72e2a29ef9b10'
OLD_CRASH_SHA = '9de288250d625a75471a2da8f876d22472f871190eec592664fcd201130d5613'
MANUAL_UAF_SHA = '92bec7016603ecbe922a2f365f83fbddb4dacf874a47c8758e6440fed681cf63'


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path: Path, value: object) -> None:
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')


def dictionary(source_files: list[Path], destination: Path) -> list[str]:
    counts: Counter[bytes] = Counter()
    for source in source_files:
        payload = source.read_bytes()[8:]
        for match in re.finditer(rb'[!-/:-@\[-`{-~]{2,12}', payload):
            counts[match.group()] += 1
        for line in payload.splitlines():
            match = re.match(rb'^[ \t]{0,3}([^\w\r\n]{2,10})', line)
            if match and match.group(1).strip():
                counts[match.group(1)] += 1
    selected = sorted((part for part, count in counts.items()
                       if count >= 2 and len(part) <= 12),
                      key=lambda part: (-counts[part], part))[:64]
    if len(selected) < 16:
        raise ValueError('public syntax dictionary unexpectedly small')
    destination.write_text(''.join(json.dumps(part.decode('ascii')) + '\n'
                                   for part in selected), encoding='ascii')
    return [part.decode('ascii') for part in selected]


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
    handoff = json.loads(handoff_path.read_text())
    if handoff['seed_count'] != 766 or len(handoff['seeds']) != 766:
        raise ValueError('public Seed handoff changed')
    output = Path(tempfile.mkdtemp(prefix='fbv2-md4c-public-dict-20261102-'))
    corpus = output / 'corpus'
    artifacts = output / 'artifacts'
    corpus.mkdir(mode=0o700)
    artifacts.mkdir(mode=0o700)
    source_files: list[Path] = []
    seed_hashes: set[str] = set()
    for row in handoff['seeds']:
        source = Path(row['stored'])
        if source.is_symlink() or not source.is_file() or sha(source) != row['stored_sha256']:
            raise ValueError('public Seed source changed')
        seed_hashes.add(row['stored_sha256'])
        source_files.append(source)
        shutil.copyfile(source, corpus / source.name)
    if (len(seed_hashes) != 766 or
            {OLD_CRASH_SHA, MANUAL_UAF_SHA} & seed_hashes):
        raise ValueError('known Crash or manual PoC is in the initial corpus')
    dict_path = output / 'public-syntax.dict'
    tokens = dictionary(source_files, dict_path)
    command = [str(qualified.binary), str(corpus), '-fork=1',
               '-ignore_crashes=1', '-max_len=512',
               f'-max_total_time={SECONDS}', '-print_final_stats=1',
               f'-artifact_prefix={artifacts}/', f'-dict={dict_path}']
    write(output / 'preflight.json', {
        'kind': 'MD4C_PUBLIC_SYNTAX_DICTIONARY_PROBE_V1',
        'contract_sha256': CONTRACT_SHA,
        'binary_sha256': qualified.binary_sha256,
        'harness_sha256': sha(qualified.harness),
        'seed_handoff_sha256': sha(handoff_path),
        'seed_count': len(seed_hashes), 'seed_sha256': sorted(seed_hashes),
        'excluded_known_sha256': [OLD_CRASH_SHA, MANUAL_UAF_SHA],
        'dictionary_sha256': sha(dict_path), 'dictionary_tokens': tokens,
        'dictionary_derivation': 'top 64 repeated ASCII punctuation runs and line prefixes from the 766 pinned public Seed payloads, no Crash or PoC source',
        'seconds': SECONDS, 'command': command,
        'model_calls': 0, 'discovery_claim': 'NONE',
    })
    ledger = PersistentProcessLedgerV2.create(
        output / 'process-ledger.json', wall_total_seconds=75,
        fuzz_total_seconds=60)

    def pin(_phase: str, _command: list[str]) -> None:
        if not _qualification_pins_ok(qualified) or sha(contract) != CONTRACT_SHA or \
                sha(dict_path) != json.loads((output / 'preflight.json').read_text())['dictionary_sha256']:
            raise ValueError('source, contract, binary, or dictionary pin changed')

    envelope = DevelopmentProcessEnvelopeV2(
        ledger, work_item_id='MD4C_PUBLIC_SYNTAX_DICT', assertion_id='GLOBAL',
        attempt_id='RUN1', output_limit_bytes=2_097_152,
        total_wall_seconds=55, pin_hook=pin)
    result: dict[str, object] = {'status': 'UNKNOWN', 'output': str(output)}
    try:
        done = _guarded_run(command, cwd=output, timeout=45,
                            process_envelope=envelope,
                            process_kind='GLOBAL_FUZZ',
                            process_segment='public_syntax_dictionary')
        (output / 'stdout.txt').write_text(done.stdout)
        (output / 'stderr.txt').write_text(done.stderr)
        result.update(status='RETURNED', returncode=done.returncode)
    except BaseException as exc:
        result.update(status='EXCEPTION', exception_type=type(exc).__name__,
                      exception_text=str(exc))
        (output / 'exception.txt').write_text(traceback.format_exc())
    final_hashes = {sha(path) for path in corpus.iterdir()
                    if path.is_file() and not path.is_symlink()}
    result['new_corpus_hashes'] = sorted(final_hashes - seed_hashes)
    result['final_corpus_count'] = len(final_hashes)
    result['artifacts'] = [
        {'name': path.name, 'sha256': sha(path), 'size': path.stat().st_size}
        for path in sorted(artifacts.iterdir())
        if path.is_file() and not path.is_symlink()]
    result['dictionary_sha256'] = sha(dict_path)
    result['ledger'] = ledger.snapshot()
    write(output / 'result.json', result)
    print(json.dumps({key: value for key, value in result.items()
                      if key not in {'ledger', 'new_corpus_hashes'}}, sort_keys=True))
    print('ledger', json.dumps({key: result['ledger'][key] for key in
                                ('fuzz_spent_seconds', 'active', 'stop_status')},
                               sort_keys=True))


if __name__ == '__main__':
    main()
