"""Bounded local diagnosis of function reach in a prior md4c corpus.

This consumes only an already completed public Fuzzing-only corpus. It is not
an official V2 finding, a new discovery campaign, or a model call.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import argparse


REFERENCE = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027')
PRODUCT = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src')
sys.path.insert(0, str(REFERENCE / 'evaluation_tools'))
sys.path.insert(0, str(PRODUCT))

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from vulnerabilityanalysis.official_harness import _v2_receipt_build_chain, hash_source_tree_v2
from vulnerabilityanalysis.runtime import _guarded_run


SOURCE_RUN = Path('/tmp/fbv2-md4c-spec-examples-20261102-run')
MANIFEST = Path('/home/dawne/work/SunrinInfosecProject2026/fbv2_hp_integration/documentation/md4c_spec_examples_exploration_20261102/run-manifest.json')
OUTPUT = Path('/tmp/md4c-coverage-reach-probe-20261102')
LLVM_IMAGE = 'gcr.io/oss-fuzz-base/base-builder@sha256:1f9cf74bc3d7029b528494542f9d9851b256dceed38d3f420989434dc5ae0760'


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(*, resume_report: bool = False, source_run: Path = SOURCE_RUN,
         manifest_path: Path = MANIFEST, output: Path = OUTPUT,
         expected_inputs: int = 5880,
         expected_manifest_sha256: str | None = None) -> None:
    if (not source_run.is_absolute() or not manifest_path.is_absolute() or
            not output.is_absolute() or source_run.resolve() != source_run or
            manifest_path.resolve() != manifest_path or
            output.resolve() != output or expected_inputs < 1 or
            (expected_manifest_sha256 is not None and
             sha(manifest_path) != expected_manifest_sha256)):
        raise ValueError('coverage probe paths or manifest pin are invalid')
    if output.exists() and not resume_report:
        raise RuntimeError('coverage probe output already exists')
    if resume_report and not output.is_dir():
        raise RuntimeError('coverage probe output is missing')
    receipt_path = REFERENCE / 'coverage_v2_build_receipt.json'
    receipt = json.loads(receipt_path.read_text())
    binary = Path(receipt['binary'])
    contract = json.loads((REFERENCE / 'public/OFFICIAL_HARNESS_CONTRACT.json').read_text())
    source_root = REFERENCE / 'model_target'
    if (not binary.is_file() or sha(binary) != receipt['binary_sha256'] or
            hash_source_tree_v2(source_root) != contract['target']['source_tree_sha256'] or
            not _v2_receipt_build_chain(
                receipt,
                harness_path=REFERENCE / 'upstream_coverage_final/test/fuzzers/fuzz-mdhtml.c',
                harness_relative=receipt['upstream_harness_path'],
                harness_sha256=receipt['upstream_harness_sha256'],
                target_root=source_root, binary_path=binary,
                binary_sha256=receipt['binary_sha256'])):
        raise RuntimeError('coverage build or source identity is not pinned')
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('kind') not in {
            'MD4C_SPEC_EXAMPLES_EXPLORATION_MANIFEST_V1',
            'MD4C_SPEC_CONTINUATION_EVIDENCE_MANIFEST_V1',
            'MD4C_SPEC_COMPOSITES_EVIDENCE_MANIFEST_V1'}:
        raise RuntimeError('prior corpus manifest changed')
    prefix = 'global_campaign/corpus/global/'
    rows = [row for row in manifest['files'] if row['path'].startswith(prefix)]
    originals = source_run / 'global_campaign/corpus/global'
    if len(rows) != expected_inputs or set(p.name for p in originals.iterdir()) != {
            Path(row['path']).name for row in rows}:
        raise RuntimeError('prior corpus file set changed')
    for row in rows:
        path = source_run / row['path']
        if (path.is_symlink() or not path.is_file() or
                path.stat().st_size != row['size'] or sha(path) != row['sha256']):
            raise RuntimeError('prior corpus bytes changed')
    if not resume_report:
        output.mkdir(mode=0o700)
    corpus = output / 'corpus'
    if not resume_report:
        corpus.mkdir()
        for row in rows:
            shutil.copyfile(source_run / row['path'], corpus / Path(row['path']).name)
        (output / 'selected').mkdir()
        (output / 'profiles').mkdir()
        ledger = PersistentProcessLedgerV2.create(
            output / 'process-ledger.json', wall_total_seconds=90,
            fuzz_total_seconds=0)
    else:
        if not (output / 'merge.stderr.txt').is_file() or not (output / 'selected').is_dir():
            raise RuntimeError('successful initial merge evidence is missing')
        ledger = PersistentProcessLedgerV2.restore(
            output / 'process-ledger.json', wall_total_seconds=90,
            fuzz_total_seconds=0)
    expected = {binary: sha(binary), receipt_path: sha(receipt_path),
                manifest_path: sha(manifest_path)}

    def pin_hook(_phase: str, _command: list[str]) -> None:
        if any(not path.is_file() or sha(path) != digest
               for path, digest in expected.items()):
            raise RuntimeError('coverage probe pin changed')

    envelope = DevelopmentProcessEnvelopeV2(
        ledger, work_item_id='MD4C_COVERAGE_PROBE', assertion_id='REACH',
        attempt_id='spec20261102export' if resume_report else 'spec20261102',
        output_limit_bytes=2_000_000,
        total_wall_seconds=90, pin_hook=pin_hook)
    if not resume_report:
        env = dict(os.environ)
        env['LLVM_PROFILE_FILE'] = str(output / 'profiles/probe-%p.profraw')
        merge = _guarded_run(
            [str(binary), '-merge=1', '-verbosity=0', '-max_total_time=10',
             str(output / 'selected'), str(corpus)], cwd=output, env=env,
            timeout=25, process_envelope=envelope,
            process_segment='coverage_corpus_merge')
        (output / 'merge.stdout.txt').write_text(merge.stdout)
        (output / 'merge.stderr.txt').write_text(merge.stderr)
        if merge.returncode != 0:
            raise RuntimeError('coverage merge did not complete')
    profiles = sorted((output / 'profiles').glob('*.profraw'))
    if not profiles:
        raise RuntimeError('coverage binary emitted no profile')
    docker = shutil.which('docker')
    if docker is None:
        raise RuntimeError('local Docker is unavailable for the pinned LLVM image')
    mounts = [docker, 'run', '--rm', '--network=none', '--read-only',
              '--cap-drop=ALL', '--pids-limit=64', '--memory=512m', '--cpus=2',
              '--user', f'{os.getuid()}:{os.getgid()}',
              '--mount', f'type=bind,src={output},dst=/probe',
              '--mount', f'type=bind,src={binary},dst=/binary,readonly',
              '--entrypoint', '/bin/sh', LLVM_IMAGE, '-c']
    profile = output / 'merged.profdata'
    if not resume_report:
        combined = _guarded_run(
            [*mounts, 'llvm-profdata merge -sparse /probe/profiles/*.profraw '
             '-o /probe/merged.profdata'],
            cwd=output, timeout=15, process_envelope=envelope,
            process_segment='profile_merge')
        (output / 'profile_merge.stdout.txt').write_text(combined.stdout)
        (output / 'profile_merge.stderr.txt').write_text(combined.stderr)
        if combined.returncode != 0 or not profile.is_file():
            raise RuntimeError('profile merge failed')
    elif profile.is_symlink() or not profile.is_file() or profile.stat().st_size == 0:
        raise RuntimeError('merged profile is missing or invalid')
    export = output / 'coverage.export.json'
    report = _guarded_run(
        [*mounts, 'llvm-cov export /binary -instr-profile=/probe/merged.profdata '
         "'-name-regex=md_collect_marks|md_consume_link_reference_definitions' "
         '> /probe/coverage.export.json'],
        cwd=output, timeout=15, process_envelope=envelope,
        process_segment='function_coverage_report')
    (output / 'coverage.stderr.txt').write_text(report.stderr)
    if report.returncode != 0 or export.is_symlink() or not export.is_file():
        raise RuntimeError('function coverage report failed')
    exported = json.loads(export.read_text())
    target_names = {'md4c.c:md_collect_marks',
                    'md4c.c:md_consume_link_reference_definitions'}
    functions = [fn for unit in exported.get('data', [])
                 for fn in unit.get('functions', [])
                 if fn.get('name') in target_names]
    summary = [
        {'name': fn['name'], 'count': fn.get('count'),
         'regions_executed': sum(region[4] > 0 for region in fn.get('regions', [])),
         'regions_total': len(fn.get('regions', [])),
         'filenames': sorted(set(fn.get('filenames', [])))}
        for fn in functions]
    if {fn['name'] for fn in summary} != target_names:
        raise RuntimeError('target functions are absent from coverage export')
    focus_lines = {3266, 5741, 5744, 5868, 5871, 5873, 5880}
    critical_segments = [
        {'line': segment[0], 'column': segment[1],
         'count': segment[2], 'has_count': segment[3],
         'is_region_entry': segment[4]}
        for unit in exported.get('data', []) for file in unit.get('files', [])
        if file.get('filename', '').endswith('/src/md4c.c')
        for segment in file.get('segments', [])
        if segment[0] in focus_lines]
    (output / 'coverage.report.json').write_text(
        json.dumps({'functions': summary, 'critical_segments': critical_segments},
                   sort_keys=True, indent=2) + '\n')
    state, state_sha = ledger.receipt_snapshot()
    result = {
        'kind': 'MD4C_LOCAL_COVERAGE_REACH_PROBE_V1',
        'source_run': str(source_run),
        'source_manifest_sha256': sha(manifest_path),
        'coverage_binary': str(binary), 'coverage_binary_sha256': sha(binary),
        'coverage_build_receipt_sha256': sha(receipt_path),
        'input_count': len(rows), 'profile_count': len(profiles),
        'merge_exit_code': 0, 'report_exit_code': report.returncode,
        'llvm_image': LLVM_IMAGE,
        'report_sha256': sha(output / 'coverage.report.json'),
        'functions': summary,
        'critical_segments': critical_segments,
        'process_ledger_sha256': state_sha,
        'process_finished': len(state['finished']),
        'process_active': len(state['active']),
        'process_stop': state['stop_status'],
        'physical_wall_seconds': state['wall_spent_seconds'],
        'automatic_discovery_credit': False,
    }
    (output / 'result.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in
                      ('input_count', 'profile_count', 'process_finished',
                       'process_active', 'physical_wall_seconds',
                       'automatic_discovery_credit')}, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--resume-report', action='store_true')
    parser.add_argument('--source-run', type=Path, default=SOURCE_RUN)
    parser.add_argument('--manifest', type=Path, default=MANIFEST)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    parser.add_argument('--expected-inputs', type=int, default=5880)
    parser.add_argument('--expected-manifest-sha256')
    args = parser.parse_args()
    main(resume_report=args.resume_report, source_run=args.source_run,
         manifest_path=args.manifest, output=args.output,
         expected_inputs=args.expected_inputs,
         expected_manifest_sha256=args.expected_manifest_sha256)
