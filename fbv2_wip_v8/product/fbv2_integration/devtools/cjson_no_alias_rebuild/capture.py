"""Capture no-alias offline cJSON build as an unapproved candidate receipt."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys


REFERENCE = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027')
OLD = REFERENCE / 'review/CJSON_V2_DEV_DRAFT_20261030'
ROOT = REFERENCE / 'review/CJSON_V2_NO_ALIAS_REBUILD_20261102'
PRODUCT_SRC = Path('/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src')
sys.path.insert(0, str(PRODUCT_SRC))
from vulnerabilityanalysis.official_harness import _v2_receipt_build_chain


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def pin(path: Path) -> dict[str, str]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'ordinary build artifact required: {path}')
    return {'path': str(path.resolve()), 'sha256': digest(path)}


def observed(lines: list[str], pattern: str) -> list[str]:
    matches = [line for line in lines if re.search(pattern, line)]
    if len(matches) != 1:
        raise ValueError(f'exactly one observed command required: {pattern}: {len(matches)}')
    line = matches[0]
    return shlex.split(line[2:] if line.startswith('+ ') else line)


def main(role: str) -> None:
    root = ROOT / role
    checkout = root / 'src/cjson'
    build = checkout / 'build'
    output = root / 'out'
    source, header = checkout / 'cJSON.c', checkout / 'cJSON.h'
    harness = checkout / 'fuzzing/cjson_read_fuzzer.c'
    upstream_script = checkout / 'fuzzing/ossfuzz.sh'
    obj = build / 'CMakeFiles/cjson.dir/cJSON.c.o'
    archive = build / 'libcjson.a'
    binary, linkmap = output / 'cjson_read_fuzzer', output / 'final_link.map'
    log = root / 'build.log'
    preflight = json.loads((root / 'preflight.json').read_text())
    result = json.loads((root / 'result.json').read_text())
    preservation = json.loads((root / 'preservation.json').read_text())
    if (result.get('status') != 'CANDIDATE_BUILT' or
            preflight.get('source_root_is_symlink') is not False or
            checkout.is_symlink() or checkout.resolve() != checkout or
            preflight.get('source_root_dev_ino') != result.get('source_root_dev_ino_after') or
            preflight.get('source_sha256') != result.get('source_sha256_after') or
            digest(log) != result.get('log_sha256') or
            digest(binary) != result.get('binary_sha256') or
            preservation.get('key_artifact_sha256', {}).get('object') != digest(obj) or
            preservation.get('key_artifact_sha256', {}).get('archive') != digest(archive) or
            subprocess.check_output(['git', '-C', str(checkout), 'status',
                                     '--porcelain=v1'], text=True).strip()):
        raise ValueError('new physical build evidence is incomplete or changed')
    lines = log.read_text().splitlines()
    first_link = next(index for index, line in enumerate(lines)
                      if line.startswith('+ clang++ '))
    if '+ ' + str(upstream_script) not in lines:
        raise ValueError('official project script did not invoke upstream script')
    cc = observed(lines[:first_link],
                  r'^/usr/local/bin/clang .*CMakeFiles/cjson\.dir/cJSON\.c\.o -c ' +
                  re.escape(str(source)) + r'$')
    ar = observed(lines[:first_link],
                  r'^/usr/local/bin/cmake -E cmake_link_script .*CMakeFiles/cjson\.dir/link\.txt')
    ld = observed(lines, r'^\+ clang\+\+ .*' + re.escape(str(harness)) +
                  r'.*-o ' + re.escape(str(binary)) + r' ')
    if (cc[cc.index('-c') + 1] != str(source) or
            ar[1:3] != ['-E', 'cmake_link_script'] or
            ld[ld.index('-o') + 1] != str(binary) or
            str(archive) not in ld or f'-Wl,-Map={linkmap}' not in ld):
        raise ValueError('observed compiler/linker command differs from physical paths')
    receipt = {
        'kind': 'OFFICIAL_OSS_FUZZ_UPSTREAM_BUILD_RECEIPT_V2',
        'status': 'CANDIDATE_UNAPPROVED',
        'oss_fuzz_revision': preflight['oss_fuzz_commit'],
        'upstream_revision': preflight['source_commit'],
        'target_revision': preflight['source_commit'],
        'build_script_path': 'projects/cjson/build.sh',
        'build_script_sha256': preflight['official_script_sha256'],
        'upstream_harness_path': 'fuzzing/cjson_read_fuzzer.c',
        'upstream_harness_sha256': digest(harness),
        'binary': str(binary), 'binary_sha256': digest(binary),
        'chained_scripts': [{'repository': 'upstream',
                             'path': 'fuzzing/ossfuzz.sh',
                             'sha256': digest(upstream_script)}],
        'compiled_sources': [pin(path) for path in (harness, source, header)],
        'build_steps': [
            {'argv': cc, 'cwd': str(build), 'exit_code': 0,
             'inputs': [pin(source), pin(header)], 'outputs': [pin(obj)]},
            {'argv': ar, 'cwd': str(build), 'exit_code': 0,
             'inputs': [pin(obj)], 'outputs': [pin(archive)],
             'link_script': pin(build / 'CMakeFiles/cjson.dir/link.txt')},
            {'argv': ld, 'cwd': str(build), 'exit_code': 0,
             'inputs': [pin(harness), pin(header), pin(archive)],
             'outputs': [pin(binary), pin(linkmap)]},
        ],
        'source_checkout_identity': {
            'path': str(checkout), 'physical_directory': True,
            'dev_ino_before': preflight['source_root_dev_ino'],
            'dev_ino_after': result['source_root_dev_ino_after'],
            'source_sha256_before': preflight['source_sha256'],
            'source_sha256_after': result['source_sha256_after']},
        'build_preflight': pin(root / 'preflight.json'),
        'build_result': pin(root / 'result.json'),
        'preservation': pin(root / 'preservation.json'),
        'verbatim_build_log': pin(log),
        'final_linker_map': pin(linkmap),
        'scope': ('Candidate consistency and no-symlink source root only; '
                  'Dockerfile equivalence and API approval remain external.'),
    }
    valid = _v2_receipt_build_chain(
        receipt, harness_path=harness, harness_relative='fuzzing/cjson_read_fuzzer.c',
        harness_sha256=digest(harness), target_root=OLD / 'model_target',
        binary_path=binary, binary_sha256=digest(binary))
    if not valid:
        raise ValueError('candidate build chain rejected by product consistency validator')
    path = root / 'build-receipt-candidate.json'
    with path.open('x', encoding='utf-8') as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({'role': role, 'status': 'CANDIDATE_CONSISTENT',
                      'receipt_sha256': digest(path),
                      'binary_sha256': digest(binary),
                      'official_qualification': 'HOLD'}, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=('asan', 'coverage'))
    main(parser.parse_args().role)
