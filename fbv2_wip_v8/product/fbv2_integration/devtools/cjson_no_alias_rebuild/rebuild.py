"""Bounded, offline candidate cJSON build with a physical $SRC/cjson checkout.

This creates development evidence only. It issues no API approval or V2 token.
"""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import time


REFERENCE = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027')
OLD = REFERENCE / 'review/CJSON_V2_DEV_DRAFT_20261030'
ROOT = REFERENCE / 'review/CJSON_V2_NO_ALIAS_REBUILD_20261102'
SOURCE_COMMIT = 'cb8693b058ba302f4829ec6d03f609ac6f848546'
OSS_COMMIT = 'a6d41d14b5293cf2d06e5572813c5995e06c09c3'
IMAGE = 'sha256:1f9cf74bc3d7029b528494542f9d9851b256dceed38d3f420989434dc5ae0760'
SOURCE_FILES = ('cJSON.c', 'cJSON.h', 'fuzzing/cjson_read_fuzzer.c', 'fuzzing/ossfuzz.sh')
SCRIPT = OLD / 'oss_fuzz_checkout/projects/cjson/build.sh'


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return sha256(stream.read()).hexdigest()


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def write_json(path: Path, value: object) -> None:
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def main(role: str) -> None:
    if role not in {'asan', 'coverage'}:
        raise ValueError('unsupported role')
    source_ref = OLD / 'model_target'
    oss_ref = OLD / 'oss_fuzz_checkout'
    if git(source_ref, 'rev-parse', 'HEAD') != SOURCE_COMMIT:
        raise ValueError('source commit changed')
    if git(oss_ref, 'rev-parse', 'HEAD') != OSS_COMMIT:
        raise ValueError('OSS-Fuzz commit changed')
    if git(source_ref, 'status', '--porcelain=v1') or git(oss_ref, 'status', '--porcelain=v1'):
        raise ValueError('pinned source checkout is dirty')
    if digest(SCRIPT) != 'cacff2e7814c94b26a283de5d6f944085c29b6fd4033f99b19bb1ae8770e7192':
        raise ValueError('official project script changed')
    inspected = subprocess.check_output(
        ['docker', 'image', 'inspect', IMAGE, '--format', '{{.Id}}'], text=True).strip()
    if inspected != IMAGE:
        raise ValueError('fixed local build image unavailable')

    root = ROOT / role
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    src = root / 'src'
    src.mkdir(mode=0o700)
    checkout = src / 'cjson'
    subprocess.run(['git', 'clone', '--quiet', '--no-hardlinks',
                    str(source_ref), str(checkout)], check=True, timeout=30)
    subprocess.run(['git', '-C', str(checkout), 'checkout', '--quiet', '--detach',
                    SOURCE_COMMIT], check=True, timeout=10)
    if checkout.is_symlink() or checkout.resolve() != checkout or \
            git(checkout, 'rev-parse', 'HEAD') != SOURCE_COMMIT or \
            git(checkout, 'status', '--porcelain=v1'):
        raise ValueError('physical source checkout is not pinned and clean')
    source_pins = {}
    for relative in SOURCE_FILES:
        path = checkout / relative
        if path.is_symlink() or digest(path) != digest(source_ref / relative):
            raise ValueError('source or Harness differs from pinned model checkout')
        source_pins[relative] = digest(path)
    output = root / 'out'
    output.mkdir(mode=0o700)
    trace = root / 'trace_env.sh'
    trace.write_text('set -x\n')
    flags = ('-O1 -g -fno-omit-frame-pointer -fsanitize=address,fuzzer-no-link '
             '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION')
    if role == 'coverage':
        flags += ' -fprofile-instr-generate -fcoverage-mapping'
    variables = {
        'SRC': str(src), 'OUT': str(output), 'CC': 'clang', 'CXX': 'clang++',
        'CFLAGS': flags,
        'CXXFLAGS': flags + f' -Wl,-Map={output / "final_link.map"}',
        'LIB_FUZZING_ENGINE': '-fsanitize=fuzzer,address',
        'VERBOSE': '1', 'BASH_ENV': str(trace),
    }
    name = f'fbv2-cjson-noalias-{role}-{os.getpid()}'
    argv = ['docker', 'run', '--rm', '--network', 'none',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--pids-limit', '512', '--memory', '4g', '--name', name,
            '--user', f'{os.getuid()}:{os.getgid()}',
            '-v', f'{root}:{root}', '-v', f'{OLD}:{OLD}:ro',
            '-w', str(checkout)]
    for key, value in variables.items():
        argv += ['-e', f'{key}={value}']
    argv += [IMAGE, 'bash', '-x', str(SCRIPT)]
    identity_before = [checkout.stat().st_dev, checkout.stat().st_ino]
    write_json(root / 'preflight.json', {
        'kind': 'CJSON_NO_ALIAS_OFFLINE_BUILD_CANDIDATE_V1',
        'role': role, 'source_commit': SOURCE_COMMIT,
        'oss_fuzz_commit': OSS_COMMIT, 'image_id': IMAGE,
        'source_root': str(checkout), 'source_root_is_symlink': False,
        'source_root_dev_ino': identity_before,
        'source_sha256': source_pins, 'official_script_sha256': digest(SCRIPT),
        'argv': argv, 'network_mode': 'none', 'wall_limit_seconds': 180,
        'build_execution_limit_seconds': 150,
        'build_script_sha256': digest(Path(__file__)),
        'log_limit_bytes': 8_388_608, 'authority_claim': 'CANDIDATE_ONLY',
    })
    log = root / 'build.log'
    started = time.monotonic()
    reason = None
    with log.open('xb') as stream:
        process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL)
        try:
            while process.poll() is None:
                # Reserve 30 seconds for forced container removal, CLI reap,
                # and an independently checked container absence result.
                if time.monotonic() - started > 150:
                    reason = 'WALL_LIMIT'
                    break
                if log.stat().st_size > 8_388_608:
                    reason = 'LOG_LIMIT'
                    break
                time.sleep(0.2)
        finally:
            if process.poll() is None:
                subprocess.run(['docker', 'rm', '-f', name],
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=10)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            stream.flush()
            os.fsync(stream.fileno())
    elapsed = time.monotonic() - started
    inspection = subprocess.run(
        ['docker', 'inspect', '--type', 'container',
         '--format', '{{.State.Status}}', name],
        capture_output=True, text=True, timeout=5)
    container_absent = (inspection.returncode != 0 and
                        ('No such object' in inspection.stderr or
                         'No such container' in inspection.stderr))
    container_state_unproven = inspection.returncode != 0 and not container_absent
    present = inspection.returncode == 0
    binary = output / 'cjson_read_fuzzer'
    source_after = {relative: digest(checkout / relative) for relative in SOURCE_FILES}
    identity_after = [checkout.stat().st_dev, checkout.stat().st_ino]
    result = {
        'kind': 'CJSON_NO_ALIAS_OFFLINE_BUILD_RESULT_V1',
        'role': role, 'status': ('CANDIDATE_BUILT' if reason is None and
                             process.returncode == 0 and binary.is_file() and
                             container_absent and not container_state_unproven and
                             elapsed <= 180 and identity_after == identity_before and
                             source_after == source_pins else 'INCOMPLETE'),
        'reason': reason, 'returncode': process.returncode,
        'wall_seconds': elapsed, 'container_left_running': present,
        'container_state_unproven': container_state_unproven,
        'container_absence_proven': container_absent,
        'source_root_dev_ino_after': identity_after,
        'source_sha256_after': source_after,
        'log_sha256': digest(log), 'log_bytes': log.stat().st_size,
        'binary_sha256': digest(binary) if binary.is_file() else None,
        'link_map_sha256': digest(output / 'final_link.map')
                           if (output / 'final_link.map').is_file() else None,
        'authority_claim': 'CANDIDATE_ONLY',
    }
    write_json(root / 'result.json', result)
    print(json.dumps({'role': role, 'status': result['status'],
                      'returncode': result['returncode'],
                      'wall_seconds': round(elapsed, 3),
                      'binary_sha256': result['binary_sha256'],
                      'container_left_running': present}, sort_keys=True))
    if result['status'] != 'CANDIDATE_BUILT':
        raise RuntimeError(f'{role} candidate build incomplete: {reason or process.returncode}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('role', choices=('asan', 'coverage'))
    main(parser.parse_args().role)
