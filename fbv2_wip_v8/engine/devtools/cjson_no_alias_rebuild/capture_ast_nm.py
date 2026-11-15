"""Offline AST/NM recapture for the no-alias cJSON candidate binaries."""

from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import shlex
import subprocess
import time


ROOT = Path('/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027/review/CJSON_V2_NO_ALIAS_REBUILD_20261102')
IMAGE = 'sha256:1f9cf74bc3d7029b528494542f9d9851b256dceed38d3f420989434dc5ae0760'
MAX_OUTPUT_BYTES = 40_000_000
MAX_COMMAND_SECONDS = 30
_ordinal = 0


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def capture(label: str, command: list[str], *, cwd: Path) -> dict:
    global _ordinal
    _ordinal += 1
    out, err = ROOT / f'{label}.stdout', ROOT / f'{label}.stderr'
    name = f'fbv2-cjson-capture-{os.getpid()}-{_ordinal}'
    docker = ['docker', 'run', '--rm', '--network', 'none', '--read-only',
              '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
              '--pids-limit', '64', '--memory', '1g',
              '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m',
              '--name', name, '--user', f'{os.getuid()}:{os.getgid()}',
              '-v', f'{ROOT}:{ROOT}:ro', '-w', str(cwd), IMAGE, *command]
    started = time.monotonic()
    stop_reason = None
    with out.open('xb') as stdout, err.open('xb') as stderr:
        proc = subprocess.Popen(docker, stdin=subprocess.DEVNULL,
                                stdout=stdout, stderr=stderr)
        while proc.poll() is None:
            if time.monotonic() - started > MAX_COMMAND_SECONDS:
                stop_reason = 'WALL_LIMIT'
                break
            if out.stat().st_size + err.stat().st_size > MAX_OUTPUT_BYTES:
                stop_reason = 'OUTPUT_LIMIT'
                break
            time.sleep(0.1)
        if proc.poll() is None:
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True,
                           timeout=5)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        stdout.flush(); stderr.flush()
        os.fsync(stdout.fileno()); os.fsync(stderr.fileno())
    inspection = subprocess.run(
        ['docker', 'inspect', '--type', 'container', '--format',
         '{{.State.Status}}', name], capture_output=True, text=True, timeout=5)
    absent = (inspection.returncode != 0 and
              ('No such container' in inspection.stderr or
               'No such object' in inspection.stderr))
    result = {'label': label, 'argv': docker, 'command': command,
              'exit_code': proc.returncode, 'stop_reason': stop_reason,
              'wall_seconds': time.monotonic() - started,
              'container_absence_proven': absent,
              'stdout_path': str(out), 'stdout_sha256': digest(out),
              'stdout_size': out.stat().st_size,
              'stderr_path': str(err), 'stderr_sha256': digest(err),
              'stderr_size': err.stat().st_size}
    if proc.returncode != 0 or stop_reason or not absent:
        raise RuntimeError(f'{label} capture incomplete: {result}')
    return result


def ast_command(compile_argv: list[str]) -> list[str]:
    result = []
    skip = False
    for part in compile_argv:
        if skip:
            skip = False
        elif part in {'-o', '-MF', '-MT'}:
            skip = True
        elif part not in {'-c', '-MD'}:
            result.append(part)
    if skip or not result[-1].endswith('/cJSON.c'):
        raise ValueError('unexpected compile command')
    return [*result, '-fsyntax-only', '-Xclang', '-ast-dump=json']


def main() -> None:
    if (ROOT / 'ast-nm-capture.json').exists():
        raise FileExistsError('candidate AST/NM capture already exists')
    rows = {}
    for role in ('asan', 'coverage'):
        role_root = ROOT / role
        receipt_path = role_root / 'build-receipt-candidate.json'
        receipt = json.loads(receipt_path.read_text())
        source = role_root / 'src/cjson/cJSON.c'
        binary = role_root / 'out/cjson_read_fuzzer'
        obj = role_root / 'src/cjson/build/CMakeFiles/cjson.dir/cJSON.c.o'
        if (receipt['status'] != 'CANDIDATE_UNAPPROVED' or
                digest(binary) != receipt['binary_sha256'] or
                digest(source) != receipt['build_steps'][0]['inputs'][0]['sha256'] or
                digest(obj) != receipt['build_steps'][0]['outputs'][0]['sha256']):
            raise ValueError(f'{role} build receipt changed')
        captures = {}
        captures['source_ast'] = capture(
            f'{role}-source-ast', ast_command(receipt['build_steps'][0]['argv']),
            cwd=role_root / 'src/cjson/build')
        for kind, path in (('binary', binary), ('object', obj)):
            for mode in ('defined-only', 'undefined-only'):
                captures[f'{kind}_{mode}'] = capture(
                    f'{role}-{kind}-{mode}', ['llvm-nm', f'--{mode}', str(path)],
                    cwd=role_root)
        rows[role] = {'binary_sha256': digest(binary),
                      'build_receipt_sha256': digest(receipt_path),
                      'source_sha256': digest(source), 'captures': captures}
    asan = ROOT / 'asan/src/cjson'
    harness = asan / 'fuzzing/cjson_read_fuzzer.c'
    harness_command = ['clang++', '-O1', '-g', '-fno-omit-frame-pointer',
                       '-fsanitize=address,fuzzer-no-link',
                       '-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION',
                       str(harness), '-I.', '-fsyntax-only', '-Xclang',
                       '-ast-dump=json']
    harness_row = capture('harness-ast', harness_command, cwd=asan / 'build')
    report = {'kind': 'CJSON_NO_ALIAS_AST_NM_CANDIDATE_V1',
              'status': 'CANDIDATE_UNAPPROVED', 'image': IMAGE,
              'roles': rows, 'harness_sha256': digest(harness),
              'harness_ast': harness_row}
    path = ROOT / 'ast-nm-capture.json'
    with path.open('x') as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write('\n')
    print(json.dumps({'status': report['status'],
                      'asan_ast_bytes': rows['asan']['captures']['source_ast']['stdout_size'],
                      'coverage_ast_bytes': rows['coverage']['captures']['source_ast']['stdout_size'],
                      'harness_ast_bytes': harness_row['stdout_size'],
                      'receipt_sha256': digest(path)}, sort_keys=True))


if __name__ == '__main__':
    main()
