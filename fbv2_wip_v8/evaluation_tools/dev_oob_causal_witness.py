"""Narrow, evaluation-only OOB causal witness for two public C toy shapes.

This does not issue a product root-cause result or call the VERIFIED Gate.
Arbitrary C expressions are intentionally rejected.  The original ASan binary
is observed twice: once directly and once under GDB at the source access.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from vulnerabilityanalysis.runtime import (
    RuntimeCleanupError, RuntimeExecutor, _guarded_run,
    triage_crash,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class OOBPins:
    source_sha256: str
    binary_sha256: str
    crash_input_sha256: str
    normal_input_sha256: str
    compiled_source_sha256: str


def pin_development_inputs(source: Path, binary: Path,
                           crash_input: Path, normal_input: Path,
                           *, compiled_source_sha256: str) -> OOBPins:
    for path in (source, binary, crash_input, normal_input):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"regular pinned file required: {path}")
    if not re.fullmatch(r"[0-9a-f]{64}", compiled_source_sha256):
        raise ValueError("frozen build-time source SHA-256 is required")
    return OOBPins(*(_sha256(path) for path in
                     (source, binary, crash_input, normal_input)),
                   compiled_source_sha256)


@dataclass(frozen=True)
class OOBWitnessSpec:
    object_kind: str
    claimed_capacity: int | None = None


@dataclass(frozen=True)
class ApprovedDebugger:
    """Externally fixed dev contract; never derive these values in the issuer."""

    invocation_path: str
    invocation_sha256: str
    resolved_path: str
    backend_path: str
    backend_sha256: str


@dataclass(frozen=True)
class OOBWitnessResult:
    status: str
    reason: str
    evidence: dict[str, object] = field(default_factory=dict)
    gate_eligible: bool = False


def _blocked(status: str, reason: str) -> OOBWitnessResult:
    return OOBWitnessResult(status, reason)


def _approved_debugger_matches(debugger: Path, approved: ApprovedDebugger) -> bool:
    try:
        backend = Path(approved.backend_path)
        if (not debugger.is_absolute() or not backend.is_absolute() or
                debugger.name != "gdb" or not debugger.is_file() or
                not backend.is_file() or backend.is_symlink() or
                str(debugger) != approved.invocation_path or
                str(debugger.resolve()) != approved.resolved_path or
                str(backend.resolve()) != approved.backend_path or
                not re.fullmatch(r"[0-9a-f]{64}", approved.invocation_sha256) or
                not re.fullmatch(r"[0-9a-f]{64}", approved.backend_sha256)):
            return False
        return (_sha256(debugger) == approved.invocation_sha256 and
                _sha256(backend) == approved.backend_sha256)
    except OSError:
        return False


def _private_write_once(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _private_json_once(path: Path, data: object) -> None:
    _private_write_once(path, (json.dumps(data, sort_keys=True, indent=2) + "\n").encode())


def _artifact_index(root: Path, names: tuple[str, ...]) -> dict[str, dict[str, object]]:
    index: dict[str, dict[str, object]] = {}
    for name in names:
        path = root / name
        if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
            raise ValueError(f"private artifact is missing or has wrong mode: {name}")
        index[name] = {"path": str(path), "sha256": _sha256(path),
                       "size": path.stat().st_size}
    return index


def _new_private_artifact_dir(root: Path) -> Path:
    if root.is_symlink():
        raise ValueError("artifact root may not be a symlink")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not root.is_dir() or root.stat().st_mode & 0o077:
        raise ValueError("artifact root must be owner-private")
    child = Path(tempfile.mkdtemp(prefix="oob-witness-", dir=root))
    if child.stat().st_mode & 0o077:
        raise ValueError("witness directory must be owner-private")
    return child


def _canonical_public_source(kind: str, capacity: int, marker: str) -> str:
    if kind == "heap":
        object_lines = (
            f"    size_t capacity = {capacity};\n"
            "    unsigned char *buffer = (unsigned char *)malloc(capacity);\n"
            "    if (buffer == NULL) return 2;\n"
            "    buffer[1] = 0;\n"
        )
        tail = "    free(buffer);\n"
    elif kind == "stack":
        object_lines = (
            f"    unsigned char buffer[{capacity}] = {{0}};\n"
            "    size_t capacity = sizeof(buffer);\n"
        )
        tail = ""
    else:
        raise ValueError("only heap and stack public toys are supported")
    return (
        "#include <stdio.h>\n#include <stdlib.h>\n#include <stddef.h>\n"
        "__attribute__((noinline)) static int target_operation(int marker) {\n"
        f"    if (marker != '{marker}') return 0;\n"
        + object_lines +
        f"    size_t index = marker == '{marker}' ? capacity : 1;\n"
        "    volatile unsigned char observed = buffer[index]; /* OOB_CAUSAL_ACCESS */\n"
        + tail +
        "    return observed;\n"
        "}\n"
        "int main(int argc, char **argv) {\n"
        "    if (argc != 2) return 3;\n"
        "    FILE *stream = fopen(argv[1], \"rb\");\n"
        "    if (stream == NULL) return 4;\n"
        "    int marker = fgetc(stream);\n"
        "    fclose(stream);\n"
        "    return target_operation(marker);\n"
        "}\n"
    )


def _source_shape(source: Path, kind: str) -> tuple[int, int, int] | None:
    """Accept only the full auditable toy grammar; never parse arbitrary C."""
    text = source.read_text(encoding="utf-8")
    marker_match = re.search(r"if \(marker != '([A-Z])'\) return 0;", text)
    if not marker_match:
        return None
    marker = marker_match.group(1)
    if kind == "heap":
        bound_match = re.search(r"size_t capacity = ([1-9][0-9]*);", text)
    elif kind == "stack":
        bound_match = re.search(r"unsigned char buffer\[([1-9][0-9]*)\] = \{0\};", text)
    else:
        return None
    if not bound_match:
        return None
    capacity = int(bound_match.group(1))
    if not 2 <= capacity <= 4096 or text != _canonical_public_source(kind, capacity, marker):
        return None
    access_lines = [number for number, line in enumerate(text.splitlines(), 1)
                    if "/* OOB_CAUSAL_ACCESS */" in line]
    if len(access_lines) != 1:
        return None
    return capacity, ord(marker), access_lines[0]


def _gdb_witness(debugger: Path, source: Path, binary: Path, input_path: Path,
                 access_line: int, timeout_seconds: float, artifact_dir: Path,
                 run_id: str) -> tuple[dict[str, object], str, list[str]]:
        witness_path = artifact_dir / "witness.json"
        script_path = artifact_dir / "commands.gdb"
        script = (
            "set pagination off\n"
            "set confirm off\n"
            "set startup-with-shell off\n"
            "set debuginfod enabled off\n"
            "set disable-randomization off\n"
            f"break {source}:{access_line}\n"
            "run\n"
            "python\n"
            "import gdb, json, os\n"
            "frame = gdb.selected_frame()\n"
            "sal = frame.find_sal()\n"
            "observation = {\n"
            f"  'run_id': {run_id!r},\n"
            "  'source_path': sal.symtab.fullname(),\n"
            "  'line': sal.line,\n"
            "  'function_name': frame.name(),\n"
            "  'binary_path': gdb.current_progspace().filename,\n"
            "  'input_marker': int(gdb.parse_and_eval('marker')),\n"
            "  'capacity': int(gdb.parse_and_eval('capacity')),\n"
            "  'index': int(gdb.parse_and_eval('index')),\n"
            "  'buffer_address': int(gdb.parse_and_eval('(unsigned long)buffer')),\n"
            "}\n"
            f"fd = os.open({str(witness_path)!r}, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n"
            "os.write(fd, (json.dumps(observation, sort_keys=True) + '\\n').encode())\n"
            "os.fsync(fd)\n"
            "os.close(fd)\n"
            "end\n"
            "continue\n")
        _private_write_once(script_path, script.encode())
        command = [str(debugger), "-nx", "--batch", "-q", "-x", str(script_path),
                   "--args", str(binary), str(input_path)]
        try:
            done = _guarded_run(command, timeout=timeout_seconds)
            stdout, stderr = done.stdout, done.stderr
        except (RuntimeCleanupError, subprocess.TimeoutExpired) as exc:
            stdout = getattr(exc, "stdout", getattr(exc, "output", "")) or ""
            stderr = getattr(exc, "stderr", "") or ""
            _private_write_once(artifact_dir / "gdb_stdout.txt",
                                stdout if isinstance(stdout, bytes) else stdout.encode())
            _private_write_once(artifact_dir / "gdb_stderr.txt",
                                stderr if isinstance(stderr, bytes) else stderr.encode())
            raise
        _private_write_once(artifact_dir / "gdb_stdout.txt", stdout.encode())
        _private_write_once(artifact_dir / "gdb_stderr.txt", stderr.encode())
        if not witness_path.is_file() or witness_path.is_symlink():
            raise ValueError("GDB did not reach the exact source access")
        witness = json.loads(witness_path.read_text(encoding="utf-8"))
        return witness, stdout + stderr, command


def issue_development_oob_witness(
        source_root: Path, source: Path, binary: Path, crash_input: Path,
        normal_input: Path, *, spec: OOBWitnessSpec, pins: OOBPins,
        debugger: Path, approved_debugger: ApprovedDebugger,
        artifacts_root: Path, timeout_seconds: float = 10) -> OOBWitnessResult:
    """Issue a bounded toy witness; never authorize product Gate promotion."""
    paths = (source, binary, crash_input, normal_input)
    if any(path.is_symlink() or not path.is_file() for path in paths):
        return _blocked("BLOCKED_PIN_MISMATCH", "regular pinned file missing")
    try:
        if not source.resolve().is_relative_to(source_root.resolve()):
            return _blocked("BLOCKED_SOURCE_PROVENANCE", "source is outside root")
        current_pins = pin_development_inputs(
            *paths, compiled_source_sha256=pins.compiled_source_sha256)
    except (OSError, ValueError):
        return _blocked("BLOCKED_PIN_MISMATCH", "pinned files cannot be read")
    if current_pins != pins:
        return _blocked("BLOCKED_PIN_MISMATCH", "pinned bytes changed")
    if pins.source_sha256 != pins.compiled_source_sha256:
        return _blocked("BLOCKED_BUILD_SOURCE_MISMATCH",
                        "current source differs from frozen build-time source bytes")
    if (not crash_input.read_bytes() or not normal_input.read_bytes() or
            crash_input == normal_input or crash_input.stat().st_size != 1 or
            normal_input.stat().st_size != 1):
        return _blocked("BLOCKED_INPUT_SHAPE", "toy inputs must be distinct one-byte files")
    if not 0 < timeout_seconds <= 30 or not _approved_debugger_matches(
            debugger, approved_debugger):
        return _blocked("BLOCKED_DEBUG_ENVIRONMENT", "pinned debugger or deadline unavailable")
    try:
        artifact_dir = _new_private_artifact_dir(artifacts_root)
    except (OSError, ValueError) as exc:
        return _blocked("BLOCKED_ARTIFACT_ENVIRONMENT", str(exc))
    run_id = artifact_dir.name

    try:
        executor = RuntimeExecutor(timeout_seconds=timeout_seconds)
        normal = executor.run([str(binary), "{input}"], normal_input)
        crash = executor.run([str(binary), "{input}"], crash_input)
    except RuntimeCleanupError as exc:
        return _blocked("BLOCKED_CLEANUP_INCOMPLETE", str(exc))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return _blocked("BLOCKED_RUNTIME_ENVIRONMENT", str(exc))
    try:
        _private_json_once(artifact_dir / "normal_runtime.json", asdict(normal))
        _private_json_once(artifact_dir / "crash_runtime.json", asdict(crash))
    except OSError as exc:
        return _blocked("BLOCKED_ARTIFACT_ENVIRONMENT", str(exc))
    if normal.exit_code != 0 or normal.sanitizer or normal.timed_out:
        return _blocked("BLOCKED_NORMAL_CONTROL", "normal toy input did not exit cleanly")
    expected_oracle = ("heap-buffer-overflow" if spec.object_kind == "heap"
                       else "stack-buffer-overflow" if spec.object_kind == "stack" else None)
    if (not expected_oracle or not crash.sanitizer or
            expected_oracle not in crash.sanitizer or crash.exit_code in (None, 0) or
            crash.timed_out):
        return _blocked("BLOCKED_NO_TARGET_OOB", "original binary did not reproduce expected OOB")
    triage = triage_crash(crash, str(source_root), str(source_root / "harness.c"),
                          target_binary=binary)
    if triage.get("category") != "TARGET_CRASH":
        return _blocked("BLOCKED_SOURCE_PROVENANCE", "original OOB did not map to pinned target")
    provenance = triage.get("source_provenance") or {}
    if (Path(str(provenance.get("checkout_source", ""))).resolve() != source.resolve() or
            provenance.get("sha256") != pins.source_sha256):
        return _blocked("BLOCKED_SOURCE_PROVENANCE", "DWARF source does not match checkout bytes")

    try:
        shape = _source_shape(source, spec.object_kind)
    except (OSError, UnicodeError):
        shape = None
    if shape is None:
        return _blocked("BLOCKED_SOURCE_SHAPE", "source is outside narrow public toy grammar")
    source_capacity, marker, access_line = shape
    if (crash_input.read_bytes()[0] != marker or
            normal_input.read_bytes()[0] == marker):
        return _blocked("BLOCKED_INPUT_RELATION", "input marker does not select the source branch")

    try:
        witness, gdb_output, gdb_command = _gdb_witness(
            debugger, source, binary, crash_input, access_line, timeout_seconds,
            artifact_dir, run_id)
    except RuntimeCleanupError as exc:
        return _blocked("BLOCKED_CLEANUP_INCOMPLETE", str(exc))
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        return _blocked("BLOCKED_DEBUG_WITNESS", str(exc))
    if (witness.get("run_id") != run_id or
            witness.get("source_path") != str(source.resolve()) or
            witness.get("binary_path") != str(binary.resolve()) or
            witness.get("function_name") != "target_operation" or
            witness.get("line") != access_line or
            witness.get("input_marker") != marker or
            witness.get("capacity") != source_capacity or
            witness.get("index") != source_capacity or
            type(witness.get("buffer_address")) is not int):
        return _blocked("BLOCKED_CAUSAL_MISMATCH", "GDB values do not match source and input")
    if spec.claimed_capacity is not None and spec.claimed_capacity != source_capacity:
        return _blocked("BLOCKED_CAUSAL_CLAIM", "claimed object bound is not observed bound")
    if expected_oracle not in gdb_output:
        return _blocked("BLOCKED_DEBUG_WITNESS", "debugged run did not reproduce same OOB family")
    access_match = re.search(r"\bREAD of size 1 at (0x[0-9a-fA-F]+)", gdb_output)
    if not access_match:
        return _blocked("BLOCKED_DEBUG_WITNESS", "ASan access address is absent")
    access_address = int(access_match.group(1), 16)
    buffer_address = witness["buffer_address"]
    if access_address != buffer_address + source_capacity:
        return _blocked("BLOCKED_CAUSAL_MISMATCH", "GDB index and ASan access address disagree")
    if spec.object_kind == "heap":
        region = re.search(r"(\d+)-byte region \[(0x[0-9a-fA-F]+),(0x[0-9a-fA-F]+)\)",
                           gdb_output)
        if (not region or int(region.group(1)) != source_capacity or
                int(region.group(2), 16) != buffer_address or
                int(region.group(3), 16) != access_address):
            return _blocked("BLOCKED_CAUSAL_MISMATCH", "ASan heap region and measured object disagree")
    if (pin_development_inputs(*paths,
                               compiled_source_sha256=pins.compiled_source_sha256) != pins or
            not _approved_debugger_matches(debugger, approved_debugger)):
        return _blocked("BLOCKED_PIN_MISMATCH", "pinned bytes changed during measurement")
    artifact_names = ("normal_runtime.json", "crash_runtime.json", "commands.gdb",
                      "witness.json", "gdb_stdout.txt", "gdb_stderr.txt")
    try:
        artifacts = _artifact_index(artifact_dir, artifact_names)
    except (OSError, ValueError) as exc:
        return _blocked("BLOCKED_ARTIFACT_ENVIRONMENT", str(exc))
    receipt_path = artifact_dir / "receipt.json"
    receipt = {
        "kind": "OOB_CAUSAL_WITNESS_DEV_RECEIPT_V2",
        "run_id": run_id,
        "status": "ISSUED_DEVELOPMENT_WITNESS",
        "scope": "public toy only; qualification NONE; Gate ineligible",
        "pins": asdict(pins),
        "spec": asdict(spec),
        "approved_debugger": asdict(approved_debugger),
        "gdb_argv": gdb_command,
        "source_path": str(source.resolve()),
        "binary_path": str(binary.resolve()),
        "crash_input_path": str(crash_input.resolve()),
        "normal_input_path": str(normal_input.resolve()),
        "artifacts": artifacts,
    }
    try:
        _private_json_once(receipt_path, receipt)
        receipt_sha256 = _sha256(receipt_path)
    except OSError as exc:
        return _blocked("BLOCKED_ARTIFACT_ENVIRONMENT", str(exc))
    evidence: dict[str, object] = {
        "kind": "OOB_CAUSAL_WITNESS_PUBLIC_TOY_V1",
        "scope": "evaluation-only narrow C grammar; not product root cause or Gate authority",
        "qualification_identity": "NONE",
        "run_id": run_id,
        "receipt_path": str(receipt_path),
        "receipt_sha256": receipt_sha256,
        "artifacts": artifacts,
        "object_kind": spec.object_kind,
        "source_path": str(source.resolve()),
        "access_line": access_line,
        "binary_path": str(binary.resolve()),
        "input_path": str(crash_input.resolve()),
        "normal_input_path": str(normal_input.resolve()),
        "source_sha256": pins.source_sha256,
        "compiled_source_sha256": pins.compiled_source_sha256,
        "binary_sha256": pins.binary_sha256,
        "input_sha256": pins.crash_input_sha256,
        "normal_input_sha256": pins.normal_input_sha256,
        "runtime_sha256": artifacts["crash_runtime.json"]["sha256"],
        "debugger_sha256": approved_debugger.invocation_sha256,
        "debugger_backend_sha256": approved_debugger.backend_sha256,
        "debugger_script_sha256": artifacts["commands.gdb"]["sha256"],
        "debugger_output_sha256": hashlib.sha256(gdb_output.encode()).hexdigest(),
        "source_provenance": provenance,
        "oracle_family": expected_oracle,
        "capacity": source_capacity,
        "index": int(witness["index"]),
        "input_marker": marker,
        "buffer_address": buffer_address,
        "access_address": access_address,
        "causal_relation": "input byte selects index equal to measured object capacity",
        "gate_eligible": False,
    }
    return OOBWitnessResult("ISSUED_DEVELOPMENT_WITNESS", "observed narrow toy bound and access", evidence)
