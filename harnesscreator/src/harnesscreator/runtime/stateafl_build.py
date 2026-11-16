"""Build a copied server tree with StateAFL's original compiler wrappers.

This prepares a process-level network fuzzing target. A successful build is
neither a libFuzzer harness nor evidence that mutated requests reach a target
handler. The caller supplies the project's trusted build argv and executable
location; no source-specific recipe is inferred here.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class StateAFLBuildSpec:
    source_root: Path
    output_dir: Path
    compiler: Path
    build_command: tuple[str, ...]
    server_relative_path: Path
    cxx_compiler: Path | None = None
    timeout_seconds: int | None = None
    linker_flags: tuple[str, ...] = ()
    container_image: str | None = None
    build_steps: tuple[tuple[str, ...], ...] = ()
    excluded_paths: tuple[Path, ...] = ()
    stop_event: threading.Event | None = None


class StateAFLBuildError(ValueError):
    """The supplied project recipe did not yield an executable target."""


def build_stateafl_server(spec: StateAFLBuildSpec) -> dict[str, Any]:
    if spec.stop_event is not None and spec.stop_event.is_set():
        raise StateAFLBuildError("instrumented build cancelled by parent analysis")
    source = spec.source_root.resolve(strict=True)
    output = spec.output_dir.resolve()
    if not source.is_dir():
        raise ValueError("server source root must be a directory")
    if output == source or source in output.parents:
        raise ValueError("instrumented build output must be outside the source tree")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("instrumented build output directory must be empty")
    excluded = tuple(path.resolve() for path in spec.excluded_paths)
    if any(path == source for path in excluded):
        raise ValueError("instrumented build cannot exclude the source root")
    all_steps = (spec.build_command, *spec.build_steps)
    if any(not step or any(not part or "\0" in part for part in step) for step in all_steps):
        raise ValueError("a trusted, nonempty build argv is required")
    if spec.timeout_seconds is not None and spec.timeout_seconds < 1:
        raise ValueError("build timeout must be positive when supplied")
    if any(not flag or "\0" in flag for flag in spec.linker_flags):
        raise ValueError("linker flags must be nonempty arguments")
    if spec.container_image is not None and (not spec.container_image.strip() or "\0" in spec.container_image):
        raise ValueError("container image must be a nonempty name")
    relative = spec.server_relative_path
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("server binary must be a relative path inside the copied source")
    compiler = _runnable(spec.compiler, "StateAFL C compiler")
    companion = compiler.with_name("afl-clang-fast++")
    cxx = _runnable(spec.cxx_compiler, "StateAFL C++ compiler") if spec.cxx_compiler else (
        _runnable(companion, "StateAFL C++ compiler") if companion.is_file() else None
    )

    output.mkdir(parents=True, exist_ok=True)
    copied = output / "source"
    def ignore_outputs(directory: str, names: list[str]) -> set[str]:
        if spec.stop_event is not None and spec.stop_event.is_set():
            raise StateAFLBuildError("instrumented build cancelled by parent analysis")
        parent = Path(directory)
        return {
            name for name in names
            if any(
                (candidate := (parent / name).resolve()) == path
                or path in candidate.parents
                for path in excluded
            )
        }

    shutil.copytree(source, copied, symlinks=True, ignore=ignore_outputs)
    prior_objects = _object_metadata(copied)
    output_binary = copied / relative
    resolved_binary = output_binary.resolve()
    if copied not in resolved_binary.parents:
        raise ValueError("server binary path escapes the copied source tree")
    # A copied checkout may already contain an old, uninstrumented binary.
    # Remove that copy before invoking the build so success cannot be inferred
    # from a stale artifact that the supplied command never produced.
    if output_binary.is_file() or output_binary.is_symlink():
        output_binary.unlink()
    elif output_binary.exists():
        raise ValueError("server binary output path is a directory")
    shim_dir = output / "compiler-shims"
    shim_dir.mkdir()
    invocation_dir = output / "compile-invocations"
    invocation_dir.mkdir()
    if spec.container_image:
        c_compiler = Path("/stateafl") / compiler.name
        cxx_compiler = (
            Path("/stateafl") / cxx.name if cxx and cxx.parent == compiler.parent
            else Path("/stateafl-cxx") / cxx.name if cxx else None
        )
    else:
        c_compiler, cxx_compiler = compiler, cxx
    for name in ("gcc", "cc"):
        _write_shim(shim_dir / name, c_compiler, spec.linker_flags, invocation_dir, bool(spec.container_image))
    for name in ("g++", "c++"):
        _write_shim(shim_dir / name, cxx_compiler, spec.linker_flags, invocation_dir, bool(spec.container_image))
    build_cc = "/work/compiler-shims/cc" if spec.container_image else str(shim_dir / "cc")
    build_cxx = "/work/compiler-shims/c++" if spec.container_image else str(shim_dir / "c++")
    env = os.environ.copy()
    env.update({
        "CC": build_cc,
        "CXX": build_cxx,
        "AFL_PATH": str(compiler.parent),
        "PATH": str(shim_dir) + os.pathsep + env.get("PATH", ""),
    })
    if spec.container_image:
        docker = shutil.which("docker")
        if not docker:
            raise StateAFLBuildError("Docker is required for the selected build container")
        entrypoint = output / "build-entrypoint.sh"
        entrypoint.write_text(
            '#!/bin/sh\nexport PATH="/work/compiler-shims:$PATH"\nexec "$@"\n',
            encoding="utf-8",
        )
        entrypoint.chmod(0o755)
        command_prefix = [
            docker, "run", "--rm", "--entrypoint", "/work/build-entrypoint.sh",
            "--volume", f"{output}:/work",
            "--volume", f"{compiler.parent}:/stateafl:ro",
            "--workdir", "/work/source",
            "--env", f"CC={build_cc}",
            "--env", f"CXX={build_cxx}",
            "--env", "AFL_PATH=/stateafl",
        ]
        if cxx and cxx.parent != compiler.parent:
            command_prefix.extend(["--volume", f"{cxx.parent}:/stateafl-cxx:ro"])
        command_prefix.append(spec.container_image)
        run_cwd, run_env = output, None
    else:
        command_prefix = []
        run_cwd, run_env = copied, env
    build_log = output / "build.log"
    with build_log.open("w", encoding="utf-8") as log:
        for index, step in enumerate(all_steps, 1):
            log.write(f"[build step {index}/{len(all_steps)}] {shlex.join(step)}\n")
            log.flush()
            try:
                if spec.stop_event is None:
                    result = subprocess.run(
                        [*command_prefix, *step], cwd=run_cwd, env=run_env,
                        text=True, stdout=log, stderr=subprocess.STDOUT,
                        timeout=spec.timeout_seconds, check=False,
                    )
                    returncode = result.returncode
                else:
                    if spec.stop_event.is_set():
                        raise StateAFLBuildError(
                            "instrumented build cancelled by parent analysis"
                        )
                    process = subprocess.Popen(
                        [*command_prefix, *step], cwd=run_cwd, env=run_env,
                        text=True, stdout=log, stderr=subprocess.STDOUT,
                        start_new_session=True,
                    )
                    deadline = (
                        time.monotonic() + spec.timeout_seconds
                        if spec.timeout_seconds is not None else None
                    )
                    try:
                        while process.poll() is None:
                            if spec.stop_event.is_set():
                                raise StateAFLBuildError(
                                    "instrumented build cancelled by parent analysis"
                                )
                            if deadline is not None and time.monotonic() >= deadline:
                                raise subprocess.TimeoutExpired(step, spec.timeout_seconds)
                            try:
                                process.wait(timeout=0.5)
                            except subprocess.TimeoutExpired:
                                pass
                        returncode = process.returncode
                    except BaseException:
                        _stop_build_process(process)
                        raise
            except (OSError, subprocess.TimeoutExpired) as exc:
                log.write(str(exc) + "\n")
                raise StateAFLBuildError(
                    f"instrumented server build step {index} did not finish: {exc}"
                ) from exc
            if returncode:
                raise StateAFLBuildError(
                    f"instrumented server build step {index} failed "
                    f"(exit={returncode}); see {build_log}"
                )
    binary = output_binary.resolve()
    if not binary.is_file() or copied not in binary.parents:
        raise StateAFLBuildError(
            "instrumented server build did not produce the expected executable; "
            f"expected binary {relative}; see {output / 'build.log'}"
        )
    if not os.access(binary, os.X_OK):
        raise StateAFLBuildError(f"built server is not executable: {binary}")
    marker = _afl_runtime_symbol(binary)
    object_coverage = _coverage_object_symbol(copied, prior_objects)
    binary_trace_pc_coverage = _trace_pc_binary_guard(binary)
    instrumentation_evidence = (
        marker is True
        and (object_coverage is True or binary_trace_pc_coverage is True)
    )
    compile_records = _compile_records(invocation_dir, output, copied, bool(spec.container_image))
    compile_db = output / "compile_commands.json"
    compile_db.write_text(json.dumps(compile_records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = {
        "status": (
            "BUILT_INSTRUMENTATION_UNVERIFIED" if instrumentation_evidence
            else "BUILT_COVERAGE_NOT_OBSERVED"
        ),
        "source_root": str(source),
        "copied_source": str(copied),
        "build_command": list(spec.build_command),
        "build_steps": [list(step) for step in spec.build_steps],
        "linker_flags": list(spec.linker_flags),
        "container_image": spec.container_image,
        "excluded_source_paths": [str(path) for path in excluded],
        "compiler": str(compiler),
        "cxx_compiler": str(cxx) if cxx else None,
        "server_binary": str(binary),
        "compile_database": str(compile_db),
        "compile_database_files": len(compile_records),
        "server_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "afl_runtime_symbol_detected": marker,
        "afl_coverage_object_detected": object_coverage,
        "afl_trace_pc_binary_guard_detected": binary_trace_pc_coverage,
        "instrumentation_evidence": instrumentation_evidence,
        "qualified_harness_claim": False,
        "vulnerability_claim": False,
        "next_evidence": (
            "Run an original-request seed through the instrumented server "
            "and confirm nonzero coverage before interpreting any fuzz result"
            if instrumentation_evidence else
            "AFL runtime plus compiler-inserted coverage were not both observed; "
            "check the Clang/LLVM pass version and build outputs before fuzzing"
        ),
    }
    (output / "build.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return report


def _stop_build_process(process: subprocess.Popen[Any]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def _runnable(path: Path | None, name: str) -> Path:
    if path is None:
        raise ValueError(f"{name} is required")
    absolute = path.expanduser().absolute()
    resolved = absolute.resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError(f"{name} is not runnable: {resolved}")
    # StateAFL's afl-clang-fast++ may be a symlink to afl-clang-fast. Preserve
    # the invoked basename so its wrapper selects the C++ driver.
    return absolute


def _write_shim(
    path: Path, compiler: Path | None, linker_flags: tuple[str, ...],
    invocation_dir: Path, containerized: bool,
) -> None:
    if compiler:
        # Project Makefiles sometimes invoke gcc directly and ignore CC/LDFLAGS.
        # Apply caller-supplied flags only at the final link, never to -c or -E.
        args = " ".join(shlex.quote(flag) for flag in linker_flags)
        capture = "/work/compile-invocations" if containerized else str(invocation_dir)
        body = (
            "#!/bin/sh\n"
            'capture=$(mktemp ' + shlex.quote(capture + "/invocation.XXXXXXXX") + ') || exit 1\n'
            "printf '%s\\0' " + shlex.quote(str(compiler)) + ' "$PWD" "$@" > "$capture"\n'
            "for arg do\n"
            '  case "$arg" in -c|-E|-S) exec ' + shlex.quote(str(compiler)) + ' "$@";; esac\n'
            "done\n"
            "exec " + shlex.quote(str(compiler)) + ' "$@"' + (" " + args if args else "") + "\n"
        )
    else:
        body = '#!/bin/sh\necho "StateAFL C++ compiler unavailable" >&2\nexit 127\n'
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def _compile_records(
    invocation_dir: Path, output: Path, copied: Path, containerized: bool,
) -> list[dict[str, Any]]:
    """Record exact source compile argv; AST flag selection remains separate."""
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()

    def mapped(value: str) -> str:
        if containerized and value.startswith("/work/"):
            return str(output / value.removeprefix("/work/"))
        if containerized and value.startswith("-I/work/"):
            return "-I" + str(output / value.removeprefix("-I/work/"))
        return value

    for path in sorted(invocation_dir.iterdir()):
        if not path.is_file():
            continue
        fields = path.read_bytes().split(b"\0")
        if fields[-1:] == [b""]:
            fields.pop()
        if len(fields) < 4:
            continue
        values = [part.decode("utf-8", errors="surrogateescape") for part in fields]
        compiler, directory, *args = values
        if "-c" not in args:
            continue
        directory = mapped(directory)
        args = [mapped(arg) for arg in args]
        sources = [arg for arg in args if not arg.startswith("-") and Path(arg).suffix.lower() in {".c", ".cc", ".cpp", ".cxx"}]
        if len(sources) != 1:
            continue
        source = Path(sources[0])
        source = (source if source.is_absolute() else Path(directory) / source).resolve()
        if not source.is_file() or copied not in source.parents:
            continue
        key = str(source), tuple(args)
        if key in seen:
            continue
        seen.add(key)
        records.append({"directory": directory, "file": str(source), "arguments": [compiler, *args]})
    return records


def _afl_runtime_symbol(binary: Path) -> bool | None:
    nm = shutil.which("nm")
    if not nm:
        return None
    result = subprocess.run(
        [nm, "-a", str(binary)], capture_output=True, text=True, check=False,
    )
    if result.returncode:
        return None  # stripped binary or unsupported object format
    return "__afl_area_ptr" in result.stdout and "__afl_auto_init" in result.stdout


def _object_metadata(source: Path) -> dict[Path, tuple[int, int]]:
    metadata = {}
    for obj in source.rglob("*.o"):
        if obj.is_file() and not obj.is_symlink() and source in obj.resolve().parents:
            stat = obj.stat()
            metadata[obj.relative_to(source)] = (stat.st_size, stat.st_mtime_ns)
    return metadata


def _coverage_object_symbol(
    source: Path, prior_objects: dict[Path, tuple[int, int]],
) -> bool | None:
    """Inspect fresh objects for either StateAFL-supported coverage mode.

    The original LLVM pass references __afl_area_ptr. StateAFL's documented
    trace-pc-guard mode instead references SanitizerCoverage callbacks and
    emits __sancov_guards sections; the runtime provides those callbacks.
    """
    nm = shutil.which("nm")
    if not nm:
        return None
    readelf = shutil.which("readelf")
    saw_fresh_object = False
    trace_pc_unverified = False
    for obj in source.rglob("*.o"):
        if not obj.is_file() or obj.is_symlink() or source not in obj.resolve().parents:
            continue
        stat = obj.stat()
        if prior_objects.get(obj.relative_to(source)) == (stat.st_size, stat.st_mtime_ns):
            continue
        saw_fresh_object = True
        result = subprocess.run([nm, "-u", str(obj)], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            continue
        if "__afl_area_ptr" in result.stdout:
            return True
        if ("__sanitizer_cov_trace_pc_guard" not in result.stdout
            or "__sanitizer_cov_trace_pc_guard_init" not in result.stdout):
            continue
        if readelf is None:
            trace_pc_unverified = True
            continue
        sections = subprocess.run(
            [readelf, "-SW", str(obj)], capture_output=True, text=True, check=False,
        )
        if sections.returncode != 0:
            trace_pc_unverified = True
        elif "__sancov_guards" in sections.stdout:
            return True
    if trace_pc_unverified:
        return None
    return False if saw_fresh_object else None


def _trace_pc_binary_guard(binary: Path) -> bool | None:
    """Find Clang's guard section in a directly compiled and linked target.

    Single-command builds can leave no fresh .o in the copied tree. The AFL
    runtime defines trace-pc callbacks even without target instrumentation,
    so those symbols alone are insufficient; Clang's guard section is required.
    """
    readelf = shutil.which("readelf")
    if readelf is None:
        return None
    sections = subprocess.run(
        [readelf, "-SW", str(binary)], capture_output=True, text=True, check=False,
    )
    if sections.returncode != 0:
        return None
    return "__sancov_guards" in sections.stdout


def has_instrumentation_evidence(report: dict[str, Any]) -> bool:
    """Accept current reports and earlier object-based reports with runtime proof."""
    return (
        report.get("afl_runtime_symbol_detected") is True
        and (
            report.get("afl_coverage_object_detected") is True
            or report.get("afl_trace_pc_binary_guard_detected") is True
        )
        and ("instrumentation_evidence" not in report
             or report["instrumentation_evidence"] is True)
    )
