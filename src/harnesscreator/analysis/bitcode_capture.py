"""Capture target-specific LLVM bitcode from recorded C/C++ compilations.

The compilation database supplies the build's include paths, macros, language
mode and source list. Clang replaces the recorded compiler only for this
analysis copy; the product build and its objects are never rewritten. A failed
or ambiguous translation unit aborts capture rather than silently omitting
possible indirect-call targets.
"""
from __future__ import annotations

import hashlib
import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class BitcodeCaptureError(ValueError):
    pass


@dataclass(frozen=True)
class CapturedBitcode:
    modules: tuple[Path, ...]
    compiled_sources: tuple[str, ...]


_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++", ".cp"}
_VALUE_OUTPUT_FLAGS = {"-o", "-MF", "-MT", "-MQ", "-MJ"}
_BARE_OUTPUT_FLAGS = {"-c", "-MD", "-MMD", "-MP"}


def _record_argv(record: dict) -> list[str]:
    arguments = record.get("arguments")
    if isinstance(arguments, list) and all(isinstance(x, str) for x in arguments):
        return list(arguments)
    command = record.get("command")
    if isinstance(command, str):
        try:
            return shlex.split(command)
        except ValueError as exc:
            raise BitcodeCaptureError(f"invalid compilation command: {exc}") from exc
    raise BitcodeCaptureError("compilation record has no usable arguments or command")


def _analysis_argv(record: dict, source: Path, destination: Path) -> list[str]:
    original = _record_argv(record)
    if not original:
        raise BitcodeCaptureError(f"empty compilation command for {source}")
    compiler = Path(original[0]).name.casefold()
    if compiler in {"ccache", "sccache", "distcc"}:
        original = original[1:]
        if not original:
            raise BitcodeCaptureError(f"compiler wrapper has no compiler for {source}")
        compiler = Path(original[0]).name.casefold()
    if ("++" in compiler or source.suffix.casefold() != ".c"
        or any(original[i:i + 2] == ["-x", "c++"]
               for i in range(len(original) - 1))):
        replacement = shutil.which("clang++")
    else:
        replacement = shutil.which("clang")
    if replacement is None:
        raise BitcodeCaptureError("Clang is required for SVF bitcode capture")
    directory = Path(str(record["directory"])).resolve()
    source_arguments = [
        argument for argument in original[1:]
        if not argument.startswith("-")
        and (Path(argument) if Path(argument).is_absolute()
             else directory / argument).resolve() == source
    ]
    if len(source_arguments) != 1:
        raise BitcodeCaptureError(
            f"compilation command does not name exactly one selected source: {source}"
        )
    result = [replacement]
    index = 1
    while index < len(original):
        argument = original[index]
        if argument in _BARE_OUTPUT_FLAGS:
            index += 1
            continue
        if argument in _VALUE_OUTPUT_FLAGS:
            if index + 1 >= len(original):
                raise BitcodeCaptureError(f"missing value after {argument} for {source}")
            index += 2
            continue
        if any(argument.startswith(flag) and argument != flag
               for flag in _VALUE_OUTPUT_FLAGS):
            index += 1
            continue
        result.append(argument)
        index += 1
    result.extend(["-emit-llvm", "-c", "-o", str(destination)])
    return result


def capture_bitcode_from_compile_database(
    compile_database: Path, source_root: Path, output_dir: Path,
) -> CapturedBitcode:
    """Compile every recorded target source to bitcode, or fail as a unit.

    Callers should use a database captured for the selected build target.
    Multi-configuration records for one source are ambiguous and rejected.
    """
    root = source_root.resolve(strict=True)
    database = compile_database.resolve(strict=True)
    try:
        records = json.loads(database.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise BitcodeCaptureError(f"cannot read compilation database {database}: {exc}") from exc
    if not isinstance(records, list):
        raise BitcodeCaptureError("compilation database must contain a list")
    selected: list[tuple[Path, dict]] = []
    seen: set[Path] = set()
    for record in records:
        if not isinstance(record, dict) or not record.get("file") or not record.get("directory"):
            raise BitcodeCaptureError("compilation database contains an incomplete record")
        directory = Path(str(record["directory"])).resolve()
        name = Path(str(record["file"]))
        source = (name if name.is_absolute() else directory / name).resolve()
        if not source.is_relative_to(root) or source.suffix.casefold() not in _SOURCE_SUFFIXES:
            continue
        if not source.is_file():
            raise BitcodeCaptureError(f"recorded source is missing: {source}")
        if source in seen:
            raise BitcodeCaptureError(
                f"multiple compile commands for {source}; capture one selected build target"
            )
        seen.add(source)
        selected.append((source, record))
    if not selected:
        raise BitcodeCaptureError(
            "compilation database has no C/C++ source in the selected project"
        )
    output_dir.mkdir(parents=True, exist_ok=True)
    modules: list[Path] = []
    sources: list[str] = []
    for source, record in selected:
        identity = hashlib.sha256(str(source).encode("utf-8")).hexdigest()[:20]
        destination = output_dir / f"{identity}.bc"
        argv = _analysis_argv(record, source, destination)
        directory = Path(str(record["directory"])).resolve()
        try:
            completed = subprocess.run(
                argv, cwd=directory, capture_output=True, text=True, check=False,
            )
        except OSError as exc:
            raise BitcodeCaptureError(f"Clang could not run for {source}: {exc}") from exc
        if completed.returncode != 0 or not destination.is_file():
            detail = (completed.stderr or completed.stdout).strip().splitlines()
            raise BitcodeCaptureError(
                f"Clang bitcode capture failed for {source}: "
                + (detail[0] if detail else f"exit {completed.returncode}")
            )
        modules.append(destination)
        sources.append(str(source))
    return CapturedBitcode(tuple(modules), tuple(sources))
