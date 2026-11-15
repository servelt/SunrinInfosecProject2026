#!/usr/bin/env python3
"""Transparent OSS-Fuzz compiler wrapper that captures analysis units for SVF.

The real compile is always executed first and its result is returned unchanged.
For successful project-source compile actions, the same translation unit is
preprocessed with the exact build macros and include paths into the mounted
OSS-Fuzz ``/out`` directory.  The locked upstream SVF image then compiles these
units with its supported LLVM 21 before running pointer analysis.  This avoids
rewriting LLVM IR when OSS-Fuzz's newer compiler changes an intrinsic ABI, and
does not alter the object code used by the fuzzer build.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import subprocess
import sys
from pathlib import Path


SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".c++"}
DROP_STANDALONE = {"-MD", "-MMD", "-MP", "-MG"}
DROP_WITH_VALUE = {"-o", "-MF", "-MT", "-MQ", "-MJ"}


def main() -> int:
    arguments = sys.argv[1:]
    wrapper_name = Path(sys.argv[0]).name.casefold()
    is_cxx = "++" in wrapper_name or "cxx" in wrapper_name
    real = os.environ.get("HC_SVF_REAL_CXX" if is_cxx else "HC_SVF_REAL_CC")
    if not real:
        real = "clang++" if is_cxx else "clang"

    completed = subprocess.run([*shlex.split(real), *arguments], check=False)
    if completed.returncode != 0:
        return completed.returncode

    output = os.environ.get("HC_SVF_OUTPUT", "").strip()
    source_root = os.environ.get("HC_SVF_SOURCE_ROOT", "").strip()
    if not output or not source_root or "-c" not in arguments:
        return 0

    root = Path(source_root).resolve()
    sources = _project_sources(arguments, root)
    for source in sources:
        _capture_translation_unit(
            real=real,
            arguments=arguments,
            source=source,
            root=root,
            output=Path(output),
        )
    return 0


def _project_sources(arguments: list[str], root: Path) -> list[Path]:
    result: list[Path] = []
    for argument in arguments:
        if (
            argument.startswith("-")
            or Path(argument).suffix.casefold() not in SOURCE_SUFFIXES
        ):
            continue
        candidate = Path(argument)
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        try:
            resolved = candidate.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        if resolved.name.startswith("conftest.") or resolved.name.startswith(
            "confdefs."
        ):
            continue
        result.append(resolved)
    return sorted(set(result))


def _capture_translation_unit(
    *,
    real: str,
    arguments: list[str],
    source: Path,
    root: Path,
    output: Path,
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    relative = source.relative_to(root).as_posix()
    digest = hashlib.sha256(
        (relative + "\0" + "\0".join(arguments)).encode("utf-8", errors="replace")
    ).hexdigest()[:16]
    safe_name = "-".join(source.with_suffix("").parts[-3:])
    safe_name = "".join(
        character if character.isalnum() else "-" for character in safe_name
    )
    suffix = ".ii" if source.suffix.casefold() != ".c" else ".i"
    destination = output / f"{safe_name}-{digest}{suffix}"
    temporary = destination.with_suffix(destination.suffix + ".tmp")

    capture_arguments = _capture_arguments(arguments)
    command = [
        *shlex.split(real),
        *capture_arguments,
        "-E",
        str(source),
        "-o",
        str(temporary),
    ]
    captured = subprocess.run(command, capture_output=True, text=True, check=False)
    if captured.returncode != 0 or not temporary.is_file():
        temporary.unlink(missing_ok=True)
        error = output / "capture-errors.log"
        with error.open("a", encoding="utf-8") as stream:
            stream.write(f"SOURCE {relative}\n")
            stream.write("COMMAND " + shlex.join(command) + "\n")
            stream.write((captured.stderr or captured.stdout or "unknown error")[-8000:])
            stream.write("\n---\n")
        return
    os.replace(temporary, destination)
    destination.with_suffix(destination.suffix + ".source").write_text(
        relative + "\n", encoding="utf-8"
    )


def _capture_arguments(arguments: list[str]) -> list[str]:
    result: list[str] = []
    skip_next = False
    for argument in arguments:
        if skip_next:
            skip_next = False
            continue
        if argument in DROP_WITH_VALUE:
            skip_next = True
            continue
        if argument in DROP_STANDALONE or argument == "-c":
            continue
        if any(
            argument.startswith(option)
            for option in ("-MF", "-MT", "-MQ", "-MJ")
        ):
            continue
        if argument.startswith("-o") and argument != "-ObjC" and len(argument) > 2:
            continue
        if argument.startswith("-Wl,") or argument.startswith("-l"):
            continue
        suffix = Path(argument).suffix.casefold()
        if suffix in SOURCE_SUFFIXES or suffix in {".o", ".a", ".so"}:
            continue
        result.append(argument)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
