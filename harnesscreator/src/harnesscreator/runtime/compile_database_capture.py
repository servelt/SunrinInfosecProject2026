"""Capture a real project build with Bear for Clang source analysis.

The caller supplies the exact build argv. Bear records compiler invocations;
this module does not infer flags from a dry run or execute a model-written
command. The captured database is analysis context, never reachability proof.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence


def capture_compile_database(
    source_root: Path,
    output_path: Path,
    build_argv: Sequence[str],
    *,
    timeout_seconds: float | None = None,
) -> Path:
    if not build_argv or any(not token or "\x00" in token for token in build_argv):
        raise ValueError("analysis build command must contain nonempty argv tokens")
    if timeout_seconds is not None and timeout_seconds <= 0:
        raise ValueError("analysis build timeout must be positive when supplied")
    root = source_root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"analysis source root is not a directory: {root}")
    bear = shutil.which("bear")
    if bear is None:
        raise ValueError(
            "Bear is required to capture actual compiler commands; install Bear "
            "or pass an existing --analysis-compile-database"
        )
    destination = output_path.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    log_path = destination.with_suffix(".build.log")
    with tempfile.NamedTemporaryFile(
        prefix="compile-commands-", suffix=".json",
        dir=destination.parent, delete=False,
    ) as temporary:
        temporary_path = Path(temporary.name)
    temporary_path.unlink()
    try:
        with log_path.open("wb") as log:
            try:
                report = subprocess.run(
                    [bear, "--output", str(temporary_path), "--", *build_argv],
                    cwd=root, stdout=log, stderr=subprocess.STDOUT,
                    timeout=timeout_seconds, check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise ValueError(
                    f"analysis build exceeded its selected timeout; see {log_path}"
                ) from exc
        if report.returncode != 0:
            raise ValueError(
                f"analysis build failed (exit {report.returncode}); see {log_path}"
            )
        try:
            records = json.loads(temporary_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError) as exc:
            raise ValueError(
                f"Bear did not produce a valid compilation database; see {log_path}"
            ) from exc
        if not isinstance(records, list) or not records:
            raise ValueError(
                "Bear captured no compiler invocations; run a real rebuild "
                f"(for make, usually make -B) and see {log_path}"
            )
        project_records = 0
        for record in records:
            if not isinstance(record, dict):
                continue
            value = record.get("file")
            if not isinstance(value, str) or not value:
                continue
            directory = Path(str(record.get("directory") or root)).resolve()
            path = Path(value)
            path = (path if path.is_absolute() else directory / path).resolve()
            if path.is_file() and (path == root or root in path.parents):
                project_records += 1
        if not project_records:
            raise ValueError(
                "Bear captured no source files in the requested project; "
                f"check the build target and see {log_path}"
            )
        os.replace(temporary_path, destination)
        return destination
    finally:
        temporary_path.unlink(missing_ok=True)
