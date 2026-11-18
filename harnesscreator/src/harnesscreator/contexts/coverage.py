from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


class CoverageUnavailable(RuntimeError):
    """No coverage data could be read for a run (not the same as zero coverage)."""


@dataclass
class CoverageSnapshot:
    """Functions and lines executed in one run of a gcov-instrumented program."""

    functions: set[tuple[str, str]] = field(default_factory=set)        # (file, function name)
    known_functions: set[tuple[str, str]] = field(default_factory=set)  # compiled into the program, executed or not
    known_lines: set[tuple[str, str, int]] = field(default_factory=set)  # instrumented lines, executed or not
    lines: set[tuple[str, str, int]] = field(default_factory=set)       # (file, function name, line)
    known_function_ranges: set[tuple[str, str, int, int]] = field(default_factory=set)
    function_ranges: set[tuple[str, str, int, int]] = field(default_factory=set)

    def merge(self, other: "CoverageSnapshot") -> None:
        self.functions |= other.functions
        self.lines |= other.lines
        self.known_function_ranges |= other.known_function_ranges
        self.function_ranges |= other.function_ranges


class GcovCoverage:
    """Reads gcov data written by a program built with ``--coverage``.

    gcov counters are flushed when the process exits normally, so the program
    under test must terminate through ``exit``/return from ``main`` when it is
    stopped.  ProFuzzBench needs a per-server signal-handler patch for the same
    reason; a run that leaves no ``.gcda`` file is reported as unavailable.
    """

    def __init__(self, build_root: Path, *, gcov: str = "gcov"):
        self.build_root = Path(build_root).resolve()
        self.gcov = gcov
        if shutil.which(gcov) is None:
            raise CoverageUnavailable(f"gcov executable not found: {gcov!r}")
        if not self.build_root.is_dir():
            raise CoverageUnavailable(f"coverage build directory does not exist: {self.build_root}")

    def _data_files(self) -> list[Path]:
        return sorted(self.build_root.rglob("*.gcda"))

    def has_notes(self) -> bool:
        return next(self.build_root.rglob("*.gcno"), None) is not None

    def reset(self) -> None:
        for path in self._data_files():
            path.unlink()

    def _relative(self, name: str, cwd: Path) -> str:
        path = Path(name)
        if not path.is_absolute():
            path = cwd / path
        try:
            return path.resolve().relative_to(self.build_root).as_posix()
        except ValueError:
            return ""  # system header or file outside the build tree

    def collect(self) -> CoverageSnapshot:
        data_files = self._data_files()
        if not data_files:
            raise CoverageUnavailable(
                "the run left no .gcda file: the program was not built with --coverage in "
                f"{self.build_root}, or it did not exit normally when stopped")
        snapshot = CoverageSnapshot()
        for data_file in data_files:
            completed = subprocess.run(
                [self.gcov, "--json-format", "--stdout", data_file.name],
                cwd=data_file.parent, capture_output=True, text=True, check=False)
            if completed.returncode != 0 or not completed.stdout.strip():
                continue
            decoder = json.JSONDecoder()
            text, index = completed.stdout, 0
            while index < len(text):
                while index < len(text) and text[index].isspace():
                    index += 1
                if index >= len(text):
                    break
                document, index = decoder.raw_decode(text, index)
                cwd = Path(document.get("current_working_directory") or data_file.parent)
                for item in document.get("files", []):
                    relative = self._relative(item.get("file", ""), cwd)
                    if not relative:
                        continue
                    for function in item.get("functions", []):
                        name = function.get("name", "")
                        snapshot.known_functions.add((relative, name))
                        start, end = int(function.get("start_line") or 0), int(function.get("end_line") or 0)
                        if start > 0 and end >= start:
                            snapshot.known_function_ranges.add((relative, name, start, end))
                        if function.get("execution_count", 0) > 0:
                            snapshot.functions.add((relative, name))
                            if start > 0 and end >= start:
                                snapshot.function_ranges.add((relative, name, start, end))
                    for line in item.get("lines", []):
                        snapshot.known_lines.add((relative, line.get("function_name", ""), int(line.get("line_number", 0))))
                        if line.get("count", 0) > 0:
                            snapshot.lines.add((relative, line.get("function_name", ""), int(line.get("line_number", 0))))
        if not snapshot.functions and not snapshot.lines:
            raise CoverageUnavailable("gcov produced no readable function or line records")
        return snapshot


class TargetMap:
    """Joins gcov (file, function name) records to analysis function ids."""

    def __init__(self, functions: Iterable[dict[str, Any]], target_function_ids: Iterable[str]):
        self.target_ids = set(target_function_ids)
        self._by_name: dict[str, list[tuple[str, str, int, int]]] = {}
        for function in functions:
            function_id = function.get("function_id")
            if function_id in self.target_ids:
                self._by_name.setdefault(function.get("name", ""), []).append((
                    function.get("file", ""), function_id,
                    int(function.get("start_line") or 0), int(function.get("end_line") or 0)))

    def function_id(self, file: str, name: str, line: int = 0) -> str | None:
        candidates = self._by_name.get(name)
        if not candidates:
            return None
        # Same name can occur twice in one source under opposite #ifdefs. A
        # gcov location must match the source range before crediting either.
        matching = [(candidate_file, function_id, start, end)
                    for candidate_file, function_id, start, end in candidates
                    if candidate_file == file or file.endswith("/" + candidate_file)
                    or candidate_file.endswith("/" + file)]
        if line and any(start and end for _, _, start, end in matching):
            matching = [row for row in matching
                        if not row[2] or not row[3] or row[2] <= line <= row[3]]
        if len(matching) == 1:
            return matching[0][1]
        if len(matching) > 1:
            return None
        if len(candidates) == 1 and not line:
            return candidates[0][1]
        base = os.path.basename(file)
        matches = [function_id for candidate_file, function_id, start, end in candidates
                   if os.path.basename(candidate_file) == base
                   and (not line or not start or not end or start <= line <= end)]
        return matches[0] if len(matches) == 1 else None

    def compiled_functions(self, snapshot: CoverageSnapshot) -> set[str]:
        """Target functions that exist in the coverage build (other targets cannot be executed by any input)."""
        located = {(file, name) for file, name, _, _ in snapshot.known_function_ranges}
        found = {fid for fid in (self.function_id(file, name, start)
                                 for file, name, start, _ in snapshot.known_function_ranges) if fid}
        return found | {fid for fid in (self.function_id(file, name)
                                        for file, name in snapshot.known_functions - located) if fid}

    def covered_functions(self, snapshot: CoverageSnapshot) -> set[str]:
        located = {(file, name) for file, name, _, _ in snapshot.function_ranges}
        found = {fid for fid in (self.function_id(file, name, start)
                                 for file, name, start, _ in snapshot.function_ranges) if fid}
        return found | {fid for fid in (self.function_id(file, name)
                                        for file, name in snapshot.functions - located) if fid}

    def instrumented_lines(self, snapshot: CoverageSnapshot) -> set[tuple[str, int]]:
        return self._lines(snapshot.known_lines)

    def covered_lines(self, snapshot: CoverageSnapshot) -> set[tuple[str, int]]:
        return self._lines(snapshot.lines)

    def _lines(self, records: set[tuple[str, str, int]]) -> set[tuple[str, int]]:
        covered = set()
        for file, name, line in records:
            function_id = self.function_id(file, name, line)
            if function_id:
                covered.add((function_id, line))
        return covered
