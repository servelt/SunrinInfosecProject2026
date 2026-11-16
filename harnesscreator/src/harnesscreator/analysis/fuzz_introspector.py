from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable


FI_DISTRIBUTION = "fuzz-introspector"
FI_REQUIRED_VERSION = "0.1.10"
FI_CACHE_SCHEMA = 1
FI_SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx"}


class FuzzIntrospectorError(RuntimeError):
    """Raised when automatic Fuzz Introspector analysis cannot be completed."""


def default_fi_cache_root(source_root: Path) -> Path:
    """Keep one content-validated FI cache across output run directories."""
    source = source_root.expanduser().resolve()
    key = hashlib.sha256(str(source).encode()).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / "harnesscreator-fi-cache" / key


@dataclass(slots=True, frozen=True)
class FuzzIntrospectorResult:
    report: Path
    cache_hit: bool
    version: str
    source_files: int


class FuzzIntrospectorRunner:
    """Run FI's build-free C/C++ frontend and cache its project report.

    HarnessCreator needs a project-wide call graph before it has generated a
    harness.  FI's LLVM/LTO mode requires a pre-existing fuzz target, so this
    adapter deliberately uses FI's build-free tree-sitter frontend and asks it
    to dump module logic for the complete source set.
    """

    def __init__(
        self,
        source_root: Path,
        cache_root: Path,
        *,
        excluded_paths: Iterable[Path] = (),
        progress: Callable[[str], None] | None = None,
        timeout_seconds: int = 1800,
        compile_database: Path | None = None,
    ):
        self.source_root = source_root.resolve()
        self.cache_root = cache_root.resolve()
        self.excluded_paths = tuple(path.resolve() for path in excluded_paths)
        self.progress = progress or (lambda _message: None)
        self.timeout_seconds = timeout_seconds
        # With a compile database only the translation units the build compiles (and the headers
        # next to them) are analysed.  Without it every C/C++ file under the root was taken:
        # measured on redis 7.x, 504 files including deps/ (Lua, jemalloc, hiredis), tests and
        # modules, and FI ran past 11 minutes; the program itself is 139 files under src/.
        self.compiled: set[Path] | None = _compiled_files(compile_database) if compile_database else None

    def run(self) -> FuzzIntrospectorResult:
        version = self._installed_version()
        source_files = self._source_files()
        if not source_files:
            raise FuzzIntrospectorError(
                f"Fuzz Introspector found no C/C++ source files under {self.source_root}"
            )

        digest = self._source_digest(source_files, version)
        target = self.cache_root / digest
        report = target / "fuzzerLogFile-harnesscreator.data.yaml"
        manifest = target / "manifest.json"
        if self._valid_cache(manifest, report, digest, version, len(source_files)):
            self.progress(
                f"Fuzz Introspector cache hit: {report} ({len(source_files)} source files)"
            )
            return FuzzIntrospectorResult(report, True, version, len(source_files))

        self.cache_root.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{digest}-", dir=self.cache_root))
        try:
            file_list = staging / "source-files.json"
            generated_report = staging / report.name
            file_list.write_text(
                json.dumps([str(path) for path in source_files], ensure_ascii=False),
                encoding="utf-8",
            )
            self.progress(
                "Fuzz Introspector automatic analysis started: "
                f"version={version}, files={len(source_files)}"
            )
            command = [
                sys.executable,
                "-m",
                "harnesscreator.analysis.fi_worker",
                "--source-root",
                str(self.source_root),
                "--source-list",
                str(file_list),
                "--report",
                str(generated_report),
            ]
            try:
                completed = subprocess.run(
                    command,
                    cwd=self.source_root,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise FuzzIntrospectorError(
                    f"automatic Fuzz Introspector analysis timed out after "
                    f"{self.timeout_seconds}s"
                ) from exc

            log = staging / "fuzz-introspector.log"
            log.write_text(
                "command: " + " ".join(command) + "\n\n"
                + "stdout:\n" + completed.stdout + "\n\n"
                + "stderr:\n" + completed.stderr,
                encoding="utf-8",
            )
            if completed.returncode != 0:
                detail = _last_nonempty_line(completed.stderr) or _last_nonempty_line(
                    completed.stdout
                )
                raise FuzzIntrospectorError(
                    "automatic Fuzz Introspector analysis failed"
                    + (f": {detail}" if detail else "")
                    + f"; log={log}"
                )
            if not generated_report.is_file() or generated_report.stat().st_size == 0:
                raise FuzzIntrospectorError(
                    f"Fuzz Introspector did not create a usable report; log={log}"
                )

            manifest_payload = {
                "schema": FI_CACHE_SCHEMA,
                "provider": "fuzz-introspector-build-free-c-cpp",
                "fuzz_introspector_version": version,
                "source_root": str(self.source_root),
                "source_digest": digest,
                "source_files": len(source_files),
                "report": generated_report.name,
            }
            (staging / "manifest.json").write_text(
                json.dumps(manifest_payload, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            if target.exists():
                shutil.rmtree(staging)
            else:
                os.replace(staging, target)
            self.progress(
                f"Fuzz Introspector automatic analysis completed: {report}"
            )
            return FuzzIntrospectorResult(report, False, version, len(source_files))
        except Exception:
            if staging.exists():
                self.progress(
                    f"Fuzz Introspector failure artifacts retained at {staging}"
                )
            raise

    @staticmethod
    def _installed_version() -> str:
        try:
            version = importlib.metadata.version(FI_DISTRIBUTION)
        except importlib.metadata.PackageNotFoundError as exc:
            raise FuzzIntrospectorError(
                "Fuzz Introspector is not installed in HarnessCreator's Python environment. "
                "Reinstall HarnessCreator with dependencies and retry "
                f"(required FI package version: {FI_REQUIRED_VERSION})."
            ) from exc
        return version

    def _source_files(self) -> list[Path]:
        files: list[Path] = []
        for directory, names, filenames in os.walk(
            self.source_root, topdown=True, followlinks=False
        ):
            current = Path(directory)
            names[:] = sorted(
                name for name in names
                if not _skip_directory(name)
                and not any(
                    _is_relative_to((current / name).resolve(), excluded)
                    for excluded in self.excluded_paths
                )
            )
            for name in filenames:
                path = current / name
                if path.suffix.lower() not in FI_SOURCE_EXTENSIONS or not path.is_file():
                    continue
                resolved = path.resolve()
                if not _is_relative_to(resolved, self.source_root):
                    continue
                if any(_is_relative_to(resolved, excluded) for excluded in self.excluded_paths):
                    continue
                files.append(resolved)
        if self.compiled:
            folders = {path.parent for path in self.compiled}
            kept = [path for path in files if path in self.compiled
                    or (path.suffix.lower() in _HEADER_SUFFIXES and path.parent in folders)]
            if any(path in self.compiled for path in kept):
                return sorted(set(kept))
        return sorted(set(files))

    def _source_digest(self, source_files: list[Path], version: str) -> str:
        digest = hashlib.sha256()
        digest.update(f"{FI_CACHE_SCHEMA}\0{version}\0".encode())
        for path in source_files:
            digest.update(str(path.relative_to(self.source_root)).encode())
            digest.update(b"\0")
            with path.open("rb") as source:
                while block := source.read(1024 * 1024):
                    digest.update(block)
            digest.update(b"\0")
        return digest.hexdigest()[:24]

    @staticmethod
    def _valid_cache(
        manifest: Path,
        report: Path,
        digest: str,
        version: str,
        source_files: int,
    ) -> bool:
        if not manifest.is_file() or not report.is_file() or report.stat().st_size == 0:
            return False
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        return (
            payload.get("schema") == FI_CACHE_SCHEMA
            and payload.get("source_digest") == digest
            and payload.get("fuzz_introspector_version") == version
            and payload.get("source_files") == source_files
        )


def _skip_directory(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered in {
            ".git",
            ".harnesscreator",
            ".fuzz-introspector",
            "build",
            "out",
            "harnesscreator-runs",
            "node_modules",
        }
        or lowered == "runs"
        or lowered.startswith("runs-")
    )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _last_nonempty_line(value: str) -> str:
    return next((line.strip() for line in reversed(value.splitlines()) if line.strip()), "")


_HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc"}


def _compiled_files(compile_database: Path) -> set[Path]:
    """Source files named by a compile_commands.json, resolved; empty when it cannot be read."""
    try:
        records = json.loads(Path(compile_database).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    files: set[Path] = set()
    for record in records if isinstance(records, list) else []:
        name = record.get("file") if isinstance(record, dict) else None
        if not name:
            continue
        path = Path(name)
        if not path.is_absolute():
            path = Path(str(record.get("directory") or Path(compile_database).parent)) / path
        try:
            files.add(path.resolve())
        except OSError:
            continue
    return files
