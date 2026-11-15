from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Iterable

from ..models import AnalysisBundle, UsageArtifact


_USAGE_COMPONENTS = {
    "test", "tests", "testing", "t", "example", "examples", "sample", "samples",
    "client", "clients", "tool", "tools", "fuzz", "fuzzer", "fuzzers",
    "corpus", "corpora", "protocol", "protocols", "spec", "specs",
}
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}
_EVIDENCE_SUFFIXES = _SOURCE_SUFFIXES | {
    ".json", ".yaml", ".yml", ".txt", ".md", ".pcap", ".pcapng", ".bin",
}
_AUTO_USAGE_TEXT_SUFFIXES = _SOURCE_SUFFIXES | {
    ".py", ".sh", ".pl", ".pm", ".t", ".rb", ".go", ".rs",
    ".java", ".js", ".ts", ".lua", ".md", ".txt", ".json",
    ".yaml", ".yml",
}


def discover_usage_artifacts(
    source_root: Path,
    analysis: AnalysisBundle,
    explicit_paths: Iterable[Path] = (),
    *,
    max_artifacts: int = 0,
) -> list[UsageArtifact]:
    """Inventory client/test/example evidence without changing Entry scope.

    This is a deterministic inventory.  It does not claim that a test is a
    valid scenario; it only makes project-authored request construction and
    ordering available as candidate evidence. Zero max_artifacts means the
    inventory has no count cutoff. A positive caller-selected count is an
    explicit resource budget, never a completeness claim.
    """

    if max_artifacts < 0:
        raise ValueError("max_artifacts cannot be negative")
    root = source_root.resolve()
    explicit_files: set[Path] = set()
    for raw in explicit_paths:
        path = raw.resolve()
        if path.is_file():
            explicit_files.add(path)
        elif path.is_dir():
            explicit_files.update(
                item.resolve()
                for item in path.rglob("*")
                if item.is_file() and item.suffix.casefold() in _EVIDENCE_SUFFIXES
            )

    functions_by_path: dict[Path, list[str]] = {}
    for function in analysis.functions.values():
        file_path = Path(function.file)
        if not file_path.is_absolute():
            file_path = root / file_path
        resolved = file_path.resolve()
        if _looks_like_usage_path(resolved, root) or resolved in explicit_files:
            functions_by_path.setdefault(resolved, []).append(function.function_id)

    candidate_paths = set(explicit_files) | set(functions_by_path)
    # Product functions are indexed from C/C++ source, but project-authored
    # clients and tests are often written in another language. Inventory
    # readable usage files by their role/path, without placing them in the
    # product call graph or treating their bytes as a proven request.
    tracked = _tracked_source_files(root)
    for candidate in (tracked if tracked is not None else root.rglob("*")):
        if (not candidate.is_file()
            or candidate.suffix.casefold() not in _AUTO_USAGE_TEXT_SUFFIXES
            or not _looks_like_usage_path(candidate, root)):
            continue
        resolved = candidate.resolve()
        if resolved.is_relative_to(root):
            candidate_paths.add(resolved)
    result: list[UsageArtifact] = []
    for path in sorted(candidate_paths, key=str):
        if max_artifacts and len(result) >= max_artifacts:
            break
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if path not in functions_by_path:
            # Non-indexed usage files are useful only if their text can be
            # inspected. Binary corpora require an explicit request fixture
            # or a format-aware decoder and are not silently treated as text.
            if b"\0" in data or not _utf8_text(data):
                continue
        relative = _display_path(path, root)
        result.append(UsageArtifact(
            path=relative,
            kind=_artifact_kind(path),
            function_ids=sorted(functions_by_path.get(path, [])),
            sha256=hashlib.sha256(data).hexdigest(),
            rationale=(
                "explicit scenario evidence supplied by the user"
                if path in explicit_files
                else "project-authored test/client/example path; candidate usage evidence only"
            ),
        ))
    return result


def _tracked_source_files(root: Path) -> list[Path] | None:
    """Prefer source-controlled examples over generated run output.

    A source tree without Git still uses the path-based inventory above.
    Git is an ownership filter for auto-discovered examples, never proof that
    their requests are valid or that untracked examples do not exist.
    """
    try:
        process = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z", "--cached", "--", "."],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=10, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if process.returncode != 0:
        return None
    return [root / name.decode("utf-8", errors="surrogateescape")
            for name in process.stdout.split(b"\0") if name]


def _utf8_text(data: bytes) -> bool:
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def relevant_usage_functions(
    artifacts: Iterable[UsageArtifact],
    analysis: AnalysisBundle,
    *,
    discriminators: Iterable[str],
    opened: Iterable[str],
    limit: int = 8,
) -> list[str]:
    """Rank project consumer functions for one action without fuzzy proof."""

    opened_set = set(opened)
    tokens = {
        token.casefold()
        for value in discriminators
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{1,}", value)
        if token.casefold() not in {"case", "cmd", "opcode"}
    }
    candidates: list[tuple[int, str]] = []
    seen: set[str] = set()
    for artifact in artifacts:
        for function_id in artifact.function_ids:
            if function_id in opened_set or function_id in seen:
                continue
            function = analysis.functions.get(function_id)
            if function is None:
                continue
            seen.add(function_id)
            source = function.source.casefold()
            score = 0
            score += 8 * sum(token in source for token in tokens)
            score += 4 * sum(
                marker in source
                for marker in (
                    "send(", "sendto(", "write(", "writev(", "request",
                    "packet", "opcode", "command", "expect", "assert",
                )
            )
            score += 2 if artifact.kind in {"test", "client", "fuzzer"} else 0
            if score:
                candidates.append((score, function_id))
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return [function_id for _score, function_id in candidates[:limit]]


def _looks_like_usage_path(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path
    parts = {part.casefold() for part in relative.parts[:-1]}
    stem = path.stem.casefold()
    return bool(parts & _USAGE_COMPONENTS) or bool(re.search(
        r"(?:^|[_-])(test|tests|client|example|sample|fuzz|fuzzer)(?:$|[_-])",
        stem,
    )) or stem.startswith(("test", "client", "example", "fuzz"))


def _artifact_kind(path: Path) -> str:
    lowered = "/".join(part.casefold() for part in path.parts)
    for kind in ("test", "client", "example", "fuzzer", "corpus", "protocol", "spec"):
        if kind in lowered:
            return kind
    return "user_evidence"


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
