"""Target-scoped CMake build evidence for the native harness verifier.

Reconstruct translation-unit closures from *existing* CMake link.txt and
compile_commands.json. Never execute commands from either file and never infer
that a collection of unrelated sources constitutes one executable. Unknown
Make/Autotools and dynamically linked/whole-archive graphs remain unresolved.
"""
from __future__ import annotations

import json
import re
import shlex
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LinkTarget:
    name: str
    output: Path
    objects: tuple[Path, ...]
    local_archives: tuple[Path, ...]
    link_flags: tuple[str, ...]
    evidence_file: Path
    executable: bool


@dataclass(frozen=True)
class TargetClosure:
    name: str
    source_paths: tuple[Path, ...]
    linker_flags: tuple[str, ...]
    evidence_files: tuple[Path, ...]
    output: Path
    # Preserve exact .o identities. The same translation unit can be compiled
    # by two targets with different -D/-I options; per-path flags are unsafe.
    compile_objects: tuple[Path, ...] = ()


def _path(token: str, directory: Path) -> Path:
    p = Path(token)
    return (p if p.is_absolute() else directory / p).resolve()


def _compiler_output(record: dict, directory: Path) -> Path | None:
    raw = record.get("output")
    if raw:
        return _path(str(raw), directory)
    argv = record.get("arguments")
    if not isinstance(argv, list):
        try:
            argv = shlex.split(str(record.get("command", "")))
        except ValueError:
            return None
    for i, token in enumerate(argv):
        if token == "-o" and i + 1 < len(argv):
            return _path(str(argv[i + 1]), directory)
        if token.startswith("-o") and len(token) > 2:
            return _path(str(token[2:]), directory)
    return None


def _read_link_target(link_txt: Path, build_dir: Path) -> LinkTarget | None:
    try:
        text = link_txt.read_text(encoding="utf-8").strip()
        argv = shlex.split(text.replace("\n", " "))
    except (OSError, ValueError):
        return None
    if not argv:
        return None
    # A link.txt may contain a trailing ranlib command. Only the first command
    # is needed for static archives; never replay it.
    if "&&" in argv:
        argv = argv[:argv.index("&&")]
    is_archive = Path(argv[0]).name.lower() in {"ar", "llvm-ar", "gcc-ar"}
    output: Path | None = None
    if is_archive:
        output = next((_path(t, build_dir) for t in argv[1:]
                       if t.endswith(".a") and not t.startswith("-")), None)
    else:
        for i, token in enumerate(argv):
            if token == "-o" and i + 1 < len(argv):
                output = _path(argv[i + 1], build_dir)
                break
    if output is None:
        return None
    objects = tuple(_path(t, build_dir) for t in argv if t.endswith(".o") or t.endswith(".obj"))
    archives = tuple(_path(t, build_dir) for t in argv if t.endswith(".a") and _path(t, build_dir) != output)
    flags: list[str] = []
    # Reuse only linker arguments (never compiler/executable/ar commands).
    # Existing absolute libraries can be linked, but no CMake shell/control
    # tokens or linker plugins are imported.
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok in {"-L", "-l"} and i + 1 < len(argv):
            flags.extend([tok, argv[i + 1]])
            i += 2
            continue
        if tok.startswith("-L") and len(tok) > 2:
            flags.append("-L" + str(_path(tok[2:], build_dir)))
        elif tok.startswith("-l") and len(tok) > 2:
            flags.append(tok)
        elif tok in {"-pthread", "-fopenmp"}:
            flags.append(tok)
        elif tok.endswith((".a", ".so")) and _path(tok, build_dir) != output:
            # The archive closure will replace project-built .a inputs.
            flags.append(str(_path(tok, build_dir)))
        i += 1
    return LinkTarget(
        name=link_txt.parent.name.removesuffix(".dir"), output=output,
        objects=objects, local_archives=archives, link_flags=tuple(flags),
        evidence_file=link_txt, executable=not is_archive,
    )


def _closure_for_target(
    target: LinkTarget,
    by_output: dict[Path, Path],
    archive_targets: dict[Path, LinkTarget],
    seen_archives: set[Path] | None = None,
) -> tuple[set[Path], list[str], list[Path], set[Path]] | None:
    source_paths: set[Path] = set()
    object_paths: set[Path] = set()
    evidence: list[Path] = [target.evidence_file]
    flags = list(target.link_flags)
    for obj in target.objects:
        if obj not in by_output:
            # Compiler-only sources such as generated helpers are unknown;
            # do not silently claim an intact target closure.
            return None
        source_paths.add(by_output[obj])
        object_paths.add(obj)
    seen = seen_archives or set()
    for archive in target.local_archives:
        if archive in archive_targets:
            if archive in seen:
                return None
            nested = _closure_for_target(archive_targets[archive], by_output, archive_targets, seen | {archive})
            if nested is None:
                return None
            nested_sources, nested_flags, nested_evidence, nested_objects = nested
            source_paths.update(nested_sources)
            object_paths.update(nested_objects)
            evidence.extend(nested_evidence)
            flags = [x for x in flags if x != str(archive)]
            flags.extend(nested_flags)
        elif not archive.exists():
            return None
    return source_paths, flags, evidence, object_paths


def resolve_cmake_target(
    source_root: Path,
    database: Path,
    required_sources: set[Path],
    *, target_binary: Path | None = None,
) -> TargetClosure | None:
    """Return a uniquely attributable *executable* target or None.

    This is intentionally non-guessing. Compile databases alone list commands
    but not link grouping; if multiple targets match, callers must supply an
    explicit project build command instead of linking arbitrary sources.
    """
    build_dir = cmake_build_directory(database)
    if build_dir is None:
        return None
    cmake = build_dir / "CMakeFiles"
    try:
        records = json.loads(database.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(records, list):
        return None
    by_output: dict[Path, Path] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        directory = Path(record.get("directory") or build_dir).resolve()
        output = _compiler_output(record, directory)
        source = _path(str(record.get("file") or ""), directory)
        if output is not None and source.is_file() and source_root.resolve() in source.parents:
            by_output[output] = source
    targets = [t for p in cmake.rglob("link.txt") if (t := _read_link_target(p, build_dir))]
    archives = {t.output: t for t in targets if not t.executable}
    candidates: list[tuple[int, LinkTarget, set[Path], list[str], list[Path], set[Path]]] = []
    for target in targets:
        if not target.executable:
            continue
        if target_binary is not None and target.output != target_binary.resolve():
            continue
        closure = _closure_for_target(target, by_output, archives)
        if closure is None:
            continue
        sources, flags, evidence, objects = closure
        overlap = len(sources & required_sources)
        if required_sources and (not overlap or not required_sources.issubset(sources)):
            continue
        candidates.append((overlap, target, sources, flags, evidence, objects))
    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    highest = candidates[0][0]
    best = [item for item in candidates if item[0] == highest]
    if len(best) != 1:
        return None
    _, target, sources, flags, evidence, objects = best[0]
    return TargetClosure(
        target.name, tuple(sorted(sources)), tuple(dict.fromkeys(flags)),
        tuple(dict.fromkeys(evidence)), target.output, tuple(sorted(objects)),
    )


def cmake_build_directory(database: Path) -> Path | None:
    """Locate a unique CMake link graph for compiler records in a database.

    Bear can save compile_commands.json outside the build directory. A
    compiler record's working directory points into the real build, whereas
    the database file's parent need not. Several matching build trees are
    ambiguous and must not be collapsed into one target.
    """
    database = database.resolve()
    if (database.parent / "CMakeFiles").is_dir():
        return database.parent
    try:
        records = json.loads(database.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(records, list):
        return None
    candidates: set[Path] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        raw_directory = record.get("directory")
        if not isinstance(raw_directory, str) or not raw_directory:
            continue
        directory = Path(raw_directory).resolve()
        for ancestor in (directory, *directory.parents):
            if ((ancestor / "CMakeFiles").is_dir()
                and (ancestor / "CMakeCache.txt").is_file()):
                candidates.add(ancestor)
                break
    return next(iter(candidates)) if len(candidates) == 1 else None
