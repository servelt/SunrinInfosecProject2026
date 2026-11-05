"""Evidence-bounded link closure from a *configured* Automake Makefile.

This parser intentionally does not run make, expand $(shell ...), or read
Makefile.am as if conditional sources were configured. The generated Makefile
provides source membership, local archive sources, and preprocessor/link flags.
Unknown expressions or ambiguous targets are NOT reconstructed by guessing.
"""
from __future__ import annotations

import re
import shlex
import json
from dataclasses import dataclass
from pathlib import Path


class MakeClosureUnresolved(ValueError):
    """Configured Makefile cannot prove the intended target's source closure."""


@dataclass(frozen=True)
class MakeTargetClosure:
    name: str
    source_flags: tuple[tuple[Path, tuple[str, ...]], ...]
    link_flags: tuple[str, ...]
    evidence_file: Path


def resolve_recorded_make_target(
    root: Path, compile_database: Path | None, required_sources: set[Path],
    *, target_binary: Path | None = None,
) -> MakeTargetClosure | None:
    """Recover a link closure from the Makefile used by recorded compilations.

    A compilation database describes translation units, not their final link.
    With one, every linked object must match a recorded compiler output.
    Without one, a simple generated Makefile must itself map every object to
    one source through an explicit pattern rule. This reads Makefile data;
    it never runs a recipe or expands make functions.
    """
    from .build_closure import _compiler_output
    from .native_build import _flags_from_compile_record

    root = root.resolve()
    by_directory: dict[Path, list[dict]] = {}
    if compile_database is not None:
        try:
            records = json.loads(compile_database.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise MakeClosureUnresolved(f"invalid compilation database: {exc}") from exc
        if not isinstance(records, list):
            raise MakeClosureUnresolved("compilation database must be an array")
        for record in records:
            if isinstance(record, dict):
                directory = Path(str(record.get("directory") or compile_database.parent)).resolve()
                if directory == root or root in directory.parents:
                    by_directory.setdefault(directory, []).append(record)
    else:
        # Source-only builds need an original link target. Search a bounded
        # project-local build layout, then demand unique target evidence.
        for makefile in root.rglob("makefile"):
            directory = makefile.parent.resolve()
            if len(directory.relative_to(root).parts) <= 3:
                by_directory[directory] = []
        for name in ("Makefile", "GNUmakefile"):
            for makefile in root.rglob(name):
                directory = makefile.parent.resolve()
                if len(directory.relative_to(root).parts) <= 3:
                    by_directory.setdefault(directory, [])
    target_binary = target_binary.resolve() if target_binary is not None else None
    candidates: list[MakeTargetClosure] = []
    for directory, group in by_directory.items():
        makefile = next(
            (directory / name for name in ("makefile", "Makefile", "GNUmakefile")
             if (directory / name).is_file()), None,
        )
        if makefile is None:
            continue
        source = makefile.read_text(encoding="utf-8", errors="replace")
        conditional_depth = 0
        conditional_link_definition = False
        for raw in source.splitlines():
            line = raw.strip()
            if line.startswith(("ifeq", "ifneq", "ifdef", "ifndef")):
                conditional_depth += 1
            elif line == "endif":
                conditional_depth = max(0, conditional_depth - 1)
            elif conditional_depth and (
                re.match(r"^(?:all|[A-Za-z0-9_.+-]+)\s*:", line)
                or (match := _ASSIGN.match(line)) is not None
                and match.group(1) in {"OBJS", "USER_OBJS", "LIBS"}
                or line.startswith(("include ", "-include "))
                and line.split(maxsplit=1)[-1] != "$(C_DEPS)"
            ):
                conditional_link_definition = True
                break
        if conditional_link_definition or conditional_depth:
            continue
        # Only literal, local fragments can affect the selected link command.
        # Variable-based include expansion is outside this static reader.
        fragments: list[Path] = []
        unsupported_include = False
        for raw in source.splitlines():
            match = re.match(r"^\s*-?include\s+(.+?)\s*$", raw)
            if not match:
                continue
            tokens = match.group(1).split()
            for token in tokens:
                if token == "$(C_DEPS)":
                    continue  # compiler dependency files do not define link inputs
                if "$" in token or any(char in token for char in "*?[]"):
                    unsupported_include = True
                    break
                fragment = (directory / token).resolve()
                if fragment != root and root not in fragment.parents:
                    unsupported_include = True
                    break
                if fragment.is_file():
                    fragments.append(fragment)
                elif not raw.lstrip().startswith("-include"):
                    unsupported_include = True
                    break
            if unsupported_include:
                break
        if unsupported_include:
            continue
        variables = _read_assignments(makefile)
        # This reader processes the literal includes in source order. A link
        # input redefined in the parent after an include would require full
        # GNU Make evaluation, so leave that layout unresolved.
        if any(name in variables for name in ("OBJS", "USER_OBJS", "LIBS")):
            continue
        conditional_fragment = False
        for fragment in fragments:
            for line in _logical_lines(fragment.read_text(encoding="utf-8", errors="replace")):
                if line.startswith(("ifeq", "ifneq", "ifdef", "ifndef", "else", "endif", "include ", "-include ")):
                    conditional_fragment = True
                    break
                match = _ASSIGN.match(line)
                if not match:
                    continue
                name, op, raw = match.groups()
                if op == "+=":
                    variables[name] = (variables.get(name, "") + " " + raw).strip()
                elif op == "?=":
                    variables.setdefault(name, raw)
                else:
                    variables[name] = raw
            if conditional_fragment:
                break
        if conditional_fragment:
            continue
        # Generated compiler dependency files may be included by Make. They
        # can affect the link closure only if they redefine variables or add
        # recipes; reject that case instead of assuming dependency-only data.
        if "$(C_DEPS)" in source:
            try:
                dependency_files = _words("C_DEPS", variables, directory)
            except MakeClosureUnresolved:
                continue
            if any(
                (not (directory / name).resolve().is_relative_to(root))
                or (path := (directory / name).resolve()).is_file() and any(
                    _ASSIGN.match(line) or line.startswith("\t")
                    or re.match(r"^\s*-?include\s+", line)
                    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
                )
                for name in dependency_files
            ):
                continue
        all_targets = re.findall(r"(?m)^all\s*:\s*([^#\n]+)$", source)
        if len(all_targets) != 1:
            continue
        names = all_targets[0].split()
        if len(names) != 1 or not re.fullmatch(r"[A-Za-z0-9_.+-]+", names[0]):
            continue
        target_name = names[0]
        if target_binary is not None and (directory / target_name).resolve() != target_binary:
            continue
        target_line = re.search(
            rf"(?m)^{re.escape(target_name)}\s*:[^\n]*\n((?:\t[^\n]*\n)+)",
            source,
        )
        if target_line is None:
            continue
        links: list[list[str]] = []
        for recipe in target_line.group(1).splitlines():
            recipe = recipe.lstrip("\t@-+").strip()
            if "$(shell" in recipe or "`" in recipe or ";" in recipe:
                continue
            try:
                expanded = _VAR.sub(
                    lambda m: _expand(m.group(1) or m.group(2), variables, directory),
                    recipe,
                )
                tokens = shlex.split(expanded)
            except (MakeClosureUnresolved, ValueError):
                continue
            if len(tokens) < 4 or Path(tokens[0]).name not in {
                "cc", "c++", "gcc", "g++", "clang", "clang++"
            } or "-o" not in tokens:
                continue
            output_index = tokens.index("-o")
            if output_index + 1 >= len(tokens) or Path(tokens[output_index + 1]).name != target_name:
                continue
            links.append(tokens)
        if len(links) != 1:
            continue
        link = links[0]
        output_index = link.index("-o")
        inputs = link[1:output_index] + link[output_index + 2:]
        object_paths: list[Path] = []
        library_tokens: list[str] = []
        saw_library = False
        for token in inputs:
            if token.endswith(".o"):
                if saw_library:
                    object_paths = []
                    break
                object_paths.append((directory / token).resolve())
            else:
                saw_library = True
                library_tokens.append(token)
        if not object_paths or len(object_paths) != len(set(object_paths)):
            continue
        try:
            link_flags, local_archives = _link_flags(library_tokens, directory, set())
        except MakeClosureUnresolved:
            continue
        if local_archives:
            continue
        object_to_source: dict[Path, tuple[Path, tuple[str, ...]]] = {}
        if compile_database is not None:
            for record in group:
                obj = _compiler_output(record, directory)
                if obj is None:
                    continue
                src = Path(str(record.get("file") or ""))
                src = (src if src.is_absolute() else directory / src).resolve()
                if not src.is_file() or (src != root and root not in src.parents):
                    continue
                if obj in object_to_source:
                    object_to_source.clear()
                    break
                object_to_source[obj] = (src, _flags_from_compile_record(record, directory))
        else:
            # Verify the source/object pairing against an actual make pattern
            # rule. A matching basename alone is not link evidence.
            rules: dict[str, tuple[str, tuple[str, ...]]] = {}
            ambiguous_rules: set[str] = set()
            for fragment in fragments:
                fragment_text = fragment.read_text(encoding="utf-8", errors="replace")
                for match in re.finditer(
                    r"(?m)^%\.o:\s*([^\s%]*)%\.(c|cc|cpp|cxx)\s*\n((?:\t[^\n]*\n)+)",
                    fragment_text,
                ):
                    suffix = match.group(2)
                    if suffix in rules or suffix in ambiguous_rules:
                        rules.pop(suffix, None)
                        ambiguous_rules.add(suffix)
                        continue
                    compiles: list[list[str]] = []
                    for recipe in match.group(3).splitlines():
                        recipe = recipe.lstrip("\t@-+").strip()
                        try:
                            expanded = _VAR.sub(
                                lambda m: _expand(m.group(1) or m.group(2), variables, directory),
                                recipe,
                            )
                            # Only the source/object automatic variables and
                            # a compiler dependency-file substitution remain.
                            residual = (expanded.replace("$(@:%.o=%.d)", "")
                                        .replace("$(@)", "")
                                        .replace("$@", "").replace("$<", ""))
                            if "$" in residual or "`" in residual or ";" in residual:
                                continue
                            tokens = shlex.split(expanded)
                        except (MakeClosureUnresolved, ValueError):
                            continue
                        if (
                            tokens and Path(tokens[0]).name in
                            {"cc", "c++", "gcc", "g++", "clang", "clang++"}
                            and "-c" in tokens and "-o" in tokens
                            and tokens[tokens.index("-o") + 1:tokens.index("-o") + 2]
                            in (["$@"], ["./$@"], [f"{match.group(1)}$@"])
                            and "$<" in tokens
                        ):
                            compiles.append(tokens)
                    if len(compiles) != 1:
                        ambiguous_rules.add(suffix)
                        continue
                    rules[suffix] = (
                        match.group(1),
                        _flags_from_compile_record({"arguments": compiles[0]}, directory),
                    )
            for obj in object_paths:
                matches: list[tuple[Path, tuple[str, ...]]] = []
                for suffix, (prefix, flags) in rules.items():
                    src = (directory / f"{prefix}{obj.stem}.{suffix}").resolve()
                    if src.is_file() and src.is_relative_to(root):
                        matches.append((src, flags))
                if len(matches) != 1:
                    object_to_source.clear()
                    break
                object_to_source[obj] = matches[0]
            listed_sources = {
                (directory / value).resolve()
                for key in ("C_SRCS", "CC_SRCS", "CPP_SRCS", "CXX_SRCS")
                for value in _words(key, variables, directory)
            }
            if listed_sources != {source for source, _ in object_to_source.values()}:
                continue
        if set(object_paths) != set(object_to_source):
            continue
        source_flags = tuple(object_to_source[obj] for obj in object_paths)
        sources = {source for source, _ in source_flags}
        if len(sources) != len(source_flags) or not required_sources.issubset(sources):
            continue
        candidates.append(MakeTargetClosure(
            target_name, source_flags, tuple(link_flags), makefile,
        ))
    if len(candidates) > 1:
        raise MakeClosureUnresolved(
            "ambiguous generated Makefile link targets: "
            + ", ".join(str(item.evidence_file) for item in candidates)
        )
    return candidates[0] if candidates else None


_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*)\s*(\+=|:=|\?=|=)\s*(.*)$")
_VAR = re.compile(r"\$\(([A-Za-z_][A-Za-z0-9_.-]*)\)|\$\{([A-Za-z_][A-Za-z0-9_.-]*)\}")
_SOURCE_EXT = {".c", ".cc", ".cpp", ".cxx"}
_ASSEMBLY_OR_GENERATED = {".s", ".S", ".l", ".y", ".ll", ".yy"}
_ALLOWED_COMPILER_SWITCHES = {"-pthread", "-fPIC", "-fpic", "-fno-exceptions", "-fexceptions", "-fno-rtti", "-frtti"}


def _logical_lines(data: str):
    pending = ""
    for raw in data.splitlines():
        if raw.startswith("\t"):
            continue  # Make recipe, never invoke it or parse assignments from it
        text = raw.strip()
        if text.endswith("\\"):
            pending += text[:-1].rstrip() + " "
            continue
        text = pending + text
        pending = ""
        # Autoconf emits comments with #; don't treat quoted '#' specially in
        # variable declarations (an actual # in -D string is uncommon).
        text = text.split(" #", 1)[0].strip()
        if text and not text.startswith("#"):
            yield text
    if pending:
        raise MakeClosureUnresolved("unfinished Makefile continuation")


def _read_assignments(makefile: Path) -> dict[str, str]:
    try:
        lines = list(_logical_lines(makefile.read_text(encoding="utf-8", errors="replace")))
    except OSError as exc:
        raise MakeClosureUnresolved(str(exc)) from exc
    variables: dict[str, str] = {}
    branching = 0
    for line in lines:
        if line.startswith(("ifeq ", "ifneq ", "ifdef ", "ifndef ", "ifeq(", "ifneq(")):
            branching += 1
            continue
        if line == "endif":
            branching = max(0, branching - 1)
            continue
        if line == "else" or line.startswith("else "):
            continue
        match = _ASSIGN.match(line)
        if not match:
            continue
        name, op, raw = match.groups()
        if branching:
            # Configured Automake Makefile normally has no conditional target
            # declarations. Never combine mutually exclusive branches.
            if name.endswith(("_PROGRAMS", "_LIBRARIES", "_SOURCES", "_LDADD")):
                raise MakeClosureUnresolved(f"conditional target variable {name} is unresolved")
            continue
        if op == "+=":
            variables[name] = variables.get(name, "") + " " + raw
        elif op == "?=":
            variables.setdefault(name, raw)
        else:
            variables[name] = raw
    return variables


def _expand(name: str, variables: dict[str, str], root: Path, seen: frozenset[str] = frozenset()) -> str:
    if name in seen:
        raise MakeClosureUnresolved(f"recursive Makefile variable: {name}")
    builtin = {"srcdir": str(root), "top_srcdir": str(root),
               "builddir": str(root), "top_builddir": str(root),
               "abs_srcdir": str(root), "abs_top_srcdir": str(root),
               "abs_builddir": str(root), "abs_top_builddir": str(root)}
    if name not in variables and name not in builtin:
        raise MakeClosureUnresolved(f"unresolved Makefile variable: {name}")
    value = variables.get(name, builtin.get(name, ""))
    # Do not execute arbitrary function expansion, shell, make automatic vars,
    # or $(var:old=new) substitutions. They cannot be statically proven.
    def replace(match: re.Match[str]) -> str:
        return _expand(match.group(1) or match.group(2), variables, root, seen | {name})
    value = _VAR.sub(replace, value)
    if "$" in value:
        raise MakeClosureUnresolved(f"unsupported Makefile expression in {name}: {value[:110]}")
    return value


def _words(name: str, variables: dict[str, str], root: Path) -> list[str]:
    if name not in variables:
        return []
    try:
        return shlex.split(_expand(name, variables, root))
    except ValueError as exc:
        raise MakeClosureUnresolved(f"unparseable {name}: {exc}") from exc


def _key(name: str) -> str:
    # Automake naming convention: `my-app` -> my_app;
    # `libsmall.a` -> libsmall_a.
    return re.sub(r"[^A-Za-z0-9_]", "_", Path(name).name)


def _sources(target: str, variables: dict[str, str], root: Path) -> list[Path]:
    sources: list[Path] = []
    for suffix in ("_SOURCES", "_nodist_SOURCES"):
        for token in _words(_key(target) + suffix, variables, root):
            src = Path(token)
            if src.suffix in _ASSEMBLY_OR_GENERATED:
                raise MakeClosureUnresolved(f"generated or assembler source needs a project build: {token}")
            if src.suffix.lower() not in _SOURCE_EXT:
                continue
            file = (src if src.is_absolute() else root / src).resolve()
            if not file.is_file() or (file != root and root not in file.parents):
                raise MakeClosureUnresolved(f"target {target} source unavailable: {token}")
            sources.append(file)
    if not sources:
        raise MakeClosureUnresolved(f"no compiled sources for target {target}")
    return list(dict.fromkeys(sources))


def _compile_flags(target: str, variables: dict[str, str], root: Path, source: Path) -> tuple[str, ...]:
    # Only data flags; filter out executable/compiler commands, response files,
    # and unknown switches. This list is *not* a re-execution of make recipes.
    from .native_build import _flags_from_compile_record

    args: list[str] = []
    language = ("CXXFLAGS", "AM_CXXFLAGS", _key(target) + "_CXXFLAGS") \
        if source.suffix.lower() in {".cc", ".cpp", ".cxx"} \
        else ("CFLAGS", "AM_CFLAGS", _key(target) + "_CFLAGS")
    for name in ("DEFS", "DEFAULT_INCLUDES", "INCLUDES", "CPPFLAGS", "AM_CPPFLAGS",
                 _key(target) + "_CPPFLAGS", *language):
        args.extend(_words(name, variables, root))
    return _flags_from_compile_record({"arguments": ["clang", *args]}, root)


def _link_flags(tokens: list[str], root: Path, local_libraries: set[str]) -> tuple[list[str], list[str]]:
    flags: list[str] = []
    archives: list[str] = []
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in local_libraries:
            archives.append(t)
        elif t in {"-l", "-L"} and i + 1 < len(tokens):
            i += 1
            flags.extend([t, tokens[i]])
        elif t.startswith("-l") and len(t) > 2:
            flags.append(t)
        elif t.startswith("-L") and len(t) > 2:
            p = Path(t[2:])
            flags.append("-L" + str(p if p.is_absolute() else (root / p).resolve()))
        elif t in {"-pthread", "-fopenmp"}:
            flags.append(t)
        elif t.endswith(".a"):
            # An external prebuilt archive is acceptable only if it exists;
            # users may still need a real build if this archive is stale.
            path = Path(t)
            src = (path if path.is_absolute() else root / path).resolve()
            if not src.is_file():
                raise MakeClosureUnresolved(f"unknown library archive: {t}")
            flags.append(str(src))
        elif t.endswith(".so"):
            src = Path(t)
            src = (src if src.is_absolute() else root / src).resolve()
            if not src.is_file():
                raise MakeClosureUnresolved(f"unknown shared library: {t}")
            flags.append(str(src))
        elif t.endswith(".la"):
            raise MakeClosureUnresolved("libtool .la dependencies need a project-native build")
        elif t.startswith("-Wl,") or t.startswith("-fuse-ld="):
            # Linker flags may alter source scope or cause arbitrary file reads.
            # Never copy them indiscriminately from a Makefile.
            raise MakeClosureUnresolved(f"unsupported linker switch: {t}")
        elif t in {"", "\\"}:
            pass
        else:
            raise MakeClosureUnresolved(f"unhandled link dependency: {t}")
        i += 1
    return flags, archives


def resolve_make_target(root: Path, required_sources: set[Path]) -> MakeTargetClosure | None:
    """Return a uniquely matched generated Makefile executable closure.

    None means no usable generated Makefile target metadata, not permission to
    treat all project files as one executable. Nonempty unresolved metadata
    raises MakeClosureUnresolved, exposing the actual missing build contract.
    """
    root = root.resolve()
    makefile = root / "Makefile"
    if not makefile.is_file():
        return None
    variables = _read_assignments(makefile)
    programs: dict[str, int] = {}
    for key in variables:
        if key.endswith("_PROGRAMS"):
            # Distinguish installed daemon executables from auxiliary debug
            # and test binaries using configured Automake metadata, never
            # project-specific names such as memcached or testapp.
            priority = 1 if key.startswith(("noinst_", "check_", "TESTS_")) else 2
            for name in _words(key, variables, root):
                programs[name] = max(priority, programs.get(name, 0))
    if not programs:
        return None
    local_libraries: set[str] = set()
    for key in variables:
        if key.endswith("_LIBRARIES"):
            local_libraries.update(_words(key, variables, root))
    possible: list[tuple[str, dict[Path, tuple[str, ...]], list[str]]] = []
    unresolved: list[str] = []
    for program in programs:
        try:
            sources: dict[Path, tuple[str, ...]] = {}
            flags: list[str] = []

            def add_target(target: str, visited: frozenset[str] = frozenset()):
                if target in visited:
                    raise MakeClosureUnresolved(f"recursive archive dependency: {target}")
                for source in _sources(target, variables, root):
                    source_flags = _compile_flags(target, variables, root, source)
                    if source in sources and sources[source] != source_flags:
                        raise MakeClosureUnresolved(f"conflicting compilation flags for {source}")
                    sources[source] = source_flags
                deps = []
                for name in ((_key(target) + "_LDADD"), (_key(target) + "_LIBADD")):
                    deps.extend(_words(name, variables, root))
                if target == program:
                    deps.extend(_words("LDADD", variables, root))
                    deps.extend(_words("LIBS", variables, root))
                external, nested = _link_flags(deps, root, local_libraries)
                flags.extend(external)
                for archive in nested:
                    add_target(archive, visited | {target})

            add_target(program)
            required = {p.resolve() for p in required_sources}
            if required and not required.issubset(sources):
                continue
            possible.append((program, sources, flags))
        except MakeClosureUnresolved as exc:
            unresolved.append(f"{program}: {exc}")
    if not possible:
        if unresolved:
            raise MakeClosureUnresolved("; ".join(unresolved[:5]))
        raise MakeClosureUnresolved("no generated-Makefile executable includes all required sources")
    if len(possible) > 1:
        best_priority = max(programs[name] for name, _, _ in possible)
        possible = [row for row in possible if programs[row[0]] == best_priority]
    if len(possible) != 1:
        raise MakeClosureUnresolved(
            "ambiguous generated-Makefile executables: "
            + ", ".join(name for name, _, _ in possible)
        )
    name, sources, flags = possible[0]
    return MakeTargetClosure(
        name=name,
        source_flags=tuple(sorted(sources.items())),
        link_flags=tuple(dict.fromkeys(flags)),
        evidence_file=makefile,
    )
