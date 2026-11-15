"""Conservative source membership from a simple included GNU Make target.

This is a target-scope provider, not a Make interpreter.  Unsupported syntax
returns no scope; project recipes and make functions are never executed.
"""

from __future__ import annotations

import re
import shlex
import json
import subprocess
from pathlib import Path
from typing import Any


_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(\+=|:=|=)\s*(.*)$")
_INCLUDE = re.compile(r"^(-?include)\s+(.+)$")
_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}


def linked_make_sources(
    binary: Path, source_root: Path, compile_database: Path | None = None,
) -> dict[str, Any]:
    """Recognize an exact executable/object/source closure or return unknown.

    The binary must sit next to its makefile, its target must link precisely
    the listed objects, and each object must map one-to-one to a listed source.
    This proves the configured target's source list, not byte identity between
    an arbitrary pre-existing binary and that target.
    """

    report: dict[str, Any] = {
        "status": "unresolved", "source_files": [],
        "policy": "unknown or unsupported Make syntax never excludes source",
    }
    binary = binary.expanduser().resolve()
    source_root = source_root.expanduser().resolve()
    if not binary.is_file() or not binary.is_relative_to(source_root):
        report["reason"] = "binary is absent or outside the source tree"
        return report
    makefile = next((p for p in (
        binary.parent / "makefile", binary.parent / "Makefile",
    ) if p.is_file()), None)
    if makefile is None:
        report["reason"] = "no adjacent configured Makefile"
        return report

    variables: dict[str, str] = {}
    target_prerequisites: list[str] = []
    target_recipes: list[str] = []
    seen_files: set[Path] = set()
    in_target = False
    conditional_depth = 0
    included_headers: set[str] = set()

    def words(value: str) -> list[str]:
        return shlex.split(value)

    def read_file(path: Path) -> None:
        nonlocal in_target, target_prerequisites, conditional_depth
        path = path.resolve()
        if path in seen_files:
            return
        if not path.is_relative_to(source_root):
            raise ValueError("include escapes source tree")
        seen_files.add(path)
        raw = path.read_text(encoding="utf-8", errors="replace")
        logical = re.sub(r"\\\r?\n", " ", raw)
        for line in logical.splitlines():
            if line.startswith("\t"):
                if in_target:
                    target_recipes.append(line.strip())
                continue
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            in_target = False
            include = _INCLUDE.match(line)
            if include:
                if conditional_depth and include.group(2).strip() != "$(C_DEPS)":
                    raise ValueError("conditional Make include changes target scope")
                for token in words(include.group(2).split("#", 1)[0]):
                    # Generated dependency files only declare header
                    # prerequisites. Inspect them separately below.
                    if token == "$(C_DEPS)":
                        continue
                    if "$" in token or any(c in token for c in "*?[]"):
                        raise ValueError("dynamic Make include")
                    included = (makefile.parent / token).resolve()
                    if included.is_file():
                        read_file(included)
                    elif include.group(1) == "include":
                        raise ValueError("required Make include is absent")
                continue
            match = _ASSIGN.match(line)
            if match:
                name, op, value = match.groups()
                if name in {"C_SRCS", "CXX_SRCS", "CPP_SRCS", "OBJS", "USER_OBJS", "C_DEPS", "LIBS"}:
                    if conditional_depth:
                        raise ValueError("conditional source/object variable")
                    if "$" in value:
                        raise ValueError("dynamic target source/object variable")
                    variables[name] = (variables.get(name, "") + " " + value).strip() if op == "+=" else value
                continue
            if line.startswith(("ifeq", "ifneq", "ifdef", "ifndef")):
                # Conditions may change the target closure; only the common
                # generated dependency-file guard is handled below.
                if "$(C_DEPS)" not in line and "$(MAKECMDGOALS),clean" not in line:
                    raise ValueError("conditional Make target membership")
                conditional_depth += 1
                continue
            if line == "else":
                raise ValueError("conditional Make branch is unsupported")
            if line == "endif":
                conditional_depth -= 1
                if conditional_depth < 0:
                    raise ValueError("unbalanced Make condition")
                continue
            rule = re.match(r"^([^:#]+):\s*(.*)$", line)
            if rule and rule.group(1).strip() == binary.name:
                if conditional_depth:
                    raise ValueError("conditional executable target rule")
                if target_prerequisites:
                    raise ValueError("multiple executable target rules")
                target_prerequisites = words(rule.group(2).split("#", 1)[0])
                in_target = True

    try:
        read_file(makefile)
        if conditional_depth:
            raise ValueError("unbalanced Make condition")
        for token in words(variables.get("C_DEPS", "")):
            dependency_file = (makefile.parent / token).resolve()
            if (dependency_file.suffix != ".d"
                or not dependency_file.is_relative_to(source_root)):
                raise ValueError("unrecognized generated dependency file")
            if dependency_file.is_file():
                dependency_text = dependency_file.read_text(
                    encoding="utf-8", errors="replace",
                )
                for line in re.sub(r"\\\r?\n", " ", dependency_text).splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and not re.match(
                        r"^[^:=]+:\s*[^:=]*$", line,
                    ):
                        raise ValueError("generated dependency file has Make logic")
                    if ":" in line:
                        for dependency in words(line.split(":", 1)[1]):
                            header = (makefile.parent / dependency).resolve()
                            if (header.is_file()
                                and header.is_relative_to(source_root)
                                and header.suffix.lower() in {
                                    ".h", ".hh", ".hpp", ".hxx",
                                }):
                                included_headers.add(
                                    header.relative_to(source_root).as_posix()
                                )
        if target_prerequisites != ["$(OBJS)", "$(USER_OBJS)"]:
            raise ValueError("target does not list exactly OBJS and USER_OBJS")
        if variables.get("USER_OBJS", "").strip():
            raise ValueError("unmapped user objects")
        sources = words(" ".join(variables.get(name, "") for name in (
            "C_SRCS", "CXX_SRCS", "CPP_SRCS",
        )))
        objects = words(variables.get("OBJS", ""))
        if (not sources or len(sources) != len(objects)
            or len(set(objects)) != len(objects)):
            raise ValueError("source/object count is incomplete")
        link_recipes = []
        for recipe in target_recipes:
            tokens = words(recipe)
            if "-o" in tokens and tokens.index("-o") + 1 < len(tokens) \
                    and tokens[tokens.index("-o") + 1] == binary.name:
                link_recipes.append(tokens)
        if len(link_recipes) != 1 or not all(
            token in link_recipes[0]
            for token in ("$(OBJS)", "$(USER_OBJS)")
        ):
            raise ValueError("link recipe does not use the declared objects")
        if any(
            token.startswith("@") or
            (token.startswith("$(") and token not in {
                "$(OBJS)", "$(USER_OBJS)", "$(LIBS)",
            }) or
            Path(token).suffix.lower() in {
                ".o", ".a", ".so", *_SOURCE_SUFFIXES,
            }
            for token in link_recipes[0]
        ):
            raise ValueError("link recipe has an unmapped input")
        resolved_sources: list[str] = []
        for source, obj in zip(sources, objects):
            src = (makefile.parent / source).resolve()
            if (src.suffix.lower() not in _SOURCE_SUFFIXES
                or Path(obj).suffix != ".o"
                or Path(obj).stem != src.stem
                or not src.is_file()
                or not src.is_relative_to(source_root)):
                raise ValueError("object/source mapping is ambiguous")
            resolved_sources.append(src.relative_to(source_root).as_posix())
        if len(set(resolved_sources)) != len(resolved_sources):
            raise ValueError("duplicate source/object mapping")
        # A local archive or search path could pull additional project source
        # into the executable. Such targets require a real link map.
        libs = words(variables.get("LIBS", ""))
        if any(not token.startswith("-l") for token in libs):
            raise ValueError("local or nonstandard link input needs a link map")
        for relative in [*resolved_sources, *included_headers]:
            included_file = source_root / relative
            if re.search(
                r'^\s*#\s*include\s*[<\"][^>\"]+\.(?:c|cc|cpp|cxx)[>\"]',
                included_file.read_text(encoding="utf-8", errors="replace"),
                re.MULTILINE,
            ):
                raise ValueError("compiled source includes another source unit")
    except (OSError, ValueError) as exc:
        report["reason"] = str(exc)
        if compile_database is not None:
            alternative = _configured_automake_sources(
                binary, source_root, makefile, compile_database,
            )
            if alternative["status"] != "unresolved":
                return alternative
            report["alternative_reason"] = alternative.get("reason", "")
        return report
    report.update({
        "status": "configured_target_closure",
        "source_files": [*resolved_sources, *sorted(included_headers)],
        "makefiles": [str(path) for path in sorted(seen_files)],
        "target": binary.name,
        "policy": (
            "configured Make target lists these source units; this does not "
            "prove that the supplied binary was built from this revision"
        ),
    })
    return report


_MAKE_REFERENCE = re.compile(r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)|\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _configured_automake_sources(
    binary: Path, source_root: Path, makefile: Path, compile_database: Path,
) -> dict[str, Any]:
    """Read a configured Automake target without evaluating Make recipes.

    Every direct object must match an entry in the captured compilation DB.
    Local static archives are conservatively expanded to all member source
    files; unknown members or link inputs make the closure unresolved.
    """
    report: dict[str, Any] = {
        "status": "unresolved", "source_files": [],
        "policy": "configured target sources; local archive members overapproximated",
    }
    try:
        raw = re.sub(r"\\\r?\n", " ", makefile.read_text(
            encoding="utf-8", errors="replace",
        ))
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.startswith(("include ", "-include ", "sinclude ")):
                if ("# am--include-marker" not in stripped
                    or ".Po" not in stripped):
                    raise ValueError("uninspected Make include may change target objects")
        target = re.sub(r"[^A-Za-z0-9_]", "_", binary.name)
        object_variable = f"{target}_OBJECTS"
        source_variable = f"{target}_SOURCES"
        link_variable = f"{target}_LDADD"
        rule = re.search(
            rf"^{re.escape(binary.name)}(?:\$\(EXEEXT\))?:\s*([^\n]*)\n((?:\t[^\n]*\n)+)",
            raw, re.MULTILINE,
        )
        if (rule is None or f"$({object_variable})" not in rule.group(1)
            or f"$({object_variable})" not in rule.group(2)):
            raise ValueError("configured executable rule does not link its target object variable")
        link_line = next((line for line in rule.group(2).splitlines()
                          if f"$({object_variable})" in line), "")
        if (f"$({link_variable})" not in link_line
            or "$(LIBS)" not in link_line
            or re.search(r"(?:^|\s)\S+\.(?:o|a|so)(?:\s|$)", link_line)):
            raise ValueError("executable recipe has unaccounted link inputs")
        variables: dict[str, str] = {}
        for line in raw.splitlines():
            if not line or line[0].isspace() or line.startswith("#"):
                continue
            match = _ASSIGN.match(line)
            if match:
                name, operator, value = match.groups()
                if operator == "+=":
                    variables[name] = (variables.get(name, "") + " " + value).strip()
                else:
                    variables[name] = value

        def expand(name: str, stack: frozenset[str] = frozenset()) -> str:
            if name in stack:
                raise ValueError(f"recursive Make variable {name}")
            value = variables.get(name)
            if value is None:
                # Automake comments out disabled conditional append variables.
                if (re.fullmatch(r"am__(?:append|objects)_\d+", name)
                    or name in {"AM_CFLAGS", "AM_CXXFLAGS", "AM_LDFLAGS"}):
                    return ""
                raise ValueError(f"undefined Make variable {name}")
            if name == f"{target}_LINK":
                # Automake's automatic target is an output, not an input.
                value = value.replace("$@", binary.name)
            result = _MAKE_REFERENCE.sub(
                lambda item: expand(item.group(1) or item.group(2), stack | {name}),
                value,
            )
            if "$" in result or "`" in result or "$(" in result:
                raise ValueError(f"unsupported Make expression in {name}")
            return result

        objects = shlex.split(expand(object_variable))
        declared_sources = shlex.split(expand(source_variable))
        if not objects or len(set(objects)) != len(objects):
            raise ValueError("target object list is empty or ambiguous")
        object_paths = {(makefile.parent / item).resolve() for item in objects}
        if any(path.suffix != ".o" or not path.is_relative_to(source_root)
               for path in object_paths):
            raise ValueError("target object is not a local object file")

        records = json.loads(compile_database.read_text(encoding="utf-8"))
        if not isinstance(records, list):
            raise ValueError("compilation database is not a list")
        output_to_source: dict[Path, Path] = {}
        for item in records:
            if not isinstance(item, dict):
                continue
            directory = Path(str(item.get("directory") or source_root)).resolve()
            output = str(item.get("output") or "")
            if not output:
                arguments = item.get("arguments") or []
                if isinstance(arguments, list) and "-o" in arguments:
                    position = arguments.index("-o")
                    if position + 1 < len(arguments):
                        output = str(arguments[position + 1])
            if not output:
                continue
            object_path = (directory / output).resolve()
            source_path = (directory / str(item.get("file") or "")).resolve()
            if object_path in object_paths:
                if (object_path in output_to_source
                    and output_to_source[object_path] != source_path):
                    raise ValueError("one target object has multiple source units")
                output_to_source[object_path] = source_path
        if set(output_to_source) != object_paths:
            raise ValueError("compilation database does not cover every target object")
        direct_sources = set(output_to_source.values())
        declared_c = {
            (makefile.parent / item).resolve() for item in declared_sources
            if Path(item).suffix.lower() in _SOURCE_SUFFIXES
        }
        if direct_sources != declared_c:
            raise ValueError("target source list and compiled object sources disagree")

        local_archive_sources: set[Path] = set()
        configured_link = f"{target}_LINK"
        if configured_link in variables:
            link_tokens = shlex.split(expand(configured_link))
            if any(Path(token).suffix in {".o", ".a", ".so"}
                   for token in link_tokens):
                raise ValueError("configured linker command has an unmapped input")
        for flag_variable in ("LIBS", "LDFLAGS", f"{target}_LDFLAGS"):
            if flag_variable not in variables:
                continue
            flags = shlex.split(expand(flag_variable))
            if any(Path(flag).suffix in {".o", ".a", ".so"} for flag in flags):
                raise ValueError("link flags contain an unaccounted object or library")
            if (any(flag.startswith("-L") and flag[2:] and
                    (makefile.parent / flag[2:]).resolve().is_relative_to(source_root)
                    for flag in flags)
                and any(flag.startswith("-l") for flag in flags)):
                raise ValueError("local library search path requires a linker map")
        link_inputs = shlex.split(expand(link_variable)) if link_variable in variables else []
        for item in link_inputs:
            if item.startswith(("-l", "-L", "-Wl,")):
                continue
            archive = (makefile.parent / item).resolve()
            if (archive.suffix != ".a" or not archive.is_file()
                or not archive.is_relative_to(source_root)):
                raise ValueError("unmapped target link input")
            listing = subprocess.run(
                ["ar", "t", str(archive)], text=True, capture_output=True,
                timeout=10, check=True,
            ).stdout.splitlines()
            if not listing:
                raise ValueError("local static archive is empty")
            for member in listing:
                if Path(member).suffix != ".o":
                    raise ValueError("non-object member in local static archive")
                matches = [archive.parent / (Path(member).stem + suffix)
                           for suffix in _SOURCE_SUFFIXES]
                matches = [path.resolve() for path in matches if path.is_file()]
                if len(matches) != 1 or not matches[0].is_relative_to(source_root):
                    raise ValueError("static archive member has ambiguous source")
                local_archive_sources.add(matches[0])
        sources = direct_sources | local_archive_sources
        for source in sources:
            if (not source.is_file() or not source.is_relative_to(source_root)
                or source.suffix.lower() not in _SOURCE_SUFFIXES):
                raise ValueError("target source is outside the selected source tree")
            if re.search(
                r'^\s*#\s*include\s*[<\"][^>\"]+\.(?:c|cc|cpp|cxx)[>\"]',
                source.read_text(encoding="utf-8", errors="replace"),
                re.MULTILINE,
            ):
                raise ValueError("compiled source includes another source unit")
        report.update({
            "status": "configured_target_closure",
            "source_files": sorted(path.relative_to(source_root).as_posix()
                                   for path in sources),
            "target": binary.name,
            "makefiles": [str(makefile)],
            "compile_database": str(compile_database),
            "archive_membership": "all local members retained as a conservative superset",
            "policy": (
                "configured Automake target objects match the captured compilation database; "
                "local archive members are overapproximated; binary byte identity is unproven"
            ),
        })
    except (OSError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        report["reason"] = str(exc)
    return report
