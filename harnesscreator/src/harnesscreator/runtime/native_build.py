"""Independent, fail-closed Clang/libFuzzer builder for unregistered C/C++ projects.

Unlike the optional OSS-Fuzz recipe adapter, this module never looks inside
OSS-Fuzz's projects/ directory or builds an existing fuzzer. It compiles the
*generated* harness against original project translation units. Inferences
are intentionally bounded: ambiguous project layouts fail with a diagnostic
rather than choosing unrelated executables or treating compilation as proof.

For complex projects, users can supply an existing trusted --build-command and
--binary. That remains a supported way to reuse a project's actual build graph.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .build_closure import _compiler_output, resolve_cmake_target
from .make_closure import (
    MakeClosureUnresolved, resolve_make_target, resolve_recorded_make_target,
)

_SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx"}
_SKIP_FOLDERS = {"test", "tests", "testing", "example", "examples", "bench", "benchmark", "benchmarks", "vendor", "third_party", "third-party", ".git", "build", ".build", "_build"}
_MAIN_DEFINITION = re.compile(
    r"(?m)^\s*(?:int|signed|auto)\s+(?:\w+\s+)*main\s*\([^;{}]*\)\s*(?:\{|$)"
)


class NativeBuildUnresolved(RuntimeError):
    """The original project's required compile/link closure is not established."""


@dataclass(frozen=True)
class SourceUnit:
    source: Path
    flags: tuple[str, ...] = ()


def _inside(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _mirror_root(root: Path, db: Path) -> Path | None:
    """The directory the compile database was recorded in when it is a copy of `root`.

    A preparation script may build in a copy of the checkout so the checkout stays clean; the
    database then names files in the copy.  The copy also holds the generated headers the build
    made, so the harness is built there."""
    try:
        records = json.loads(db.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, dict):
            continue
        directory = Path(str(record.get("directory") or db.parent))
        src = Path(str(record.get("file") or ""))
        src = (src if src.is_absolute() else directory / src).resolve()
        if _inside(src, root) or not src.is_file():
            continue
        for candidate in src.parents:
            relative = src.relative_to(candidate)
            if (root / relative).is_file():
                return candidate
        return None
    return None


def _binary_closure(target_binary: Path, db: Path, root: Path) -> tuple[list[SourceUnit], Path | None]:
    """Translation units the executable was linked from, read from its DWARF compile units.

    The compile database lists every compilation of a build, including other programs (a bundled
    interpreter's own CLI) and test mains behind #ifdef.  The executable's debug information names
    exactly the sources linked into it, and `nm -l` names the file that defines its main()."""
    try:
        dump = subprocess.run(["readelf", "--debug-dump=info", "--dwarf-depth=1", str(target_binary)],
                              text=True, capture_output=True, timeout=300).stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NativeBuildUnresolved(f"cannot read debug information of {target_binary}: {exc}") from exc
    linked: set[Path] = set()
    for block in dump.split("Compilation Unit @")[1:]:
        name = re.search(r"DW_AT_name\s*:\s*(?:\(indirect[^)]*\):\s*)?(\S+)", block)
        comp_dir = re.search(r"DW_AT_comp_dir\s*:\s*(?:\(indirect[^)]*\):\s*)?(\S+)", block)
        if name:
            path = Path(name.group(1))
            if not path.is_absolute() and comp_dir:
                path = Path(comp_dir.group(1)) / path
            linked.add(path.resolve())
    if not linked:
        raise NativeBuildUnresolved(f"{target_binary} has no DWARF compile units; build it with -g")
    records = json.loads(db.read_text(encoding="utf-8"))
    units: dict[Path, SourceUnit] = {}
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, dict):
            continue
        directory = Path(str(record.get("directory") or db.parent)).resolve()
        src = Path(str(record.get("file") or ""))
        src = (src if src.is_absolute() else directory / src).resolve()
        if src in linked and _inside(src, root) and src.suffix.lower() in _SOURCE_EXTENSIONS:
            units[src] = SourceUnit(src, _flags_from_compile_record(record, directory))
    main_source = None
    try:
        symbols = subprocess.run(["nm", "-l", "--defined-only", str(target_binary)],
                                 text=True, capture_output=True, timeout=300).stdout
        found = re.search(r"(?m)^\S+\s+T\s+main\s+(\S+?):\d+\s*$", symbols)
        if found:
            main_source = Path(found.group(1)).resolve()
    except (OSError, subprocess.TimeoutExpired):
        pass
    return sorted(units.values(), key=lambda unit: str(unit.source)), main_source


def _find_compile_database(root: Path) -> Path | None:
    for path in (root / "compile_commands.json", root / "build" / "compile_commands.json", root / "out" / "build" / "compile_commands.json"):
        if path.is_file():
            return path
    return None


def _flags_from_compile_record(entry: dict, directory: Path) -> tuple[str, ...]:
    """Copy only safe, relevant C/C++ preprocessor/ABI switches.

    Compile databases can contain output commands, arbitrary -Xclang plugins,
    or other executable arguments. Never replay them verbatim.
    """
    tokens = entry.get("arguments")
    if not isinstance(tokens, list):
        command = entry.get("command")
        if not isinstance(command, str):
            return ()
        tokens = shlex.split(command)
    flags: list[str] = []
    index = 0
    path_options = {"-I", "-isystem", "-iquote", "-include", "-imacros"}
    text_options = {"-D", "-U"}
    while index < len(tokens):
        token = str(tokens[index])
        if token in path_options and index + 1 < len(tokens):
            index += 1
            value = Path(str(tokens[index]))
            if not value.is_absolute():
                value = (directory / value).resolve()
            flags.extend([token, str(value)])
        elif token.startswith("-I") and len(token) > 2:
            value = Path(token[2:])
            flags.append("-I" + str(value if value.is_absolute() else (directory / value).resolve()))
        elif token in text_options and index + 1 < len(tokens):
            index += 1
            flags.extend([token, str(tokens[index])])
        elif token.startswith(("-D", "-U")) and len(token) > 2:
            flags.append(token)
        elif token.startswith("-std=") or token in ("-pthread", "-fPIC", "-fpic", "-fno-exceptions", "-fexceptions", "-fno-rtti", "-frtti"):
            flags.append(token)
        # Unrecognized and plugin/driver flags are deliberately not copied.
        index += 1
    return tuple(flags)


def discover_source_units(
    root: Path, *, limit: int = 96, include_explicit_vendor: bool = False,
    compile_database: Path | None = None,
) -> tuple[list[SourceUnit], str]:
    root = root.resolve()
    db = compile_database or _find_compile_database(root)
    units: list[SourceUnit] = []
    if db:
        try:
            records = json.loads(db.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise NativeBuildUnresolved(f"invalid compile database {db}: {exc}") from exc
        if not isinstance(records, list):
            raise NativeBuildUnresolved("compile database must contain a JSON array")
        by_path: dict[Path, SourceUnit] = {}
        for record in records:
            if not isinstance(record, dict):
                continue
            directory = Path(record.get("directory") or db.parent).resolve()
            src = Path(str(record.get("file") or ""))
            if not src.is_absolute():
                src = directory / src
            src = src.resolve()
            if src.suffix.lower() not in _SOURCE_EXTENSIONS or not src.is_file() or not _inside(src, root):
                continue
            # A real build target is authoritative about its own vendor and
            # generated objects. Ignore test/vendor dirs only when guessing a
            # standalone root build without explicit link-target evidence.
            if (not include_explicit_vendor and
                any(name.lower() in _SKIP_FOLDERS for name in src.relative_to(root).parts[:-1])):
                continue
            by_path[src] = SourceUnit(src, _flags_from_compile_record(record, directory))
        units = list(sorted(by_path.values(), key=lambda unit: str(unit.source)))
        evidence = str(db)
    else:
        # Without a compilation database only accept small, uncomplicated
        # layouts. A single source directory is safer than guessing between
        # several project executables or vendored libraries.
        root_units = [p.resolve() for p in root.iterdir() if p.is_file() and p.suffix.lower() in _SOURCE_EXTENSIONS]
        src_units: list[Path] = []
        if (root / "src").is_dir():
            src_units = [p.resolve() for p in (root / "src").rglob("*") if p.is_file() and p.suffix.lower() in _SOURCE_EXTENSIONS and not any(part.lower() in _SKIP_FOLDERS for part in p.relative_to(root).parts[:-1])]
        if root_units and src_units:
            raise NativeBuildUnresolved(
                "source files span root and src/ without compile_commands.json; "
                "cannot infer one link target. Supply --build-command and --binary, "
                "or generate a compile_commands.json from the project's build system"
            )
        units = [SourceUnit(p) for p in sorted(root_units or src_units)]
        evidence = "small source layout (no compile database)"
    if not units:
        raise NativeBuildUnresolved(
            "no unambiguous C/C++ translation units found; supply an existing "
            "--build-command and --binary or compile_commands.json"
        )
    if len(units) > limit:
        raise NativeBuildUnresolved(
            f"{len(units)} translation units require a target-specific link closure; "
            "supply --build-command and --binary instead of compiling unrelated programs"
        )
    return units, evidence


def _main_units(units: list[SourceUnit]) -> list[Path]:
    found = []
    for unit in units:
        try:
            src = unit.source.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise NativeBuildUnresolved(f"cannot inspect {unit.source}: {exc}") from exc
        if _MAIN_DEFINITION.search(src):
            found.append(unit.source)
    return found


# sanitizer -> (compile -fsanitize, link -fsanitize, extra flags for both)
_SANITIZERS = {
    # -fsanitize=function (part of `undefined` since clang 17) reports every call through a cast
    # function pointer, an idiom C servers use for module and command tables (redis' RM_* API);
    # clang 14 never checked it in C, so it stays off to keep the reports comparable.
    "address+undefined": ("fuzzer-no-link,address,undefined", "fuzzer,address,undefined", ["-fno-sanitize=function"]),
    "memory": ("fuzzer-no-link,memory", "fuzzer,memory", ["-fsanitize-memory-track-origins=2"]),
}
# Measured on this WSL kernel (vm.mmap_rnd_bits=32): MemorySanitizer started 6/10 times with
# clang-14 and 12/20 with clang-15 ("out of application range ... can not mmap the shadow
# memory"), and 20/20 with clang-20.  Older clangs are not tried for MSan.
_MSAN_MIN_CLANG = 18


def _compilers(sanitizer: str) -> tuple[str | None, str | None]:
    """(cc, c++) for a sanitizer: HARNESSCREATOR_NATIVE_CC/CXX, else clang, else for MSan the
    newest versioned clang-N with N >= _MSAN_MIN_CLANG."""
    cc, cxx = os.environ.get("HARNESSCREATOR_NATIVE_CC"), os.environ.get("HARNESSCREATOR_NATIVE_CXX")
    if cc:
        return shutil.which(cc), shutil.which(cxx) if cxx else shutil.which(cc.replace("clang", "clang++"))
    # The newest installed clang: an old default clang may not compile current C (clang 14 rejects
    # redis' `static _Atomic(T*) x = NULL;`).
    for version in range(30, (_MSAN_MIN_CLANG if sanitizer == "memory" else 14) - 1, -1):
        found = shutil.which(f"clang-{version}")
        if found:
            return found, shutil.which(f"clang++-{version}")
    if sanitizer != "memory":
        return shutil.which("clang"), shutil.which("clang++")
    for version in range(30, _MSAN_MIN_CLANG - 1, -1):
        found = shutil.which(f"clang-{version}")
        if found:
            return found, shutil.which(f"clang++-{version}")
    return None, None


def build_native(
    source_root: Path, harness: Path, output: Path,
    *, compile_database: Path | None = None, target_binary: Path | None = None,
) -> Path:
    root = source_root.resolve(strict=True)
    harness = harness.resolve(strict=True)
    output = output.resolve()
    if not root.is_dir():
        raise NativeBuildUnresolved("source root is not a directory")
    if harness.suffix.lower() not in _SOURCE_EXTENSIONS:
        raise NativeBuildUnresolved("generated harness must be C or C++")
    # First discover the target's build evidence. A compile database alone
    # does not reveal which executable owns a translation unit, so we never
    # merge unrelated targets into one fuzzing binary.
    db = compile_database or _find_compile_database(root)
    if db is not None:
        mirror = _mirror_root(root, db)
        if mirror is not None:
            root = mirror.resolve()
    required_sources: set[Path] = set()
    hints_file = harness.parent / "harness-plan.json"
    if hints_file.is_file():
        try:
            hints = json.loads(hints_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise NativeBuildUnresolved(f"invalid harness source contract: {exc}") from exc
        if not isinstance(hints, dict):
            raise NativeBuildUnresolved("harness source contract must be an object")
        for value in hints.get("required_source_files", []):
            if not isinstance(value, str) or not value:
                raise NativeBuildUnresolved("invalid required source file in harness contract")
            path = Path(value)
            path = (path if path.is_absolute() else root / path).resolve()
            if not _inside(path, root) or not path.is_file():
                raise NativeBuildUnresolved(
                    f"harness requires a source file absent from the project: {value}"
                )
            required_sources.add(path)
    selected_target = resolve_cmake_target(
        root, db, required_sources, target_binary=target_binary,
    ) if db else None
    selected_make_target = None
    extra_link_flags: list[str] = []
    binary_main: Path | None = None
    linked_units: list[SourceUnit] | None = None
    if selected_target is None and db is not None and target_binary is not None:
        linked_units, binary_main = _binary_closure(target_binary.resolve(), db, root)
        if not linked_units:
            raise NativeBuildUnresolved(
                f"no compile-database record matches a translation unit linked into {target_binary}")
    if linked_units is not None:
        units = linked_units
        evidence = f"translation units linked into {target_binary} (DWARF) from {db}"
        # Libraries the project built without -g leave no compile unit behind (a bundled Lua, xxhash).
        # Its own static archives supply them; a linker takes an archive member only for a symbol
        # nothing else defines, so archives never duplicate the units compiled above.
        archives: dict[str, Path] = {}
        for archive in sorted(root.rglob("*.a"), key=lambda p: (len(p.parts), str(p))):
            archives.setdefault(archive.name, archive)
        if archives:
            extra_link_flags = ["-Wl,--start-group", *(str(a) for a in archives.values()), "-Wl,--end-group"]
    elif selected_target is not None:
        # CMake may compile the SAME source for several executable targets
        # with different macros, include directories, and ABI flags. Selecting
        # flags by filename (the former behavior) made the result dependent on
        # compile_commands.json record order. Choose compiler records by the
        # exact object files in this executable and its linked local archives.
        try:
            records = json.loads(db.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise NativeBuildUnresolved(f"invalid CMake compile database: {exc}") from exc
        if not isinstance(records, list):
            raise NativeBuildUnresolved("CMake compile database is not an array")
        selected_objects = set(selected_target.compile_objects)
        by_file: dict[Path, SourceUnit] = {}
        matched_objects: set[Path] = set()
        for record in records:
            if not isinstance(record, dict):
                continue
            directory = Path(record.get("directory") or db.parent).resolve()
            obj = _compiler_output(record, directory)
            if obj not in selected_objects:
                continue
            src = Path(str(record.get("file") or ""))
            src = (src if src.is_absolute() else directory / src).resolve()
            if not src.is_file() or not _inside(src, root):
                raise NativeBuildUnresolved(f"CMake target source unavailable: {src}")
            flags = _flags_from_compile_record(record, directory)
            prior = by_file.get(src)
            if prior is not None and prior.flags != flags:
                raise NativeBuildUnresolved(
                    f"CMake target compiles the same source with incompatible flags: {src}"
                )
            by_file[src] = SourceUnit(src, flags)
            matched_objects.add(obj)
        if matched_objects != selected_objects or set(by_file) != set(selected_target.source_paths):
            raise NativeBuildUnresolved(
                "CMake target compile object records incomplete or inconsistent"
            )
        units = [by_file[path] for path in sorted(by_file)]
        extra_link_flags = list(selected_target.linker_flags)
        evidence = (
            f"CMake target {selected_target.name} from "
            + ", ".join(str(p) for p in selected_target.evidence_files)
        )
    else:
        if db and (db.parent / "CMakeFiles").is_dir():
            raise NativeBuildUnresolved(
                "CMake compile/link records exist, but no uniquely attributable "
                "executable closure contains all required original sources"
            )
        try:
            selected_make_target = resolve_make_target(root, required_sources)
            if (selected_make_target is not None and target_binary is not None
                and (root / selected_make_target.name).resolve() != target_binary.resolve()):
                selected_make_target = None
            if selected_make_target is None:
                selected_make_target = resolve_recorded_make_target(
                    root, db, required_sources, target_binary=target_binary,
                )
        except MakeClosureUnresolved as exc:
            raise NativeBuildUnresolved(f"configured Makefile target is unresolved: {exc}") from exc
        if selected_make_target is not None:
            units = [SourceUnit(source, flags) for source, flags in selected_make_target.source_flags]
            extra_link_flags = list(selected_make_target.link_flags)
            evidence = f"configured Make target {selected_make_target.name} from {selected_make_target.evidence_file}"
        else:
            if target_binary is not None and any(
                (directory / name).is_file()
                for directory in (root, target_binary.resolve().parent)
                for name in ("Makefile", "makefile", "GNUmakefile")
            ):
                raise NativeBuildUnresolved(
                    "original executable has Makefile evidence, but no matching "
                    "source/object/link closure was established"
                )
            if db and len(discover_source_units(
                root, limit=1_000_000, compile_database=db,
            )[0]) > 96:
                raise NativeBuildUnresolved(
                    "compile database has no identifiable executable link target; "
                    "supply target-specific build evidence instead of combining unrelated programs"
                )
            units, evidence = discover_source_units(
                root, limit=96, compile_database=db,
            )
    if required_sources and not required_sources.issubset({u.source for u in units}):
        unresolved = sorted(str(p) for p in required_sources - {u.source for u in units})
        raise NativeBuildUnresolved(
            "build closure does not cover required Entry/handler sources: "
            + ", ".join(unresolved[:10])
        )
    mains = [binary_main] if linked_units is not None and binary_main in {u.source for u in units} else (
        [] if linked_units is not None and binary_main is None else _main_units(units))
    if len(mains) > 1:
        names = ", ".join(str(src.relative_to(root)) for src in mains[:8])
        raise NativeBuildUnresolved(
            f"multiple program main() definitions ({names}); cannot infer which executable's "
            "objects belong to the harness. Supply --build-command and --binary"
        )
    # Pure C projects must not require a C++ compiler. This includes the
    # generated harness, not just the original sources.
    contains_cpp = any(unit.source.suffix.lower() != ".c" for unit in [*units, SourceUnit(harness)])
    sanitizer = os.environ.get("HARNESSCREATOR_NATIVE_SANITIZER", "address+undefined")
    if sanitizer not in _SANITIZERS:
        raise NativeBuildUnresolved(f"unknown sanitizer {sanitizer!r}; choose one of {sorted(_SANITIZERS)}")
    compile_sanitizer, link_sanitizer, sanitizer_flags = _SANITIZERS[sanitizer]
    cc, cxx = _compilers(sanitizer)
    if not cc:
        raise NativeBuildUnresolved(
            "clang is required for the standalone libFuzzer builder"
            + (f"; MemorySanitizer needs clang >= {_MSAN_MIN_CLANG} (clang-14 and clang-15 cannot start on a "
               "kernel with vm.mmap_rnd_bits=32), set HARNESSCREATOR_NATIVE_CC" if sanitizer == "memory" else ""))
    if contains_cpp and not cxx:
        raise NativeBuildUnresolved("clang++ is required when building C++ translation units")
    scratch = output / ".native-build"
    scratch.mkdir(parents=True, exist_ok=True)
    binary = output / "hc-native-fuzzer"
    inputs = [*units, SourceUnit(harness)]
    compile_prefix = ["-O1", "-g", "-fno-omit-frame-pointer", f"-fsanitize={compile_sanitizer}", "-fPIC",
                      *sanitizer_flags]
    # Optional extra compile flags (e.g. -fno-inline so per-function coverage of
    # the built harness can be compared by function name with the original).
    compile_prefix += shlex.split(os.environ.get("HARNESSCREATOR_NATIVE_EXTRA_CFLAGS", ""))
    # A generated harness lives outside the product checkout. Expose headers
    # under the selected original source directories without assuming a
    # particular project name, or asking the model to invent include flags.
    source_include_dirs = sorted({str(root), *(str(unit.source.parent) for unit in units)})
    objects: list[str] = []
    plan = {
        "builder": "harnesscreator-native-clang",
        "source_root": str(root),
        "harness": str(harness),
        "binary": str(binary),
        "build_evidence": evidence,
        "selected_cmake_target": selected_target.name if selected_target else None,
        "selected_make_target": selected_make_target.name if selected_make_target else None,
        "source_contract_file": str(hints_file) if hints_file.is_file() else None,
        "required_source_files": sorted(str(p) for p in required_sources),
        "link_flags_from_build_graph": extra_link_flags,
        "original_sources": [str(unit.source) for unit in units],
        "renamed_main": [str(p) for p in mains],
        "compile_commands": [],
    }
    plan_file = scratch / "build-plan.json"
    for idx, unit in enumerate(inputs):
        obj = scratch / f"source-{idx}.o"
        compiler = cxx if unit.source.suffix.lower() != ".c" else cc
        argv = [compiler, *compile_prefix]
        for include_dir in source_include_dirs:
            argv.extend(["-I", include_dir])
        if str(unit.source.parent) not in source_include_dirs:
            argv.extend(["-I", str(unit.source.parent)])
        if unit.source in mains:
            argv.append("-Dmain=hc_native_original_main")
        argv.extend(unit.flags)
        argv.extend(["-c", str(unit.source), "-o", str(obj)])
        plan["compile_commands"].append(argv)
        plan_file.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            result = subprocess.run(argv, cwd=root, text=True, capture_output=True, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise NativeBuildUnresolved(f"compiler invocation failed for {unit.source}: {exc}") from exc
        if result.returncode:
            raise NativeBuildUnresolved(
                f"compilation failed for {unit.source} (exit {result.returncode}):\n"
                + (result.stdout + result.stderr)[-14000:]
            )
        objects.append(str(obj))
    linker = cxx if contains_cpp else cc
    link = [linker, *objects, f"-fsanitize={link_sanitizer}", *sanitizer_flags, "-pthread", "-lm", "-ldl",
            *extra_link_flags]
    # WSL's sanitizer runtime can intermittently fault before libFuzzer runs
    # with a PIE executable. A repeated 30-launch comparison on this target
    # produced 9 pre-main SIGSEGVs for PIE and none for the same objects
    # relinked without PIE. Restrict this linker workaround to WSL builds.
    # MemorySanitizer maps its shadow around a PIE executable and refuses to start without one.
    if sanitizer != "memory" and sys.platform == "linux" and "microsoft" in os.uname().release.casefold():
        link.append("-no-pie")
    link.extend(["-o", str(binary)])
    plan["link_command"] = link
    plan_file.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        result = subprocess.run(link, cwd=root, text=True, capture_output=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NativeBuildUnresolved(f"linker invocation failed: {exc}") from exc
    if result.returncode or not binary.is_file():
        raise NativeBuildUnresolved(
            f"link failed (exit {result.returncode}); likely unresolved project libraries/objects. "
            "Use the project's build graph via --build-command and --binary.\n"
            + (result.stdout + result.stderr)[-14000:]
        )
    return binary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Standalone Clang/libFuzzer builder; never uses OSS-Fuzz project recipes")
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compile-database", type=Path)
    parser.add_argument("--target-binary", type=Path)
    args = parser.parse_args(argv)
    try:
        path = build_native(
            args.source_root, args.harness, args.output,
            compile_database=args.compile_database,
            target_binary=args.target_binary,
        )
    except (OSError, NativeBuildUnresolved) as exc:
        print(f"NATIVE_BUILD_UNRESOLVED: {exc}", file=sys.stderr)
        return 2
    print(f"NATIVE_BUILD_OK: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
