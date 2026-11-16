"""Early, non-blocking capability report for an arbitrary C/C++ source tree.

A missing tool can block a particular verifier, not erase a source Entry.
This report is written before any costly source analysis or LLM call.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from ..models import ProjectSpec
from .native_build import _find_compile_database
from .build_closure import cmake_build_directory


def _original_target_binary(project: ProjectSpec) -> Path | None:
    if not project.scenario_command:
        return None
    root = project.source_root.resolve()
    value = Path(project.scenario_command[0])
    path = (value if value.is_absolute() else root / value).resolve()
    return path if path.is_file() and path.is_relative_to(root) else None


def source_analysis_binary(project: ProjectSpec) -> Path | None:
    """Use the explicitly selected binary, or the original in-tree executable.

    A launcher outside the source tree cannot identify this checkout's build
    target and must not silently become an AST ordering hint.
    """
    return project.analysis_binary or _original_target_binary(project)


def _embedded_gdb_line_info(binary: Path | None) -> bool | None:
    """Report in-file ELF line tables; external debug files remain unknown."""
    if binary is None or not binary.is_file():
        return None
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.common.exceptions import ELFError
    except ImportError:
        return None
    try:
        with binary.open("rb") as stream:
            return ELFFile(stream).get_section_by_name(".debug_line") is not None
    except (OSError, ValueError, ELFError):
        return None


def inspect_capabilities(project: ProjectSpec) -> dict[str, object]:
    tools = {
        name: shutil.which(name)
        for name in ("clang", "clang++", "cmake", "make", "ninja", "gdb")
    }
    root: Path = project.source_root
    db = project.analysis_compile_database or _find_compile_database(root)
    target_binary = _original_target_binary(project)
    generated_makefile = (root / "Makefile").is_file()
    recorded_makefile: Path | None = None
    if native_build := any("harnesscreator.runtime.native_build" in token for token in project.build_command):
        from .make_closure import MakeClosureUnresolved, resolve_recorded_make_target
        try:
            closure = resolve_recorded_make_target(
                root, db, set(), target_binary=target_binary,
            )
        except (MakeClosureUnresolved, OSError):
            closure = None
        if closure is not None:
            recorded_makefile = closure.evidence_file
    build_markers = [
        name for name in ("CMakeLists.txt", "Makefile", "Makefile.am", "configure", "meson.build")
        if (root / name).exists()
    ]
    command = project.scenario_command
    runtime_exe = (
        (shutil.which(command[0]) if "/" not in command[0] else
         str(Path(command[0]).resolve()) if Path(command[0]).is_file() else None)
        if command else None
    )
    gdb_embedded_lines = _embedded_gdb_line_info(
        Path(runtime_exe) if runtime_exe else None
    ) if project.scenario_attribution == "gdb" else None
    blockers = []
    if native_build and (not tools["clang"] or not tools["clang++"]):
        blockers.append("NATIVE_BUILD_TOOLCHAIN_MISSING: clang and clang++ are required")
    if command and not runtime_exe:
        blockers.append("ORIGINAL_EXECUTABLE_NOT_FOUND")
    if not command:
        blockers.append("ORIGINAL_EXECUTION_UNCONFIGURED: source drafts only; not runtime proof")
    # GDB's process-wide breakpoint order does not identify the request whose
    # bytes selected a handler. The strict runtime verifier already refuses
    # this promotion; report the inevitable qualification blocker before
    # any model or source-analysis work is scheduled.
    if command and project.scenario_attribution == "gdb":
        blockers.append(
            "EXACT_REQUEST_ATTRIBUTION_UNAVAILABLE: GDB breakpoint order cannot "
            "establish request-to-handler causality; this run can produce "
            "source or exploratory drafts, but not a qualified harness. "
            "Request-correlated instrumentation is required for strict proof"
        )
        if project.scenario_exploratory_drafts and gdb_embedded_lines is False:
            blockers.append(
                "GDB_SOURCE_LINES_NOT_EMBEDDED: the selected original executable "
                "has no embedded DWARF line table, so file:line acquisition "
                "breakpoints may not resolve. A separate debug file may still "
                "supply the lines; verify it with GDB before a long run"
            )
    # The native OSS-Fuzz adapter intentionally returns qualified=False even
    # after a clean build and smoke run. It has no exact target-reach or
    # original/harness differential verifier. Report this before model work;
    # otherwise a user can spend hours analyzing Actions for an outcome this
    # selected backend cannot produce. This is a backend capability, not a
    # reason to discard source candidates or skip explicit smoke testing.
    if project.verification_backend == "oss-fuzz":
        blockers.append(
            "OSS_FUZZ_NATIVE_DIAGNOSTIC_ONLY: the selected adapter can build "
            "and smoke-test a harness, but currently cannot mark it QUALIFIED; "
            "exact target reach and original/harness equivalence are not verified"
        )
    if (native_build and not db and not generated_makefile
        and recorded_makefile is None and len(build_markers) > 0):
        blockers.append(
            "BUILD_GRAPH_NOT_CAPTURED: no compile database or configured Makefile; "
            "configure the project or supply a trusted build command"
        )
    return {
        "policy": "non-blocking; retain source candidates even when verification dependencies are unavailable",
        "tools": tools,
        "source_root": str(root),
        "build_system_markers": build_markers,
        "compile_database": str(db) if db else None,
        "configured_makefile": (
            str(root / "Makefile") if generated_makefile else
            str(recorded_makefile) if recorded_makefile else None
        ),
        "native_build_selected": native_build,
        "original_execution_configured": bool(command),
        "original_executable_available": bool(runtime_exe),
        "gdb_embedded_line_info": gdb_embedded_lines,
        "strict_request_attribution_configured": (
            bool(command) and project.scenario_attribution == "trace"
        ),
        "strict_request_attribution_note": (
            "trace mode is only a configured contract; the original binary "
            "must actually emit request-correlated acquisition, handler, "
            "and result events before runtime proof is available"
            if project.scenario_attribution == "trace" else
            "GDB breakpoint order has no request identity"
        ),
        "verification_blockers": blockers,
    }


def inspect_build_closure_for_plan(project: ProjectSpec, plan: "HarnessPlan") -> dict[str, object]:
    """Non-building, non-blocking target-specific readiness assessment.

    This runs BEFORE spending harness-generation model turns. It is only an
    early diagnosis: static make/CMake evidence is not a successful link and
    never changes candidate proof or final qualification.
    """
    from ..models import HarnessPlan
    from .build_closure import resolve_cmake_target
    from .make_closure import (
        MakeClosureUnresolved, resolve_make_target, resolve_recorded_make_target,
    )
    from .native_build import NativeBuildUnresolved, discover_source_units

    record: dict[str, object] = {
        "plan_id": plan.plan_id,
        "action_id": plan.target_action_id,
        "required_source_files": list(plan.required_source_files),
        "status": "UNRESOLVED",
        "build_target": None,
        "note": "Static build evidence is not a successful compile or link",
    }
    if project.verification_backend == "oss-fuzz":
        record.update(status="EXPLICIT_OSS_FUZZ_BACKEND", build_target=project.oss_fuzz_project)
        return record
    if project.build_command and not any(
        "harnesscreator.runtime.native_build" in item for item in project.build_command
    ):
        record.update(status="USER_BUILD_COMMAND_CONFIGURED")
        return record
    root = project.source_root.resolve()
    required: set[Path] = set()
    for item in plan.required_source_files:
        file = Path(item)
        file = (file if file.is_absolute() else root / file).resolve()
        if not file.is_file() or root not in file.parents:
            record["reason"] = f"REQUIRED_SOURCE_UNAVAILABLE_OR_OUTSIDE_ROOT: {item}"
            return record
        required.add(file)
    if not required:
        record["reason"] = "NO_REQUIRED_SOURCE_EVIDENCE"
        return record
    db = project.analysis_compile_database or _find_compile_database(root)
    target_binary = _original_target_binary(project)
    if db and cmake_build_directory(db) is not None:
        closure = resolve_cmake_target(
            root, db, required, target_binary=target_binary,
        )
        if closure is None:
            record["reason"] = "CMAKE_TARGET_CLOSURE_NOT_UNIQUELY_RESOLVED"
        else:
            record.update(status="CANDIDATE", builder="cmake-link-graph",
                          build_target=closure.name,
                          source_count=len(closure.source_paths),
                          evidence_files=[str(x) for x in closure.evidence_files])
        return record
    if (root / "Makefile").is_file():
        try:
            closure = resolve_make_target(root, required)
        except MakeClosureUnresolved as exc:
            record["reason"] = f"MAKE_TARGET_CLOSURE_UNRESOLVED: {exc}"
            return record
        if (closure is not None and target_binary is not None
            and (root / closure.name).resolve() != target_binary):
            closure = None
        if closure is not None:
            record.update(status="CANDIDATE", builder="generated-makefile",
                          build_target=closure.name,
                          source_count=len(closure.source_flags),
                          evidence_files=[str(closure.evidence_file)])
            return record
    try:
        closure = resolve_recorded_make_target(
            root, db, required, target_binary=target_binary,
        )
    except MakeClosureUnresolved as exc:
        record["reason"] = f"RECORDED_MAKE_TARGET_UNRESOLVED: {exc}"
        return record
    if closure is not None:
        record.update(status="CANDIDATE", builder="recorded-make-target",
                      build_target=closure.name,
                      source_count=len(closure.source_flags),
                      evidence_files=[str(closure.evidence_file)])
        return record
    if target_binary is not None and any(
        (directory / name).is_file()
        for directory in (root, target_binary.parent)
        for name in ("Makefile", "makefile", "GNUmakefile")
    ):
        record["reason"] = "ORIGINAL_EXECUTABLE_MAKE_CLOSURE_NOT_MATCHED"
        return record
    try:
        units, evidence = discover_source_units(
            root, limit=96, compile_database=db,
        )
        all_sources = {item.source for item in units}
        if not required.issubset(all_sources):
            record["reason"] = "FALLBACK_SOURCE_SET_MISSES_REQUIRED_SOURCES"
        else:
            record.update(status="CANDIDATE", builder="standalone-small-source-layout",
                          source_count=len(units), evidence_files=[evidence])
    except (NativeBuildUnresolved, OSError, ValueError) as exc:
        record["reason"] = f"LINK_CLOSURE_NOT_AVAILABLE: {exc}"
    return record


def safe_inspect_build_closure_for_plan(project: ProjectSpec, plan: "HarnessPlan") -> dict[str, object]:
    """Fail OPEN for source discovery, but CLOSED for build proof.

    Build-graph parsers consume heterogeneous, sometimes incomplete source
    trees. No parser bug or malformed project metadata may abort unrelated
    Actions or quietly mark a failed build as verified. The error is retained
    per target and the actual native builder still applies its own checks.
    """
    try:
        return inspect_build_closure_for_plan(project, plan)
    except Exception as exc:
        return {
            "plan_id": plan.plan_id,
            "action_id": plan.target_action_id,
            "status": "UNRESOLVED",
            "build_target": None,
            "reason": f"BUILD_PREFLIGHT_ERROR: {type(exc).__name__}: {exc}",
            "note": "Build evidence missing; never elevates proof or prevents draft generation",
        }
