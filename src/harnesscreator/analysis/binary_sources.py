"""Positive source-origin evidence from an ELF executable's DWARF or symtab.

This only changes analysis order. A missing or unmatched compilation unit is
never evidence that a function is absent from the executable.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Iterable


def selected_binary_is_program(binary: Path | None) -> bool:
    """Recognize an ELF program, including PIE, without guessing from its name."""
    if binary is None or not binary.is_file():
        return False
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.common.exceptions import ELFError
    except ImportError:
        return False
    try:
        with binary.open("rb") as stream:
            elf = ELFFile(stream)
            if elf.header.e_type == "ET_EXEC":
                return True
            return (elf.header.e_type == "ET_DYN"
                    and any(segment.header.p_type == "PT_INTERP"
                            for segment in elf.iter_segments()))
    except (OSError, ValueError, ELFError):
        return False


def _symbol_file_hints(elf: Any, indexed_files: set[str]) -> tuple[set[str], int, int]:
    """Map ELF STT_FILE names only when the indexed basename is unique.

    STT_FILE records the linker's input file name, not its source contents or
    build revision. It can improve inspection order but cannot exclude any
    source, and an ambiguous basename is never selected.
    """
    try:
        from elftools.elf.sections import SymbolTableSection
    except ImportError:
        return set(), 0, 0
    by_basename: dict[str, set[str]] = {}
    for relative in indexed_files:
        by_basename.setdefault(Path(relative).name, set()).add(relative)
    hints: set[str] = set()
    symbols = 0
    ambiguous = 0
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        if section.header.sh_type != "SHT_SYMTAB":
            continue
        for symbol in section.iter_symbols():
            if symbol.entry.st_info.type != "STT_FILE":
                continue
            symbols += 1
            name = Path(symbol.name).name
            matches = by_basename.get(name, set())
            if len(matches) == 1:
                hints.update(matches)
            elif len(matches) > 1:
                ambiguous += 1
    return hints, symbols, ambiguous


def linked_source_priority(
    binary: Path,
    source_root: Path,
    indexed_files: Iterable[str],
) -> dict[str, Any]:
    """Match accessible DWARF primary sources to byte-identical index files.

    Separate debug files, generated files and inaccessible container paths
    deliberately remain unknown. They are never used to exclude functions.
    """

    binary = binary.expanduser().resolve()
    source_root = source_root.expanduser().resolve()
    report: dict[str, Any] = {
        "binary": str(binary),
        "status": "unavailable",
        "matched_files": [],
        "symbol_file_hints": [],
        "symbol_file_count": 0,
        "ambiguous_symbol_files": 0,
        "compile_units": 0,
        "unmatched_units": 0,
        "policy": "matching source files are prioritized; unmatched files remain eligible",
    }
    if not binary.is_file():
        report["reason"] = "binary is absent or not a regular file"
        return report
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.common.exceptions import DWARFError, ELFError
    except ImportError:
        report["reason"] = "pyelftools is unavailable"
        return report

    source_paths: dict[str, Path] = {}
    for relative in set(indexed_files):
        candidate = (source_root / relative).resolve()
        if candidate.is_relative_to(source_root) and candidate.is_file():
            source_paths[relative] = candidate
    source_hashes: dict[Path, str] = {}
    compiled_hashes: dict[Path, str] = {}
    matched: set[str] = set()
    try:
        with binary.open("rb") as stream:
            elf = ELFFile(stream)
            if not elf.has_dwarf_info():
                hints, symbols, ambiguous = _symbol_file_hints(
                    elf, set(source_paths)
                )
                report["symbol_file_hints"] = sorted(hints)
                report["symbol_file_count"] = symbols
                report["ambiguous_symbol_files"] = ambiguous
                report["status"] = "symbol_file_hints" if hints else "no_dwarf"
                report["reason"] = (
                    "ELF has no in-file DWARF; STT_FILE names are ordering "
                    "hints only and do not prove source identity or absence"
                )
                return report
            dwarf = elf.get_dwarf_info()
            for unit in dwarf.iter_CUs():
                top = unit.get_top_DIE()
                if top.tag != "DW_TAG_compile_unit":
                    continue
                report["compile_units"] += 1
                attributes = top.attributes
                name = attributes.get("DW_AT_name")
                directory = attributes.get("DW_AT_comp_dir")
                if name is None:
                    report["unmatched_units"] += 1
                    continue
                source_name = os.fsdecode(name.value)
                compiled = Path(source_name)
                if not compiled.is_absolute():
                    if directory is None:
                        report["unmatched_units"] += 1
                        continue
                    compiled = Path(os.fsdecode(directory.value)) / compiled
                compiled = compiled.resolve()
                if not compiled.is_file():
                    report["unmatched_units"] += 1
                    continue
                candidates = [
                    (relative, indexed)
                    for relative, indexed in source_paths.items()
                    if (
                        compiled == indexed
                        or compiled.as_posix().endswith(
                            "/" + relative.replace("\\", "/")
                        )
                    )
                ]
                if not candidates:
                    # A DWARF path is binary-controlled input. Do not read an
                    # arbitrary host file that cannot name an indexed source.
                    report["unmatched_units"] += 1
                    continue
                compiled_digest = compiled_hashes.get(compiled)
                if compiled_digest is None:
                    compiled_digest = hashlib.sha256(compiled.read_bytes()).hexdigest()
                    compiled_hashes[compiled] = compiled_digest
                possible: list[str] = []
                for relative, indexed in candidates:
                    indexed_digest = source_hashes.get(indexed)
                    if indexed_digest is None:
                        indexed_digest = hashlib.sha256(indexed.read_bytes()).hexdigest()
                        source_hashes[indexed] = indexed_digest
                    if indexed_digest == compiled_digest:
                        possible.append(relative)
                if len(possible) == 1:
                    matched.add(possible[0])
                else:
                    report["unmatched_units"] += 1
    except (OSError, ValueError, TypeError, DWARFError, ELFError) as exc:
        report["status"] = "error"
        report["reason"] = f"DWARF inspection failed: {type(exc).__name__}: {exc}"
        return report
    if not matched and report["compile_units"] == 0:
        # Some ELF binaries contain unwind information that makes
        # has_dwarf_info() true even though no source compilation units can
        # be matched. Try the ordinary linker's STT_FILE table as a weaker
        # positive hint, never as a source-identity or exclusion proof. If
        # DWARF CUs exist but fail source/hash matching, the current checkout
        # may be stale: do not replace that negative identity check with a
        # same-basename symbol hint.
        try:
            with binary.open("rb") as stream:
                hints, symbols, ambiguous = _symbol_file_hints(
                    ELFFile(stream), set(source_paths)
                )
        except (OSError, ValueError, TypeError, ELFError) as exc:
            report["status"] = "error"
            report["reason"] = f"ELF symbol inspection failed: {type(exc).__name__}: {exc}"
            return report
        report["symbol_file_hints"] = sorted(hints)
        report["symbol_file_count"] = symbols
        report["ambiguous_symbol_files"] = ambiguous
    report["status"] = (
        "matched" if matched else
        "symbol_file_hints" if report["symbol_file_hints"] else "no_match"
    )
    report["matched_files"] = sorted(matched)
    return report
