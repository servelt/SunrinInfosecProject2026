"""Order AST work using recorded compiler context for a selected executable.

The compile database records compilation, not linkage. Matching a compiler
working directory to the executable's directory is therefore only a work
ordering hint. Every recorded translation unit remains eligible.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..runtime.native_build import _find_compile_database


def order_translation_units(
    paths: list[Path], source_root: Path, compile_database: Path | None,
    target_binary: Path | None,
) -> list[Path]:
    """Visit sources compiled beside the selected executable first.

    Build systems may compile all objects elsewhere or share one directory
    across targets. In those cases this ordering supplies no preference.
    """

    preferred: set[Path] = set()
    if target_binary is not None and target_binary.is_file():
        database = compile_database or _find_compile_database(source_root)
        if database is not None:
            try:
                records = json.loads(database.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                records = []
            if isinstance(records, list):
                target_directory = target_binary.resolve().parent
                for record in records:
                    if not isinstance(record, dict):
                        continue
                    raw_file = record.get("file")
                    if not isinstance(raw_file, str) or not raw_file:
                        continue
                    directory = Path(str(record.get("directory") or database.parent)).resolve()
                    if directory != target_directory:
                        continue
                    path = Path(raw_file)
                    preferred.add((path if path.is_absolute() else directory / path).resolve())
    return sorted(paths, key=lambda path: (path.resolve() not in preferred, str(path)))
