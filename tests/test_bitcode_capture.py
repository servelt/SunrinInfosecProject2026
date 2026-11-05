from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from harnesscreator.analysis.bitcode_capture import (
    BitcodeCaptureError, capture_bitcode_from_compile_database,
)


def test_c_and_cpp_bitcode_capture_preserves_recorded_build_flags(tmp_path: Path) -> None:
    if shutil.which("clang") is None or shutil.which("clang++") is None:
        pytest.skip("Clang C and C++ compilers are required")
    root = tmp_path / "project"
    root.mkdir()
    (root / "value.h").write_text("#define MAGIC 42\n")
    c_source = root / "target.c"
    cpp_source = root / "target.cc"
    c_source.write_text('#include "value.h"\nint target(void) { return MAGIC; }\n')
    cpp_source.write_text('#include "value.h"\nint other() { return MAGIC; }\n')
    original_object = root / "target.o"
    original_object.write_bytes(b"existing product object")
    records = [
        {
            "directory": str(root), "file": str(c_source),
            "arguments": ["cc", "-I.", "-c", "target.c", "-o", "target.o"],
        },
        {
            "directory": str(root), "file": str(cpp_source),
            "arguments": ["c++", "-I.", "-c", "target.cc", "-o", "target-cc.o"],
        },
    ]
    database = tmp_path / "compile_commands.json"
    database.write_text(json.dumps(records))

    captured = capture_bitcode_from_compile_database(
        database, root, tmp_path / "analysis",
    )

    assert len(captured.modules) == 2
    assert set(captured.compiled_sources) == {str(c_source), str(cpp_source)}
    assert all(path.read_bytes().startswith(b"BC\xc0\xde") for path in captured.modules)
    assert original_object.read_bytes() == b"existing product object"
    assert not (root / "target-cc.o").exists()


def test_ambiguous_multiple_configs_fail_without_choosing_one(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    source = root / "target.c"
    source.write_text("int target(void) { return 1; }\n")
    database = tmp_path / "compile_commands.json"
    database.write_text(json.dumps([
        {"directory": str(root), "file": str(source),
         "arguments": ["cc", "-DOPTION=1", "-c", "target.c"]},
        {"directory": str(root), "file": str(source),
         "arguments": ["cc", "-DOPTION=2", "-c", "target.c"]},
    ]))

    with pytest.raises(BitcodeCaptureError, match="multiple compile commands"):
        capture_bitcode_from_compile_database(database, root, tmp_path / "analysis")
