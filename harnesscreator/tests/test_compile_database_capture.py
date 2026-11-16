"""Build-context capture preserves the flags needed by source analysis."""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from harnesscreator.analysis import StaticAnalyzer
from harnesscreator.runtime.compile_database_capture import capture_compile_database
from harnesscreator.runtime.build_closure import (
    cmake_build_directory, resolve_cmake_target,
)
from harnesscreator.runtime.native_build import discover_source_units


def test_recorded_real_build_recovers_generated_header_context(tmp_path: Path):
    compiler = shutil.which("cc")
    if not compiler or not shutil.which("clang"):
        pytest.skip("C and Clang compilers are required")
    root = tmp_path / "daemon"
    root.mkdir()
    include = tmp_path / "configured-includes"
    include.mkdir()
    (include / "generated.h").write_text("#define ACCEPTED_BYTE 'X'\n")
    (root / "daemon.c").write_text(
        '#include "generated.h"\n#include <unistd.h>\n'
        'int receive_one(int fd) { char data[2]; '
        'if (read(fd, data, 2) != 2) return 0; '
        'return data[0] == ACCEPTED_BYTE; }\n'
    )
    unconfigured = StaticAnalyzer(root).index()
    assert unconfigured.completeness["clang_c_ast_parsed_files"] == 0

    # A tiny Bear protocol fixture records the *executed* compiler argv.
    # It exercises the capture-to-analyzer integration without depending on
    # the host having Bear installed; production uses the real Bear binary.
    tool_dir = tmp_path / "tools"
    tool_dir.mkdir()
    bear = tool_dir / "bear"
    bear.write_text(
        f"#!{sys.executable}\n"
        "import json, os, subprocess, sys\n"
        "assert sys.argv[1] == '--output' and sys.argv[3] == '--'\n"
        "command = sys.argv[4:]\n"
        "subprocess.run(command, check=True)\n"
        "with open(sys.argv[2], 'w') as stream:\n"
        "    json.dump([{'directory': os.getcwd(), 'file': 'daemon.c', "
        "'arguments': command}], stream)\n"
    )
    bear.chmod(0o755)
    command = [compiler, "-I", str(include), "-c", "daemon.c", "-o", "daemon.o"]
    destination = tmp_path / "analysis" / "compile_commands.json"
    with patch.dict(os.environ, {"PATH": str(tool_dir) + os.pathsep + os.environ["PATH"]}):
        captured = capture_compile_database(root, destination, command)
    assert captured == destination
    assert (root / "daemon.o").is_file()
    configured = StaticAnalyzer(root, compile_database=captured).index()
    assert configured.completeness["clang_c_ast_parsed_files"] == 1
    units, source = discover_source_units(root, compile_database=captured)
    assert len(units) == 1 and source == str(captured)
    assert str(include) in units[0].flags


def test_capture_does_not_run_build_when_bear_is_missing(tmp_path: Path):
    root = tmp_path / "source"
    root.mkdir()
    marker = root / "build-ran"
    with patch("harnesscreator.runtime.compile_database_capture.shutil.which", return_value=None):
        with pytest.raises(ValueError, match="Bear is required"):
            capture_compile_database(
                root, tmp_path / "out" / "compile_commands.json",
                [sys.executable, "-c", f"open({str(marker)!r}, 'w').close()"],
            )
    assert not marker.exists()


def test_cmake_link_graph_is_found_when_recorded_database_is_elsewhere(tmp_path: Path):
    root = tmp_path / "source"
    root.mkdir()
    source = root / "daemon.c"
    source.write_text("int main(void) { return 0; }\n")
    build = tmp_path / "build"
    link_dir = build / "CMakeFiles" / "daemon.dir"
    link_dir.mkdir(parents=True)
    (build / "CMakeCache.txt").write_text("# configured build\n")
    (link_dir / "link.txt").write_text(
        "cc CMakeFiles/daemon.dir/daemon.c.o -o daemon\n"
    )
    database = tmp_path / "analysis" / "compile_commands.json"
    database.parent.mkdir()
    database.write_text(json.dumps([{
        "directory": str(build),
        "file": str(source),
        "arguments": ["cc", "-c", str(source), "-o",
                      "CMakeFiles/daemon.dir/daemon.c.o"],
    }]))
    assert cmake_build_directory(database) == build
    closure = resolve_cmake_target(root, database, {source})
    assert closure is not None and closure.name == "daemon"
    assert closure.source_paths == (source,)

    second = tmp_path / "other-build"
    (second / "CMakeFiles").mkdir(parents=True)
    (second / "CMakeCache.txt").write_text("# a different configuration\n")
    database.write_text(json.dumps([
        {"directory": str(build), "file": str(source)},
        {"directory": str(second), "file": str(source)},
    ]))
    assert cmake_build_directory(database) is None
    assert resolve_cmake_target(root, database, {source}) is None
