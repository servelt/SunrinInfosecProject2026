"""Real CMake multi-executable builds must not borrow sibling compile defines."""
from __future__ import annotations
import json
import shutil
import subprocess
from pathlib import Path
import pytest
from harnesscreator.runtime.native_build import build_native


@pytest.mark.skipif(not all(shutil.which(x) for x in ("cmake", "clang", "clang++")),
                    reason="requires CMake and clang")
def test_identical_source_with_different_compile_definitions(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "shared.c").write_text(
        "#ifndef EXPECTED\n#error missing build target definition\n#endif\n"
        "int compiled_configuration(void) { return EXPECTED; }\n")
    (src / "daemon.c").write_text("int main(void) { return 0; }\n")
    (src / "test_program.c").write_text("int main(void) { return 0; }\n")
    (src / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.16)\n"
        "project(per_target C)\n"
        "add_executable(daemon daemon.c shared.c)\n"
        "target_compile_definitions(daemon PRIVATE EXPECTED=42)\n"
        "add_executable(test_program test_program.c shared.c)\n"
        "target_compile_definitions(test_program PRIVATE EXPECTED=99)\n"
    )
    subprocess.run(["cmake", "-S", str(src), "-B", str(src / "build"),
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
                   check=True, capture_output=True, text=True, timeout=30)
    out = tmp_path / "out"
    out.mkdir()
    harness = out / "fuzz_target.c"
    harness.write_text(
        "#include <stddef.h>\n"
        "int compiled_configuration(void);\n"
        "int LLVMFuzzerTestOneInput(const unsigned char *x, size_t n) {\n"
        "  (void)x;(void)n;\n"
        "  if (compiled_configuration() != 42) __builtin_trap();\n"
        "  return 0;\n}\n"
    )
    (out / "harness-plan.json").write_text(json.dumps({
        "required_source_files": ["daemon.c", "shared.c"]
    }))
    binary = build_native(src, harness, out)
    run = subprocess.run([str(binary), "-runs=5"],
                         capture_output=True, text=True, timeout=25)
    assert run.returncode == 0, run.stderr[-1500:]
    build = json.loads((out / ".native-build/build-plan.json").read_text())
    assert build["selected_cmake_target"] == "daemon"
    assert any("-DEXPECTED=42" in cmd for cmd in build["compile_commands"])
    assert not any("-DEXPECTED=99" in cmd for cmd in build["compile_commands"])
