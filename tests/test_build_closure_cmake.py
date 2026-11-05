"""Real CMake multi-target regression: no preexisting OSS-Fuzz registration."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from harnesscreator.runtime.native_build import NativeBuildUnresolved, build_native


@pytest.mark.skipif(not all(shutil.which(x) for x in ("clang", "clang++", "cmake")),
                    reason="requires real CMake/Clang")
def test_resolves_transitive_static_library_and_ignores_other_main(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "lib").mkdir()
    (source / "lib/parser.c").write_text(
        '#include <stddef.h>\nint parse(const unsigned char *p, size_t n)'
        '{return n>0 && p[0]==65;}\n'
    )
    (source / "service.c").write_text(
        '#include <stddef.h>\n'
        'extern int parse(const unsigned char *,size_t);\n'
        'int service(const unsigned char *p,size_t n){return parse(p,n);}\n'
        'int main(void){return 0;}\n'
    )
    (source / "unrelated.c").write_text(
        'int unrelated(void){return 19;}\nint main(void){return 0;}\n'
    )
    (source / "CMakeLists.txt").write_text(
        'cmake_minimum_required(VERSION 3.16)\n'
        'project(example C)\n'
        'add_library(parser STATIC lib/parser.c)\n'
        'add_executable(service service.c)\n'
        'target_link_libraries(service PRIVATE parser)\n'
        'add_executable(unrelated unrelated.c)\n'
    )
    build_dir = source / "build"
    subprocess.run(["cmake", "-S", str(source), "-B", str(build_dir),
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
                   capture_output=True, text=True, check=True)
    generated = tmp_path / "generated"
    generated.mkdir()
    harness = generated / "fuzz_target.c"
    harness.write_text(
        '#include <stddef.h>\n'
        'extern int service(const unsigned char*,size_t);\n'
        'int LLVMFuzzerTestOneInput(const unsigned char *p,size_t n)'
        '{(void)service(p,n);return 0;}\n'
    )
    (generated / "harness-plan.json").write_text(json.dumps({
        "required_source_files": ["service.c", "lib/parser.c"]
    }))
    binary = build_native(source, harness, generated)
    assert binary.is_file()
    assert subprocess.run([str(binary), "-runs=10"], capture_output=True,
                          timeout=15).returncode == 0
    meta = json.loads((generated / ".native-build/build-plan.json").read_text())
    assert meta["selected_cmake_target"] == "service"
    assert set(meta["original_sources"]) == {
        str(source / "service.c"), str(source / "lib/parser.c")
    }
    assert "unrelated.c" not in json.dumps(meta)
    with pytest.raises(NativeBuildUnresolved, match="no uniquely attributable"):
        build_native(
            source, harness, generated,
            target_binary=build_dir / "unrelated",
        )


@pytest.mark.skipif(not all(shutil.which(x) for x in ("clang", "clang++", "cmake")),
                    reason="requires real CMake/Clang")
def test_refuses_ambiguous_build_when_no_source_contract(tmp_path: Path):
    source = tmp_path / "project"
    source.mkdir()
    (source / "CMakeLists.txt").write_text(
        'cmake_minimum_required(VERSION 3.16)\nproject(ambig C)\n'
        'add_executable(left left.c)\nadd_executable(right right.c)\n'
    )
    for name in ("left", "right"):
        (source / f"{name}.c").write_text("int main(void){return 0;}\n")
    subprocess.run(["cmake", "-S", str(source), "-B", str(source / "build"),
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"],
                   capture_output=True, text=True, check=True)
    out = tmp_path / "output"
    out.mkdir()
    harness = out / "fuzz_target.c"
    harness.write_text(
        '#include <stddef.h>\n'
        'int LLVMFuzzerTestOneInput(const unsigned char *p,size_t n){return 0;}\n'
    )
    with pytest.raises(NativeBuildUnresolved, match="no uniquely attributable"):
        build_native(source, harness, out)


@pytest.mark.skipif(not all(shutil.which(x) for x in ("clang", "clang++", "cmake")),
                    reason="requires real CMake/Clang")
def test_explicit_cmake_target_can_use_vendored_source(tmp_path: Path):
    """A vendored parser in the product target must not be globally excluded."""
    root = tmp_path / "product"
    root.mkdir()
    (root / "vendor").mkdir()
    (root / "vendor/parser.c").write_text(
        '#include <stddef.h>\nint parse(const unsigned char *p, size_t n){return n && p[0]==84;}\n'
    )
    (root / "main.c").write_text(
        '#include <stddef.h>\nextern int parse(const unsigned char*,size_t);\n'
        'int service(const unsigned char *p,size_t n){return parse(p,n);}\n'
        'int main(void){return 0;}\n'
    )
    (root / "CMakeLists.txt").write_text(
        'cmake_minimum_required(VERSION 3.16)\nproject(target C)\n'
        'add_executable(main main.c vendor/parser.c)\n'
    )
    subprocess.run(["cmake", "-S", str(root), "-B", str(root / "build"),
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"], check=True, capture_output=True)
    out = tmp_path / "fuzz"
    out.mkdir()
    harness = out / "fuzz_target.c"
    harness.write_text(
        '#include <stddef.h>\nextern int service(const unsigned char*,size_t);\n'
        'int LLVMFuzzerTestOneInput(const unsigned char *p,size_t n)'
        '{(void)service(p,n);return 0;}\n'
    )
    (out / "harness-plan.json").write_text(json.dumps({
        "required_source_files": ["main.c", "vendor/parser.c"]
    }))
    binary = build_native(root, harness, out)
    assert subprocess.run([str(binary), "-runs=10"], capture_output=True, timeout=15).returncode == 0
