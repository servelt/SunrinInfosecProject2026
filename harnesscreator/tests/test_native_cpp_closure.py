"""A real C++ daemon target with an independent C libFuzzer driver."""
from __future__ import annotations
import json
import shutil
import subprocess
from pathlib import Path
import pytest
from harnesscreator.runtime.native_build import build_native


@pytest.mark.skipif(not all(shutil.which(x) for x in ('cmake','clang','clang++')),
                    reason='requires CMake/Clang toolchain')
def test_cpp_link_target_with_stdlib_and_c_harness(tmp_path: Path):
    source = tmp_path/'source'; source.mkdir()
    (source/'daemon.cpp').write_text(r'''
#include <cstddef>
#include <string>
extern "C" int dispatch_cpp(const unsigned char *p, size_t n) {
    std::string message(reinterpret_cast<const char *>(p), n);
    return message == "HELLO";
}
int main(int, char**) { return 0; }
''')
    (source/'other.cpp').write_text('int main() { return 0; }\n')
    (source/'CMakeLists.txt').write_text(
        'cmake_minimum_required(VERSION 3.16)\n'
        'project(native_harness LANGUAGES CXX)\n'
        'add_executable(daemon daemon.cpp)\n'
        'add_executable(other other.cpp)\n'
    )
    subprocess.run(['cmake','-S',str(source),'-B',str(source/'build'),
                    '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'],
                   check=True, capture_output=True, timeout=30)
    out=tmp_path/'out'; out.mkdir()
    harness=out/'fuzz_target.c'
    harness.write_text(
        '#include <stddef.h>\nextern int dispatch_cpp(const unsigned char*,size_t);\n'
        'int LLVMFuzzerTestOneInput(const unsigned char *p,size_t n){return dispatch_cpp(p,n);}\n')
    (out/'harness-plan.json').write_text(json.dumps({'required_source_files':['daemon.cpp']}))
    binary=build_native(source,harness,out)
    run=subprocess.run([str(binary),'-runs=10'],capture_output=True,text=True,timeout=20)
    assert run.returncode==0,run.stderr[-1500:]
    plan=json.loads((out/'.native-build/build-plan.json').read_text())
    assert plan['selected_cmake_target']=='daemon'
    assert 'other.cpp' not in json.dumps(plan)
    assert any('clang++' in cmd[0] for cmd in plan['compile_commands'])
