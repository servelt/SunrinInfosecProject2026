"""Exercise the explicit StateAFL build adapter with a hardcoded gcc Makefile."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from harnesscreator.runtime.stateafl_build import (
    StateAFLBuildError,
    StateAFLBuildSpec,
    _compile_records,
    _coverage_object_symbol,
    _trace_pc_binary_guard,
    build_stateafl_server,
    has_instrumentation_evidence,
)


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    compiler = shutil.which("gcc")
    if compiler is None or shutil.which("make") is None:
        pytest.skip("requires gcc and make")
    source = tmp_path / "source"
    source.mkdir()
    (source / "server.c").write_text("int main(void) { return 0; }\n")
    (source / "Makefile").write_text(
        "all: server\n"
        "server: server.o\n\tgcc -o server server.o\n"
        "server.o: server.c\n\tgcc -c server.c -o server.o\n"
    )
    wrapper = tmp_path / "afl-clang-fast"
    wrapper.write_text(
        "#!/bin/sh\n"
        "printf '%s\\n' \"$*\" >> " + str(tmp_path / "compiler.log") + "\n"
        "exec " + compiler + ' "$@"\n'
    )
    wrapper.chmod(0o755)
    return source, wrapper


def test_hardcoded_compiler_is_replaced_and_link_flags_only_reach_link(tmp_path: Path):
    source, wrapper = _fixture(tmp_path)
    result = build_stateafl_server(StateAFLBuildSpec(
        source_root=source, output_dir=tmp_path / "output", compiler=wrapper,
        build_command=("make", "all"), server_relative_path=Path("server"),
        linker_flags=("-no-pie",),
    ))
    assert Path(result["server_binary"]).is_file()
    assert result["qualified_harness_claim"] is False
    assert result["status"] == "BUILT_COVERAGE_NOT_OBSERVED"
    assert result["afl_coverage_object_detected"] is False
    lines = (tmp_path / "compiler.log").read_text().splitlines()
    assert len(lines) == 2
    assert "-no-pie" not in lines[0]
    assert lines[1].endswith("-no-pie")
    records = json.loads(Path(result["compile_database"]).read_text())
    assert result["compile_database_files"] == 1
    assert records[0]["file"] == str(tmp_path / "output/source/server.c")
    assert records[0]["arguments"][-4:] == ["-c", "server.c", "-o", "server.o"]
    assert json.loads((tmp_path / "output/build.json").read_text()) == result


def test_instrumented_build_does_not_copy_run_artifacts_inside_source(tmp_path: Path):
    source, wrapper = _fixture(tmp_path)
    runs = source / "runs"
    prior = runs / "prior-run"
    prior.mkdir(parents=True)
    (prior / "large-fuzz-output.bin").write_bytes(b"old coverage corpus")
    result = build_stateafl_server(StateAFLBuildSpec(
        source_root=source, output_dir=tmp_path / "output", compiler=wrapper,
        build_command=("make", "all"), server_relative_path=Path("server"),
        excluded_paths=(runs,),
    ))
    assert Path(result["server_binary"]).is_file()
    assert not (tmp_path / "output/source/runs").exists()
    assert result["excluded_source_paths"] == [str(runs.resolve())]


def test_early_instrumented_build_stops_with_parent_analysis(tmp_path: Path):
    source, wrapper = _fixture(tmp_path)
    stop = threading.Event()
    timer = threading.Timer(0.2, stop.set)
    started = time.monotonic()
    timer.start()
    try:
        with pytest.raises(StateAFLBuildError, match="cancelled by parent analysis"):
            build_stateafl_server(StateAFLBuildSpec(
                source_root=source, output_dir=tmp_path / "output", compiler=wrapper,
                build_command=(sys.executable, "-c", "import time; time.sleep(30)"),
                server_relative_path=Path("server"), stop_event=stop,
            ))
    finally:
        timer.cancel()
    assert time.monotonic() - started < 10


def test_container_compile_record_remaps_source_and_include_paths(tmp_path: Path):
    output = tmp_path / "output"
    source = output / "source"
    invocation_dir = output / "compile-invocations"
    (source / "include").mkdir(parents=True)
    invocation_dir.mkdir()
    (source / "main.cpp").write_text("int main() { return 0; }\n")
    (invocation_dir / "invocation.1").write_bytes(
        b"/stateafl/afl-clang-fast++\0/work/source\0-c\0main.cpp\0"
        b"-I/work/source/include\0-o\0main.o\0"
    )
    records = _compile_records(invocation_dir, output, source, True)
    assert len(records) == 1
    assert records[0]["directory"] == str(source)
    assert records[0]["file"] == str(source / "main.cpp")
    assert "-I" + str(source / "include") in records[0]["arguments"]


def test_preexisting_binary_cannot_be_mistaken_for_new_build(tmp_path: Path):
    source, wrapper = _fixture(tmp_path)
    old = source / "server"
    old.write_text("#!/bin/sh\nexit 0\n")
    old.chmod(0o755)
    with pytest.raises(StateAFLBuildError, match="expected binary server"):
        build_stateafl_server(StateAFLBuildSpec(
            source_root=source, output_dir=tmp_path / "output", compiler=wrapper,
            build_command=("true",), server_relative_path=Path("server"),
        ))
    assert not (tmp_path / "output/source/server").exists()


def test_explicit_build_steps_execute_in_order(tmp_path: Path):
    source, wrapper = _fixture(tmp_path)
    result = build_stateafl_server(StateAFLBuildSpec(
        source_root=source, output_dir=tmp_path / "output", compiler=wrapper,
        build_command=("true",), build_steps=(("make", "all"),),
        server_relative_path=Path("server"),
    ))
    assert Path(result["server_binary"]).is_file()
    assert result["build_steps"] == [["make", "all"]]
    assert "[build step 2/2] make all" in (tmp_path / "output/build.log").read_text()


def test_trace_pc_guard_object_is_recognized_as_compiler_instrumented(tmp_path: Path):
    clang = shutil.which("clang")
    if clang is None or shutil.which("nm") is None or shutil.which("readelf") is None:
        pytest.skip("requires clang, nm, and readelf")
    source = tmp_path / "server.c"
    source.write_text("int main(int argc, char **argv) { return argc > 1 && argv[1][0]; }\n")
    obj = tmp_path / "server.o"
    subprocess.run(
        [clang, "-O1", "-fsanitize-coverage=trace-pc-guard", "-c",
         str(source), "-o", str(obj)],
        check=True,
    )
    assert _coverage_object_symbol(tmp_path, {}) is True


def test_manual_trace_pc_callback_calls_are_not_coverage_evidence(tmp_path: Path):
    clang = shutil.which("clang")
    if clang is None or shutil.which("nm") is None or shutil.which("readelf") is None:
        pytest.skip("requires clang, nm, and readelf")
    source = tmp_path / "server.c"
    source.write_text(
        "extern void __sanitizer_cov_trace_pc_guard(unsigned *);\n"
        "extern void __sanitizer_cov_trace_pc_guard_init(unsigned *, unsigned *);\n"
        "void probe(unsigned *p) { __sanitizer_cov_trace_pc_guard(p); "
        "__sanitizer_cov_trace_pc_guard_init(p, p + 1); }\n"
    )
    subprocess.run(
        [clang, "-O0", "-c", str(source), "-o", str(tmp_path / "server.o")],
        check=True,
    )
    assert _coverage_object_symbol(tmp_path, {}) is False


def test_direct_compile_and_link_preserves_trace_pc_guard_evidence(tmp_path: Path):
    clang = shutil.which("clang")
    if clang is None or shutil.which("readelf") is None:
        pytest.skip("requires clang and readelf")
    source = tmp_path / "server.c"
    source.write_text(
        "#include <stdint.h>\n"
        "void __sanitizer_cov_trace_pc_guard(uint32_t *p) { (void)p; }\n"
        "void __sanitizer_cov_trace_pc_guard_init(uint32_t *a, uint32_t *b) "
        "{ (void)a; (void)b; }\n"
        "int main(int argc, char **argv) { return argc > 1 && argv[1][0]; }\n"
    )
    binary = tmp_path / "server"
    subprocess.run(
        [clang, "-O1", "-fsanitize-coverage=trace-pc-guard",
         str(source), "-o", str(binary)],
        check=True,
    )
    assert _coverage_object_symbol(tmp_path, {}) is None
    assert _trace_pc_binary_guard(binary) is True


def test_runtime_marker_is_required_with_coverage_evidence():
    assert not has_instrumentation_evidence({"afl_coverage_object_detected": True})
    assert not has_instrumentation_evidence({
        "afl_trace_pc_binary_guard_detected": True,
        "instrumentation_evidence": True,
    })
    assert has_instrumentation_evidence({
        "afl_coverage_object_detected": True,
        "afl_runtime_symbol_detected": True,
    })
