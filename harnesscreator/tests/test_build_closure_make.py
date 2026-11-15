"""Configured Automake multi-executable closure tests using real libFuzzer."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from harnesscreator.runtime.make_closure import (
    MakeClosureUnresolved, resolve_make_target, resolve_recorded_make_target,
)
from harnesscreator.runtime.native_build import NativeBuildUnresolved, build_native


@pytest.mark.skipif(not all(shutil.which(x) for x in ("clang", "clang++")),
                    reason="requires real Clang/libFuzzer")
def test_configured_make_multiple_programs_archive_and_real_fuzzer(tmp_path: Path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "lib").mkdir()
    (root / "lib/parse.c").write_text(
        '#include <stddef.h>\nint parse(const unsigned char *p,size_t n){return n && p[0]==65;}\n'
    )
    (root / "server.c").write_text(
        '#include <stddef.h>\nextern int parse(const unsigned char*,size_t);\n'
        'int service(const unsigned char *p,size_t n){return parse(p,n);}\n'
        'int main(void){return 0;}\n'
    )
    (root / "other.c").write_text('int main(void){return 1;}\n')
    (root / "Makefile").write_text(
        '# simulated generated Automake Makefile, no shell execution\n'
        'bin_PROGRAMS = server\n'
        'noinst_PROGRAMS = other server-debug\n'
        'noinst_LIBRARIES = libparse.a\n'
        'server_SOURCES = server.c\n'
        'server_LDADD = libparse.a -lm\n'
        'server_debug_SOURCES = $(server_SOURCES)\n'
        'server_debug_LDADD = $(server_LDADD)\n'
        'other_SOURCES = other.c\n'
        'libparse_a_SOURCES = lib/parse.c\n'
        'DEFS = -DUSE_PARSE=1\n'
    )
    closure = resolve_make_target(root, {root / "server.c", root / "lib/parse.c"})
    assert closure is not None and closure.name == "server"
    out = tmp_path / "generated"
    out.mkdir()
    (out / "fuzz_target.c").write_text(
        '#include <stddef.h>\nextern int service(const unsigned char*,size_t);\n'
        'int LLVMFuzzerTestOneInput(const unsigned char *p,size_t n)'
        '{(void)service(p,n);return 0;}\n'
    )
    (out / "harness-plan.json").write_text(json.dumps({
        "required_source_files": ["server.c", "lib/parse.c"]
    }))
    binary = build_native(root, out / "fuzz_target.c", out)
    result = subprocess.run([str(binary), "-runs=10"], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr[-1500:]
    plan = json.loads((out / ".native-build" / "build-plan.json").read_text())
    assert plan["selected_make_target"] == "server"
    assert set(plan["original_sources"]) == {str(root / "server.c"), str(root / "lib/parse.c")}
    assert "other.c" not in json.dumps(plan)
    assert any("-DUSE_PARSE=1" in args for args in plan["compile_commands"])


def test_ambiguous_installed_programs_without_source_contract(tmp_path: Path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "Makefile").write_text(
        'bin_PROGRAMS = a b\na_SOURCES = a.c\nb_SOURCES = b.c\n'
    )
    for name in ("a", "b"):
        (root / f"{name}.c").write_text('int main(void){return 0;}\n')
    with pytest.raises(MakeClosureUnresolved, match="ambiguous"):
        resolve_make_target(root, set())


def test_unresolved_make_shell_expression_is_not_executed(tmp_path: Path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "Makefile").write_text('bin_PROGRAMS = main\nmain_SOURCES = $(shell echo /tmp/bad.c)\n')
    (root / "main.c").write_text('int main(void){return 0;}\n')
    with pytest.raises(MakeClosureUnresolved, match="unsupported Makefile expression"):
        resolve_make_target(root, set())


def test_missing_generated_source_stays_unresolved(tmp_path: Path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "Makefile").write_text('bin_PROGRAMS = server\nserver_SOURCES = generated_parser.c\n')
    with pytest.raises(MakeClosureUnresolved, match="source unavailable"):
        resolve_make_target(root, set())


@pytest.mark.skipif(not all(shutil.which(x) for x in ("clang", "clang++")),
                    reason="requires real Clang/libFuzzer")
def test_recorded_subdirectory_make_link_is_used_for_generated_harness(tmp_path: Path):
    root = tmp_path / "source"
    build = root / "Release"
    build.mkdir(parents=True)
    (root / "daemon.c").write_text(
        '#include <math.h>\n#include <stddef.h>\n'
        'int service(const unsigned char *p,size_t n)'
        '{return n && cos((double)p[0]) > 0.5;}\n'
        'int main(void){return 0;}\n'
    )
    (build / "makefile").write_text(
        '-include sources.mk\n-include subdir.mk\n-include objects.mk\n'
        'all: daemon\n'
        'daemon: $(OBJS)\n\tclang -o "daemon" $(OBJS) $(LIBS)\n'
    )
    (build / "sources.mk").write_text('OBJS :=\n')
    (build / "subdir.mk").write_text('OBJS += ./daemon.o\n')
    (build / "objects.mk").write_text('LIBS := -lm\n')
    db = root / "compile_commands.json"
    db.write_text(json.dumps([{
        "directory": str(build), "file": str(root / "daemon.c"),
        "output": str(build / "daemon.o"),
        "arguments": ["clang", "-c", "../daemon.c", "-o", "daemon.o"],
    }]))
    closure = resolve_recorded_make_target(root, db, {root / "daemon.c"})
    assert closure is not None
    assert closure.name == "daemon"
    assert closure.link_flags == ("-lm",)
    out = tmp_path / "output"
    out.mkdir()
    harness = out / "fuzz_target.c"
    harness.write_text(
        '#include <stddef.h>\nextern int service(const unsigned char*,size_t);\n'
        'int LLVMFuzzerTestOneInput(const unsigned char *p,size_t n)'
        '{(void)service(p,n);return 0;}\n'
    )
    (out / "harness-plan.json").write_text(json.dumps({
        "required_source_files": ["daemon.c"]
    }))
    binary = build_native(root, harness, out, compile_database=db)
    run = subprocess.run([str(binary), "-runs=3"], capture_output=True, text=True, timeout=15)
    assert run.returncode == 0, run.stderr[-1500:]
    plan = json.loads((out / ".native-build" / "build-plan.json").read_text())
    assert plan["selected_make_target"] == "daemon"
    assert "-lm" in plan["link_command"]


def test_recorded_make_link_rejects_missing_compile_object(tmp_path: Path):
    root = tmp_path / "source"
    build = root / "Release"
    build.mkdir(parents=True)
    (root / "daemon.c").write_text('int main(void){return 0;}\n')
    (build / "makefile").write_text(
        '-include objects.mk\nall: daemon\n'
        'daemon: $(OBJS)\n\tclang -o daemon $(OBJS) $(LIBS)\n'
    )
    (build / "objects.mk").write_text('OBJS := daemon.o missing.o\nLIBS := -lm\n')
    db = root / "compile_commands.json"
    db.write_text(json.dumps([{
        "directory": str(build), "file": str(root / "daemon.c"),
        "output": str(build / "daemon.o"),
        "arguments": ["clang", "-c", "../daemon.c", "-o", "daemon.o"],
    }]))
    assert resolve_recorded_make_target(root, db, {root / "daemon.c"}) is None


@pytest.mark.skipif(not all(shutil.which(x) for x in ("clang", "clang++")),
                    reason="requires real Clang/libFuzzer")
def test_generated_make_pattern_closure_without_compilation_database(tmp_path: Path):
    root = tmp_path / "source"
    build = root / "Release"
    build.mkdir(parents=True)
    (root / "daemon.c").write_text(
        '#include <math.h>\n#include <stddef.h>\n'
        'int service(const unsigned char *p,size_t n)'
        '{return n && cos((double)p[0]) > 0.5;}\n'
        'int main(void){return 0;}\n'
    )
    (build / "makefile").write_text(
        '-include sources.mk\n-include subdir.mk\n-include objects.mk\n'
        'all: daemon\n'
        'daemon: $(OBJS)\n\t@echo linking\n'
        '\tclang -o "daemon" $(OBJS) $(LIBS)\n'
    )
    (build / "sources.mk").write_text('C_SRCS :=\nOBJS :=\n')
    (build / "subdir.mk").write_text(
        'C_SRCS += ../daemon.c\nOBJS += ./daemon.o\n'
        '%.o: ../%.c\n\t@echo compiling\n'
        '\tclang -std=c99 -c -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"\n'
    )
    (build / "objects.mk").write_text('LIBS := -lm\n')
    closure = resolve_recorded_make_target(
        root, None, {root / "daemon.c"}, target_binary=build / "daemon",
    )
    assert closure is not None
    assert closure.link_flags == ("-lm",)
    out = tmp_path / "out"
    out.mkdir()
    harness = out / "fuzz_target.c"
    harness.write_text(
        '#include <stddef.h>\nextern int service(const unsigned char*,size_t);\n'
        'int LLVMFuzzerTestOneInput(const unsigned char *p,size_t n)'
        '{(void)service(p,n);return 0;}\n'
    )
    (out / "harness-plan.json").write_text(json.dumps({
        "required_source_files": ["daemon.c"]
    }))
    binary = build_native(root, harness, out, target_binary=build / "daemon")
    run = subprocess.run([str(binary), "-runs=3"], capture_output=True, text=True, timeout=15)
    assert run.returncode == 0, run.stderr[-1500:]
    plan = json.loads((out / ".native-build" / "build-plan.json").read_text())
    assert plan["selected_make_target"] == "daemon"


def test_generated_make_pattern_rejects_unmapped_link_object(tmp_path: Path):
    root = tmp_path / "source"
    build = root / "Release"
    build.mkdir(parents=True)
    (root / "daemon.c").write_text('int main(void){return 0;}\n')
    (build / "makefile").write_text(
        '-include subdir.mk\n-include objects.mk\nall: daemon\n'
        'daemon: $(OBJS)\n\tclang -o daemon $(OBJS) $(LIBS)\n'
    )
    (build / "subdir.mk").write_text(
        'C_SRCS := ../daemon.c\nOBJS := daemon.o missing.o\n'
        '%.o: ../%.c\n\tclang -c -o "$@" "$<"\n'
    )
    (build / "objects.mk").write_text('LIBS := -lm\n')
    assert resolve_recorded_make_target(
        root, None, {root / "daemon.c"}, target_binary=build / "daemon",
    ) is None


def test_native_build_does_not_substitute_a_different_make_executable(tmp_path: Path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "Makefile").write_text(
        "bin_PROGRAMS = other\nother_SOURCES = other.c\n"
    )
    (root / "other.c").write_text("int main(void){return 0;}\n")
    original = root / "server"
    original.write_bytes(b"original binary")
    out = tmp_path / "out"
    out.mkdir()
    harness = out / "fuzz_target.c"
    harness.write_text(
        "#include <stddef.h>\n"
        "int LLVMFuzzerTestOneInput(const unsigned char *p, size_t n)"
        "{return 0;}\n"
    )
    with pytest.raises(NativeBuildUnresolved, match="no matching source/object/link closure"):
        build_native(root, harness, out, target_binary=original)


@pytest.mark.skipif(not all(shutil.which(x) for x in ("clang", "clang++", "autoconf", "automake", "autoreconf")),
                    reason="requires real Autotools and Clang")
def test_real_autoreconf_configure_multi_executable_binary(tmp_path: Path):
    """Check the parser against actual GNU Automake substitutions, not just a fake Makefile."""
    root = tmp_path / "configured"
    root.mkdir()
    (root / "lib").mkdir()
    (root / "configure.ac").write_text(
        'AC_INIT([hc-test],[0.1])\nAM_INIT_AUTOMAKE([foreign])\n'
        'AC_PROG_CC\nAC_PROG_RANLIB\nAC_CONFIG_FILES([Makefile])\nAC_OUTPUT\n'
    )
    (root / "Makefile.am").write_text(
        'AUTOMAKE_OPTIONS = foreign\n'
        'bin_PROGRAMS = daemon\n'
        'noinst_PROGRAMS = daemon-debug unrelated\n'
        'noinst_LIBRARIES = libparse.a\n'
        'libparse_a_SOURCES = lib/parse.c\n'
        'daemon_SOURCES = daemon.c\n'
        'daemon_LDADD = libparse.a\n'
        'daemon_debug_SOURCES = $(daemon_SOURCES)\n'
        'daemon_debug_LDADD = $(daemon_LDADD)\n'
        'unrelated_SOURCES = unrelated.c\n'
    )
    (root / "daemon.c").write_text(
        '#include <stddef.h>\nextern int parse(const unsigned char*,size_t);\n'
        'int service(const unsigned char *p,size_t n){return parse(p,n);}\n'
        'int main(void){return 0;}\n'
    )
    (root / "lib/parse.c").write_text(
        '#include <stddef.h>\nint parse(const unsigned char *p,size_t n){return n && p[0]==65;}\n'
    )
    (root / "unrelated.c").write_text('int main(void){return 0;}\n')
    for argv in (["autoreconf", "-fi"], ["./configure"]):
        run = subprocess.run(argv, cwd=root, capture_output=True, text=True, timeout=30)
        assert run.returncode == 0, run.stderr[-2000:]
    out = tmp_path / "artifact"
    out.mkdir()
    harness = out / "fuzz_target.c"
    harness.write_text(
        '#include <stddef.h>\nextern int service(const unsigned char*,size_t);\n'
        'int LLVMFuzzerTestOneInput(const unsigned char *p,size_t n)'
        '{(void)service(p,n);return 0;}\n'
    )
    (out / "harness-plan.json").write_text(json.dumps({
        "required_source_files": ["daemon.c", "lib/parse.c"]
    }))
    binary = build_native(root, harness, out)
    run = subprocess.run([str(binary), "-runs=10"], capture_output=True, text=True, timeout=15)
    assert run.returncode == 0, run.stderr[-1500:]
    plan = json.loads((out / ".native-build" / "build-plan.json").read_text())
    assert plan["selected_make_target"] == "daemon"
    assert len(plan["original_sources"]) == 2
    assert "unrelated.c" not in str(plan)
