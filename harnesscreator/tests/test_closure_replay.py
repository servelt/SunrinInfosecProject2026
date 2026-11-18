"""A rebuild from a copy of the tree replays the original harness build's closure."""

import json
from pathlib import Path

import pytest

from harnesscreator.runtime.native_build import NativeBuildUnresolved, _replay_closure


def _tree(base: Path) -> Path:
    for rel in ("src/main.c", "src/util.c", "src/libs/x.c"):
        (base / rel).parent.mkdir(parents=True, exist_ok=True)
        (base / rel).write_text("int x;\n")
    return base


def _legacy_plan(orig: Path, path: Path) -> Path:
    cc = lambda src, rename=False: (
        ["/usr/bin/clang", "-O1", "-g", "-fsanitize=fuzzer-no-link,address,undefined", "-fPIC", "-fno-inline",
         "-I", str(orig), "-I", str(orig / "src"), "-I", str(orig / "src/libs")]
        + (["-Dmain=hc_native_original_main"] if rename else [])
        + ["-I", str(orig / "include"), "-DWITH_SSL", f"-I{orig}/src/libs", "-c", str(src), "-o", "o.o"])
    plan = {"source_root": str(orig), "harness": "/elsewhere/fuzz_target.c",
            "original_sources": [str(orig / "src/main.c"), str(orig / "src/util.c"), str(orig / "src/libs/x.c")],
            "renamed_main": [str(orig / "src/main.c")], "link_flags_from_build_graph": ["-pthread", "-lssl"],
            "compile_commands": [cc(orig / "src/main.c", True), cc(orig / "src/util.c"), cc(orig / "src/libs/x.c"),
                                 cc(Path("/elsewhere/fuzz_target.c"))]}
    path.write_text(json.dumps(plan))
    return path


def test_legacy_plan_is_moved_onto_the_copy(tmp_path: Path):
    orig, copy = _tree(tmp_path / "orig"), _tree(tmp_path / "copy")
    units, links, mains, _ = _replay_closure(_legacy_plan(orig, tmp_path / "plan.json"), copy.resolve())
    assert [u.source for u in units] == [copy.resolve() / "src/main.c", copy.resolve() / "src/util.c",
                                         copy.resolve() / "src/libs/x.c"]
    # The builder's own include block and main rename are not project flags; the project's are moved.
    assert units[0].flags == ("-I", str(copy.resolve() / "include"), "-DWITH_SSL", f"-I{copy.resolve()}/src/libs")
    assert mains == [copy.resolve() / "src/main.c"] and links == ["-pthread", "-lssl"]


def test_recorded_units_are_used_as_they_are(tmp_path: Path):
    orig, copy = _tree(tmp_path / "orig"), _tree(tmp_path / "copy")
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"source_root": str(orig), "units": [{"source": str(orig / "src/util.c"),
                                                                     "flags": ["-I", str(orig / "src")]}],
                                "renamed_main": [], "link_flags_from_build_graph": []}))
    units, _, _, _ = _replay_closure(plan, copy.resolve())
    assert units[0].source == copy.resolve() / "src/util.c" and units[0].flags == ("-I", str(copy.resolve() / "src"))


def test_a_plan_that_does_not_map_onto_the_copy_is_refused(tmp_path: Path):
    orig, copy = _tree(tmp_path / "orig"), tmp_path / "empty"
    copy.mkdir()
    with pytest.raises(NativeBuildUnresolved):
        _replay_closure(_legacy_plan(orig, tmp_path / "plan.json"), copy.resolve())


def test_language_semantics_flags_survive_the_compile_record():
    from harnesscreator.runtime.native_build import _flags_from_compile_record
    record = {"arguments": ["gcc", "-fcommon", "-std=c99", "-O3", "-fno-strict-aliasing", "-m32",
                            "-fplugin=/x.so", "-DX=1", "-c", "a.c", "-o", "a.o"]}
    flags = _flags_from_compile_record(record, Path("/src"))
    assert "-fcommon" in flags and "-fno-strict-aliasing" in flags and "-DX=1" in flags
    assert "-m32" not in flags and not any(f.startswith("-fplugin") for f in flags)
