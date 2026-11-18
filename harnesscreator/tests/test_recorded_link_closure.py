"""An executed Make link command selects one executable from a mixed C build."""
from __future__ import annotations

import hashlib
import argparse
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from harnesscreator.runtime.build_closure import resolve_recorded_link_target
from harnesscreator.runtime.native_build import build_native
from harnesscreator.contexts.harness import _settings


def _recorded_build(tmp_path: Path) -> tuple[Path, Path, Path]:
    cc = shutil.which("cc")
    if not cc:
        pytest.skip("a C compiler is required")
    root = tmp_path / "source"
    root.mkdir()
    (root / "app.c").write_text("int main(void) { return 0; }\n")
    (root / "renamed.c").write_text("int main(void) { return 1; }\n")
    (root / "other.c").write_text("int main(void) { return 2; }\n")
    records = []
    for name, flags in (("app", []), ("renamed", ["-Dmain=renamed_main"]), ("other", [])):
        argv = [cc, *flags, "-c", name + ".c", "-o", name + ".o"]
        subprocess.run(argv, cwd=root, check=True, capture_output=True)
        records.append({"directory": str(root), "file": str(root / (name + ".c")),
                        "arguments": argv, "output": str(root / (name + ".o"))})
    link = [cc, "app.o", "renamed.o", "-o", "app"]
    subprocess.run(link, cwd=root, check=True, capture_output=True)
    db = tmp_path / "analysis" / "compile_commands.json"
    db.parent.mkdir()
    db.write_text(json.dumps(records))
    binary = root / "app"
    record = {"directory": str(root), "arguments": link,
              "target_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "compile_database_sha256": hashlib.sha256(db.read_bytes()).hexdigest()}
    (db.parent / "link_commands.json").write_text(json.dumps(record))
    return root, db, binary


def test_recorded_link_uses_only_the_selected_executable_and_renamed_main(tmp_path: Path):
    if not shutil.which("clang") or not shutil.which("nm"):
        pytest.skip("Clang and nm are required")
    root, db, binary = _recorded_build(tmp_path)
    target = resolve_recorded_link_target(root, db, set(), target_binary=binary)
    assert target is not None
    assert {p.name for p in target.source_paths} == {"app.c", "renamed.c"}
    harness = tmp_path / "fuzz_target.c"
    harness.write_text(
        "#include <stddef.h>\n#include <stdint.h>\n"
        "extern int hc_native_original_main(void);\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) "
        "{ (void)data; (void)size; return hc_native_original_main(); }\n")
    built = build_native(root, harness, tmp_path / "fuzzer", compile_database=db, target_binary=binary)
    plan = json.loads((built.parent / ".native-build" / "build-plan.json").read_text())
    assert [Path(p).name for p in plan["renamed_main"]] == ["app.c"]
    assert {Path(p).name for p in plan["original_sources"]} == {"app.c", "renamed.c"}
    subprocess.run([str(built), "-runs=1"], check=True, capture_output=True, timeout=15)


def test_recorded_link_rejects_stale_binary_and_compiler_database(tmp_path: Path):
    root, db, binary = _recorded_build(tmp_path)
    record_file = db.parent / "link_commands.json"
    original = json.loads(record_file.read_text())
    assert resolve_recorded_link_target(root, db, set(), target_binary=binary) is not None
    record_file.write_text(json.dumps({**original, "target_sha256": "0" * 64}))
    assert resolve_recorded_link_target(root, db, set(), target_binary=binary) is None
    record_file.write_text(json.dumps(original))
    db.write_text(db.read_text() + " ")
    assert resolve_recorded_link_target(root, db, set(), target_binary=binary) is None


def test_context_harness_receives_the_recorded_original_binary(tmp_path: Path):
    root, db, binary = _recorded_build(tmp_path)
    run = tmp_path / "run"
    run.mkdir()
    (run / "project.json").write_text(json.dumps({
        "source_root": str(root), "analysis_compile_database": str(db),
        "analysis_binary": str(binary), "name": "fixture"}))
    settings = _settings(argparse.Namespace(source=None, compile_database=None,
                                            target_binary=None, attempts=1, no_build=False), run)
    assert settings.target_binary == binary
