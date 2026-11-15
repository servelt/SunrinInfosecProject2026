"""Regression boundaries for the reviewed cJSON HP live candidate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


CANDIDATE = (Path(__file__).resolve().parents[3] / "_HISTORY" /
             "legacy_2026-10_11" / "hp_cjson_official_qualification_toctou_v2_20261108")
BUILDER = CANDIDATE / "cjson_assertion_build.py"
MANIFEST = CANDIDATE / "cjson_assertion_build_manifest.json"
ENGINE = Path(__file__).resolve().parent.parent
PREBUILT = ENGINE / "documentation" / "cjson_prebuilt_provider_free_20261102"
OLD_SELECTION = Path(
    "/home/dawne/SunrinInfosecProject2026/reference_archive_20261028/"
    "by_date/20261023/hp-cjson-independent-preflight-20261023/"
    "OFFLINE_SELECTION_PREVIEW.json")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run(*args: Path | str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/usr/bin/python3.12", "-I", str(BUILDER),
         "--manifest-sha256", _sha(MANIFEST), *map(str, args)],
        capture_output=True, text=True,
        check=False, timeout=120)


def test_builder_uses_pinned_header_and_publishes_without_overwrite(tmp_path):
    """A sibling header cannot replace the reviewed cJSON.h."""
    row = json.loads(MANIFEST.read_text())
    shutil.copyfile(Path(row["original_source"]["path"]), tmp_path / "cJSON.c")
    (tmp_path / "cJSON.h").write_text(
        '#error "untrusted sibling header was selected"\n', encoding="utf-8")
    output = tmp_path / "instrumented-target"
    first = _run(tmp_path / "cJSON.c", "-o", output)
    assert first.returncode == 0, first.stderr
    assert output.is_file() and not output.is_symlink()
    before = _sha(output)

    second = _run(tmp_path / "cJSON.c", "-o", output)
    assert second.returncode != 0
    assert _sha(output) == before


def test_builder_rejects_cross_directory_and_unlisted_output(tmp_path):
    row = json.loads(MANIFEST.read_text())
    source_dir = tmp_path / "source"
    output_dir = tmp_path / "other"
    source_dir.mkdir()
    output_dir.mkdir()
    shutil.copyfile(Path(row["original_source"]["path"]),
                    source_dir / "cJSON.c")
    assert _run(source_dir / "cJSON.c", "-o",
                output_dir / "instrumented-target").returncode != 0
    assert _run(source_dir / "cJSON.c", "-o",
                source_dir / "arbitrary-target").returncode != 0


def test_builder_rejects_changed_harness_relative_header(tmp_path):
    """The header selected by Harness ../cJSON.h is an independent pin."""
    isolated = tmp_path / "candidate"
    isolated.mkdir()
    builder = isolated / BUILDER.name
    manifest = isolated / MANIFEST.name
    shutil.copy2(BUILDER, builder)
    row = json.loads(MANIFEST.read_text())
    target = tmp_path / "target"
    upstream = tmp_path / "upstream"
    (upstream / "fuzzing").mkdir(parents=True)
    target.mkdir()
    for name in ("cJSON.c", "cJSON.h"):
        shutil.copyfile(Path(row[f"original_source" if name == "cJSON.c"
                                 else "header_source"]["path"]), target / name)
    shutil.copyfile(Path(row["harness_source"]["path"]),
                    upstream / "fuzzing" / "cjson_read_fuzzer.c")
    shutil.copyfile(target / "cJSON.h", upstream / "cJSON.h")
    official = isolated / "official-binary"
    shutil.copyfile(Path(row["official_binary"]["path"]), official)
    row["source_root"] = str(target.resolve())
    row["original_source"] = {
        "path": str((target / "cJSON.c").resolve()),
        "sha256": _sha(target / "cJSON.c")}
    row["header_source"] = {
        "path": str((target / "cJSON.h").resolve()),
        "sha256": _sha(target / "cJSON.h")}
    row["harness_source"] = {
        "path": str((upstream / "fuzzing" / "cjson_read_fuzzer.c").resolve()),
        "sha256": _sha(upstream / "fuzzing" / "cjson_read_fuzzer.c")}
    row["harness_header_source"] = {
        "path": str((upstream / "cJSON.h").resolve()),
        "sha256": _sha(upstream / "cJSON.h")}
    row["official_binary"] = {
        "path": str(official.resolve()), "sha256": _sha(official)}
    row["source_files"] = {
        "cJSON.c": row["original_source"]["sha256"],
        "cJSON.h": row["header_source"]["sha256"],
        "fuzzing/cjson_read_fuzzer.c": row["harness_source"]["sha256"],
    }
    row["allowed_translation_units"] = {
        "cJSON.c": row["original_source"]["sha256"]}
    manifest.write_text(json.dumps(row, sort_keys=True, indent=2) + "\n")

    # Change only the distinct physical header selected by the Harness.
    (upstream / "cJSON.h").write_text(
        '#error "changed Harness-relative header"\n', encoding="utf-8")
    evaluation = tmp_path / "evaluation"
    evaluation.mkdir()
    shutil.copyfile(target / "cJSON.c", evaluation / "cJSON.c")
    done = subprocess.run(
        ["/usr/bin/python3.12", "-I", str(builder),
         "--manifest-sha256", _sha(manifest),
         str(evaluation / "cJSON.c"), "-o",
         str(evaluation / "instrumented-target")],
        capture_output=True, text=True, check=False, timeout=120)
    assert done.returncode != 0
    assert not (evaluation / "instrumented-target").exists()


def test_builder_log_is_exclusive_and_does_not_follow_symlink(tmp_path):
    row = json.loads(MANIFEST.read_text())
    shutil.copyfile(Path(row["original_source"]["path"]), tmp_path / "cJSON.c")
    victim = tmp_path / "victim.txt"
    victim.write_text("sentinel\n", encoding="utf-8")
    (tmp_path / "cjson-assertion-build-instrumented-target.log").symlink_to(victim)
    done = _run(tmp_path / "cJSON.c", "-o", tmp_path / "instrumented-target")
    assert done.returncode != 0
    assert victim.read_text(encoding="utf-8") == "sentinel\n"
    assert not (tmp_path / "instrumented-target").exists()


def test_builder_requires_the_exact_parent_approved_manifest_digest(tmp_path):
    row = json.loads(MANIFEST.read_text())
    shutil.copyfile(Path(row["original_source"]["path"]), tmp_path / "cJSON.c")
    done = subprocess.run(
        ["/usr/bin/python3.12", "-I", str(BUILDER),
         "--manifest-sha256", "0" * 64, str(tmp_path / "cJSON.c"),
         "-o", str(tmp_path / "instrumented-target")],
        capture_output=True, text=True, check=False, timeout=120)
    assert done.returncode != 0
    assert not (tmp_path / "instrumented-target").exists()


def test_absolute_interpreter_contract_ignores_hostile_path(tmp_path):
    row = json.loads(MANIFEST.read_text())
    shutil.copyfile(Path(row["original_source"]["path"]), tmp_path / "cJSON.c")
    hostile = tmp_path / "hostile"
    hostile.mkdir()
    marker = tmp_path / "path-python-ran"
    fake = hostile / "python3"
    fake.write_text(
        "#!/bin/sh\nprintf hijacked > " + str(marker) + "\nexit 0\n",
        encoding="utf-8")
    fake.chmod(0o755)
    env = dict(os.environ)
    env["PATH"] = str(hostile) + ":" + env.get("PATH", "")
    output = tmp_path / "instrumented-target"
    done = subprocess.run(
        [str(BUILDER), "--manifest-sha256", _sha(MANIFEST),
         str(tmp_path / "cJSON.c"), "-o", str(output)],
        capture_output=True, text=True, check=False, timeout=120, env=env)
    assert done.returncode == 0, done.stderr
    assert output.is_file()
    assert not marker.exists()


def test_compiler_path_replacement_after_snapshot_cannot_execute_marker(
        tmp_path, monkeypatch):
    isolated = tmp_path / "candidate"
    isolated.mkdir()
    builder = isolated / BUILDER.name
    manifest = isolated / MANIFEST.name
    shutil.copy2(BUILDER, builder)
    row = json.loads(MANIFEST.read_text())
    compiler = isolated / "compiler"
    replacement = isolated / "replacement"
    marker = tmp_path / "replacement-ran"
    compiler.write_text(
        "#!/bin/sh\nout=\nwhile [ $# -gt 0 ]; do\n"
        "  if [ \"$1\" = -o ]; then shift; out=$1; fi\n  shift\n"
        "done\nprintf admitted > \"$out\"\n",
        encoding="utf-8")
    replacement.write_text(
        "#!/bin/sh\nprintf replaced > " + str(marker) + "\nexit 1\n",
        encoding="utf-8")
    compiler.chmod(0o755)
    replacement.chmod(0o755)
    row["builder_sha256"] = _sha(builder)
    row["compiler"] = {"path": str(compiler), "sha256": _sha(compiler)}
    manifest.write_text(json.dumps(row, sort_keys=True, indent=2) + "\n")
    source = tmp_path / "cJSON.c"
    shutil.copyfile(Path(row["original_source"]["path"]), source)
    output = tmp_path / "instrumented-target"

    module_spec = importlib.util.spec_from_file_location(
        "isolated_cjson_assertion_builder", builder)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    real_run = subprocess.run

    def replace_original_then_run(*args, **kwargs):
        replacement.replace(compiler)
        return real_run(*args, **kwargs)

    monkeypatch.setattr(module.subprocess, "run", replace_original_then_run)
    monkeypatch.setattr(
        sys, "argv", [str(builder), "--manifest-sha256", _sha(manifest),
                      str(source), "-o", str(output)])
    assert module.main() == 0
    assert output.read_bytes() == b"admitted"
    assert not marker.exists()


def test_assertion_build_semantics_match_original_cjson_core_configuration():
    row = json.loads(MANIFEST.read_text())
    assert row["fixed_flags"] == [
        "-DCJSON_API_VISIBILITY", "-DCJSON_EXPORT_SYMBOLS",
        "-DENABLE_LOCALES", "-std=c89", "-O1", "-g",
        "-fno-omit-frame-pointer", "-fsanitize=fuzzer,address",
    ]
    assert row["harness_header_source"]["sha256"] == (
        row["header_source"]["sha256"])
    receipt = json.loads((CANDIDATE / "BUILD_RECEIPT.json").read_text())
    original_compile = receipt["build_steps"][0]["argv"]
    for option in ("-DCJSON_API_VISIBILITY", "-DCJSON_EXPORT_SYMBOLS",
                   "-DENABLE_LOCALES", "-std=c89", "-O1", "-g",
                   "-fno-omit-frame-pointer"):
        assert option in original_compile


def test_aligned_preprocessor_keeps_locale_decimal_point_path():
    row = json.loads(MANIFEST.read_text())
    semantic_flags = [flag for flag in row["fixed_flags"]
                      if not flag.startswith("-fsanitize=")]
    done = subprocess.run(
        [row["compiler"]["path"], *semantic_flags, "-E",
         "-I" + row["source_root"], row["original_source"]["path"]],
        capture_output=True, text=True, check=False, timeout=120)
    assert done.returncode == 0, done.stderr
    assert "localeconv" in done.stdout


def test_frozen_scheduler_order_is_filtered_by_official_harness_reachability():
    """Preserve the neutral order while rejecting its unreachable rank 1."""
    rows = json.loads((PREBUILT / "functions.json").read_text())
    reached = {row["name"] for row in rows
               if "cjson_read_fuzzer" in row.get("reached_by_fuzzers", [])}
    ranked = json.loads(OLD_SELECTION.read_text())["selection"]
    selected = next(row for row in ranked if row["function"] in reached)
    assert ranked[0]["function"] == "cJSON_ParseWithLength"
    assert "cJSON_ParseWithLength" not in reached
    assert selected["function"] == "cJSON_Delete"
    assert selected["ordinal"] == 2

    evidence = json.loads((
        CANDIDATE / "OFFICIAL_HARNESS_REACHABILITY_SELECTION.json").read_text())
    assert evidence["original_rank_1_rejected"] == "cJSON_ParseWithLength"
    assert evidence["selected_function"] == "cJSON_Delete"
    assert evidence["official_functions_sha256"] == _sha(
        CANDIDATE / "reachability" / "functions.json")


def test_candidate_bundles_exact_upstream_harness_and_git_comparison():
    comparison = json.loads((
        CANDIDATE / "UPSTREAM_GIT_FILE_COMPARISON.json").read_text())
    assert all(row["all_equal"] is True for row in comparison["files"])
    harness = next(row for row in comparison["files"]
                   if row["relative_path"] == "fuzzing/cjson_read_fuzzer.c")
    assert harness["bundled_sha256"] == (
        "a8e9443438bfb323dcaed5af86dfc3fae7dfbc970a992b0af569a58e1b8c9376")
    assert _sha(CANDIDATE / "upstream-source" /
                "fuzzing/cjson_read_fuzzer.c") == harness["bundled_sha256"]


def test_candidate_binary_and_prebuilt_catalog_share_the_same_pin():
    contract = json.loads((
        CANDIDATE / "CONTRACT_DRAFT_PENDING_REVIEW.json").read_text())
    prebuilt = json.loads((
        PREBUILT / "candidate-prebuilt-manifest.json").read_text())
    assert contract["local"]["binary_sha256"] == (
        prebuilt["asan_binary"]["sha256"])
    assert Path(contract["local"]["binary"]) == Path(
        prebuilt["asan_binary"]["path"])
    assert contract["local"]["harness_sha256"] == (
        prebuilt["source_files"]["fuzzing/cjson_read_fuzzer.c"])
