"""Fail-closed checks for the explicit, provider-free original launcher."""

import hashlib
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest

from devtools import original_public_dev as launcher


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fixture(tmp_path, monkeypatch):
    product_src = tmp_path / "product" / "src"
    issuer = product_src / "vulnerabilityanalysis" / "official_harness.py"
    issuer.parent.mkdir(parents=True)
    issuer.write_text("# pinned issuer fixture\n")
    task = tmp_path / "task"
    (task / "repo").mkdir(parents=True)
    binary = tmp_path / "binary"
    binary.write_bytes(b"fixture binary")
    contract = tmp_path / "contract.json"
    contract.write_text(json.dumps({
        "kind": "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2",
        "local": {"harness_file": str(tmp_path / "harness"),
                  "binary": str(binary), "normal_seed": str(tmp_path / "seed")},
        "target": {"source_root": str(tmp_path / "source")},
    }))
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "schema": "fbv2-prebuilt-v1", "project_name": "fixture",
        "source_commit": "a" * 40, "fuzzer_name": "fuzz_fixture",
        "asan_binary": {"sha256": _sha(binary)},
    }))
    calls = []
    issuer_module = ModuleType("vulnerabilityanalysis.official_harness")
    issuer_module.__file__ = str(issuer)

    def issue(**kwargs):
        calls.append("qualification")
        return SimpleNamespace(product_issued=True,
            contract_kind="OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2",
            binary=binary, binary_sha256=_sha(binary),
            upstream_revision="a" * 40)

    issuer_module.issue_official_pinned_qualification = issue
    monkeypatch.setitem(sys.modules, "vulnerabilityanalysis.official_harness", issuer_module)

    def prepare(*_args):
        calls.append("prebuilt")
        return {"fuzzer_name": "fuzz_fixture", "asan_binary": str(binary),
                "function_count": 4, "reachable_count": 3}

    monkeypatch.setattr(launcher, "prepare_prebuilt", prepare)
    args = dict(product_src=product_src, product_issuer_sha256=_sha(issuer),
                contract_path=contract, contract_sha256=_sha(contract),
                manifest_path=manifest, manifest_sha256=_sha(manifest),
                task_path=task, oss_fuzz_checkout=tmp_path / "oss",
                upstream_checkout=tmp_path / "upstream")
    return args, calls, issuer_module


def test_preflight_reissues_product_qualification_before_preparing(tmp_path, monkeypatch):
    args, calls, _ = _fixture(tmp_path, monkeypatch)
    result = launcher.preflight(**args)
    assert result["status"] == "PINNED_PROVIDER_FREE"
    assert result["product_issued"] is True
    assert result["model_calls"] == result["target_executions"] == 0
    assert calls == ["qualification", "prebuilt"]


def test_preflight_rejects_unqualified_input_before_preparing(tmp_path, monkeypatch):
    args, calls, issuer_module = _fixture(tmp_path, monkeypatch)
    issuer_module.issue_official_pinned_qualification = lambda **_kwargs: None
    with pytest.raises(ValueError, match="product-issued qualification"):
        launcher.preflight(**args)
    assert calls == []


def test_preflight_rejects_changed_manifest_before_qualification(tmp_path, monkeypatch):
    args, calls, _ = _fixture(tmp_path, monkeypatch)
    args["manifest_path"].write_text("{}")
    with pytest.raises(ValueError, match="prebuilt manifest identity mismatch"):
        launcher.preflight(**args)
    assert calls == []


def test_live_mode_is_closed_before_any_qualification_or_execution(tmp_path, monkeypatch):
    args, calls, _ = _fixture(tmp_path, monkeypatch)
    argv = ["--mode", "live"]
    for name, value in args.items():
        argv.extend(["--" + name.replace("_", "-"), str(value)])
    with pytest.raises(SystemExit) as exc:
        launcher.main(argv)
    assert exc.value.code == 2
    assert calls == []


def test_scripted_factory_constructs_original_worker_without_running(tmp_path, monkeypatch, repos):
    args, calls, _ = _fixture(tmp_path, monkeypatch)
    admission = launcher.admit_pinned(**args)
    factory_calls = []

    def forbidden_factory(*_args):
        factory_calls.append("called")
        raise AssertionError("provider-free factory was invoked")

    executor, strategy = launcher.build_provider_free_executor(
        admission, workspace=tmp_path / "worker", task_path=args["task_path"],
        repos=repos, task_id="fixture-task", llm_client_factory=forbidden_factory,
        original_global_bridge_factory=forbidden_factory)
    assert executor.fuzzer_binary_path == admission.qualification.binary
    assert executor.require_original_global_bridge is True
    assert strategy.executor is executor
    assert factory_calls == []
    assert calls == ["qualification", "prebuilt"]


def test_scripted_factory_rejects_missing_role_factory(tmp_path, monkeypatch, repos):
    args, _, _ = _fixture(tmp_path, monkeypatch)
    admission = launcher.admit_pinned(**args)
    with pytest.raises(ValueError, match="qualified pinned dependencies"):
        launcher.build_provider_free_executor(
            admission, workspace=tmp_path / "worker", task_path=args["task_path"],
            repos=repos, task_id="fixture-task", llm_client_factory=None,
            original_global_bridge_factory=lambda *_args: None)
    assert not (tmp_path / "worker").exists()
