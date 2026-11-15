"""Provider-free signed HP admission and post-Worker one-shot receipts."""

import asyncio
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

PRODUCT_SRC = Path("/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src")
if str(PRODUCT_SRC) not in sys.path:
    sys.path.insert(0, str(PRODUCT_SRC))

from devtools import original_public_live_entry as entry
from devtools import original_hp_live_optin as hp_live
from vulnerabilityanalysis.llm import CodexAppServerClient


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _assets(tmp_path):
    product = tmp_path / "product"
    source = product / "src"
    source.mkdir(parents=True)
    for relative in hp_live._HP_ASSETS.values():
        path = product / relative
        path.parent.mkdir(exist_ok=True)
        path.write_text(str(relative) + "\n")
    return source, {"enabled": True, "max_items": 1,
                    "max_model_calls": 3,
                    "assets": hp_live.hp_asset_hashes(source)}


def test_signed_hp_requires_separate_mode_and_fixed_asset_hashes(tmp_path):
    source, hp = _assets(tmp_path)
    spec = {"identity": {"product_src": str(source)}, "hp": hp}
    with pytest.raises(ValueError, match="ordinary public development"):
        entry._hp_preimport_admission(spec, hp_mode=False, check_only=False)
    assert entry._hp_preimport_admission(
        spec, hp_mode=True, check_only=False) is True
    assert entry._hp_preimport_admission(
        spec, hp_mode=False, check_only=True) is True
    assert entry._hp_preimport_admission(
        {"identity": spec["identity"]}, hp_mode=False,
        check_only=False) is False
    with pytest.raises(ValueError, match="opt-in is absent"):
        entry._hp_preimport_admission(
            {"identity": spec["identity"]}, hp_mode=True,
            check_only=False)
    (source.parent / "prompts/function_analysis.md").write_text("changed\n")
    with pytest.raises(ValueError, match="pin changed"):
        entry._hp_preimport_admission(spec, hp_mode=True,
                                      check_only=False)
    with pytest.raises(ValueError, match="SHA-256 changed"):
        hp_live.validate_hp_spec(hp, source, enabled=True)


def test_hp_physical_recipe_is_pinned_before_runtime_import(tmp_path, monkeypatch):
    source, hp = _assets(tmp_path)
    builder = tmp_path / "multi_tu_assertion_build.py"
    manifest = tmp_path / "multi_tu_assertion_build_manifest.json"
    builder.write_text("# controlled builder bytes\n")
    manifest.write_text("{}\n")
    hp["physical"] = {
        "enabled": True, "builder_path": str(builder),
        "builder_sha256": _sha(builder),
        "manifest_path": str(manifest),
        "manifest_sha256": _sha(manifest),
        "guided_seconds": 1, "total_wall_seconds": 120,
        "output_limit_bytes": 4_000_000,
    }
    spec = {"identity": {"product_src": str(source)}, "hp": hp}
    with pytest.raises(ValueError, match="builder is not trusted"):
        entry._hp_preimport_admission(
            spec, hp_mode=False, check_only=True)
    monkeypatch.setattr(entry, "_TRUSTED_MD4C_HP_BUILDER", builder)
    monkeypatch.setattr(entry, "_TRUSTED_MD4C_HP_BUILDER_SHA256", _sha(builder))
    monkeypatch.setattr(entry, "_TRUSTED_MD4C_HP_MANIFEST_SHA256", _sha(manifest))
    assert entry._hp_preimport_admission(
        spec, hp_mode=False, check_only=True) is True
    manifest.write_text('{"changed":true}\n')
    with pytest.raises(ValueError, match="manifest pin changed"):
        entry._hp_preimport_admission(
            spec, hp_mode=False, check_only=True)


def test_hp_check_only_does_not_claim_live_readiness(tmp_path, monkeypatch, capsys):
    spec_path = tmp_path / "spec.json"
    spec_path.write_text("{}")
    monkeypatch.setattr(entry, "_bootstrap", lambda *args, **kwargs: {
        "hp": {"enabled": True}})
    assert entry.main(["--spec", str(spec_path), "--spec-sha256", "a" * 64,
                       "--check-only"]) == 2
    assert json.loads(capsys.readouterr().out) == {
        "status": "INCOMPLETE_ADMISSION",
        "reason": "HP_LIVE_MODE_NOT_VALIDATED",
        "hp_preimport_pins_verified": True,
        "hp_physical_recipe_files_pinned": False,
        "model_physical_calls": 0,
    }


def test_hp_client_preserves_product_no_tool_instructions(tmp_path, monkeypatch):
    observed = []

    async def product_request(self, method, params):
        observed.append((method, dict(params), self._fbv2_request_stage))
        return {"ok": True}

    monkeypatch.setattr(CodexAppServerClient, "_request", product_request)
    client_type = hp_live._hp_client_type(lambda: None)
    client = client_type(cwd=tmp_path, executable="unused")
    params = {"baseInstructions": "No tools", "developerInstructions":
              "Unknown is not safe", "dynamicTools": [],
              "approvalPolicy": "never", "sandbox": "read-only"}
    asyncio.run(client._request("thread/start", params))
    assert observed == [("thread/start", params, "thread/start")]
    assert client._fbv2_request_stage is None
    assert client_type.start is not CodexAppServerClient.start


def test_signed_hp_run_claim_is_one_shot_and_result_is_separate(
        tmp_path, monkeypatch):
    source, hp = _assets(tmp_path)
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    (run_dir / "model_events").mkdir(mode=0o700)
    account = {"stop_status": None, "active": {}}
    gate = SimpleNamespace(snapshot=lambda: {"physical": 4})
    bound = SimpleNamespace(
        identity=SimpleNamespace(product_src=source, run_dir=run_dir,
                                 task_id="task", run_id="run"),
        model_gate=gate,
        process_ledger=SimpleNamespace(
            receipt_snapshot=lambda: (account, "a" * 64)),
        caps=SimpleNamespace(physical_model_calls=32),
        recheck=lambda: None)
    original = {"status": "EXECUTED_UNVERIFIED", "task_id": "task",
                "run_id": "run", "original_result": {"worker_id": "worker"}}
    calls = []

    async def scripted_hp(**kwargs):
        calls.append(kwargs)
        assert (run_dir / "HP_RUN_CLAIM.json").is_file()
        return {"status": "HP_POST_WORKER_COMPLETE", "selected_count": 1,
                "rows": [{"status": "NO_SAFE_ASSUMPTION"}],
                "security_gate_credit": "NOT_CREDITED"}

    monkeypatch.setattr(hp_live, "run_post_worker_hp", scripted_hp)
    spec_path = tmp_path / "signed-spec.json"
    spec_path.write_text(json.dumps({"hp": hp}, sort_keys=True))
    spec_sha = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    result = hp_live.run_signed_hp_after_worker(
        bound, original, hp, spec_path=spec_path, spec_sha256=spec_sha)
    assert result["status"] == "HP_POST_WORKER_COMPLETE"
    assert result["analysis_status"] == "COMPLETE"
    assert result["physical_execution_status"] == "NOT_REQUESTED"
    assert result["completion_scope"] == "ANALYSIS_ONLY"
    assert result["model_physical_calls"] == 0
    assert len(calls) == 1
    receipt = json.loads(Path(result["result_path"]).read_text())
    assert receipt["original_status"] == "EXECUTED_UNVERIFIED"
    assert receipt["physical_execution_status"] == "NOT_REQUESTED"
    assert receipt["security_gate_credit"] == "NOT_CREDITED"
    assert hashlib.sha256(Path(result["result_path"]).read_bytes()).hexdigest() == (
        result["result_sha256"])
    with pytest.raises(FileExistsError):
        hp_live.run_signed_hp_after_worker(
            bound, original, hp, spec_path=spec_path, spec_sha256=spec_sha)
    assert len(calls) == 1
