"""Provider-free signed HP admission and post-Worker one-shot receipts."""

import asyncio
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

PRODUCT_SRC = Path(__file__).resolve().parents[2] / "product" / "src"
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


def test_bounded_nohint_hp_five_call_cap_is_opt_in_only(tmp_path):
    source, hp = _assets(tmp_path)
    hp["max_model_calls"] = 5
    hp_live.validate_hp_spec(hp, source, enabled=True,
                             bounded_nohint_hp=True)
    with pytest.raises(ValueError, match="opt-in or cap"):
        hp_live.validate_hp_spec(hp, source, enabled=True)
    hp["max_model_calls"] = 4
    with pytest.raises(ValueError, match="opt-in or cap"):
        hp_live.validate_hp_spec(hp, source, enabled=True,
                                 bounded_nohint_hp=True)


def test_hp_only_five_call_cap_is_explicitly_admitted(tmp_path):
    source, hp = _assets(tmp_path)
    hp["max_model_calls"] = 5
    hp_live.validate_hp_spec(hp, source, enabled=True, hp_only=True)
    with pytest.raises(ValueError, match="opt-in or cap"):
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


def test_exact_cjson_physical_recipe_is_pinned_before_runtime_import(tmp_path, monkeypatch):
    source, hp = _assets(tmp_path)
    root = (Path(__file__).resolve().parents[3] / "_HISTORY" /
            "legacy_2026-10_11" / "hp_cjson_official_qualification_toctou_v2_20261108")
    builder = root / "cjson_assertion_build.py"
    manifest = root / "cjson_assertion_build_manifest.json"
    monkeypatch.setattr(entry, "_TRUSTED_CJSON_HP_BUILDER", builder)
    hp["physical"] = {
        "enabled": True, "builder_path": str(builder),
        "builder_sha256": _sha(builder),
        "manifest_path": str(manifest),
        "manifest_sha256": _sha(manifest),
        "guided_seconds": 1, "total_wall_seconds": 120,
        "output_limit_bytes": 4_000_000,
    }
    spec = {"identity": {"product_src": str(source)}, "hp": hp}
    assert entry._hp_preimport_admission(
        spec, hp_mode=False, check_only=True) is True
    hp["physical"]["builder_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="builder is not trusted"):
        entry._hp_preimport_admission(
            spec, hp_mode=False, check_only=True)


def test_cjson_pending_review_cannot_issue_official_qualification():
    from vulnerabilityanalysis.official_harness import (
        issue_official_pinned_qualification, validate_v2_local_pins)

    root = (Path(__file__).resolve().parents[3] / "_HISTORY" /
            "legacy_2026-10_11" / "hp_cjson_official_qualification_20261105")
    contract_path = root / "CONTRACT_DRAFT_PENDING_REVIEW.json"
    contract = json.loads(contract_path.read_text())
    source_root = Path(contract["target"]["source_root"])
    arguments = {
        "source_root": source_root,
        "harness": Path(contract["local"]["harness_file"]),
        "binary": Path(contract["local"]["binary"]),
        "normal_seed": Path(contract["local"]["normal_seed"]),
        "oss_fuzz_checkout": Path(
            "/home/dawne/SunrinInfosecProject2026/reference/"
            "blind2_v2_preparation_20261027/review/"
            "CJSON_V2_DEV_DRAFT_20261030/oss_fuzz_checkout"),
        "upstream_checkout": Path(
            "/home/dawne/SunrinInfosecProject2026/reference/"
            "blind2_v2_preparation_20261027/review/"
            "CJSON_V2_INDEPENDENT_REBUILD_20261102/upstream_asan_final"),
    }
    assert json.loads((root / "API_REVIEW_PENDING.json").read_text())[
        "status"] == "PENDING_INDEPENDENT_REVIEW"
    assert validate_v2_local_pins(contract, **arguments) is None
    assert issue_official_pinned_qualification(
        contract_path=contract_path,
        approved_contract_sha256=_sha(contract_path), **arguments) is None


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


def test_hp_pipeline_separates_per_turn_timeout_from_campaign_wall(
        tmp_path, monkeypatch):
    """A larger campaign clock must not silently enlarge each model turn."""
    run_dir = tmp_path / "run"
    event_dir = run_dir / "model_events"
    event_dir.mkdir(parents=True, mode=0o700)
    event_dir.chmod(0o700)
    hp = {"enabled": True, "max_items": 1, "max_model_calls": 4,
          "assets": {}}
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps({"hp": hp}, sort_keys=True))
    spec_sha = _sha(spec_path)
    observed = []

    class Transport:
        def __init__(self, **kwargs):
            observed.append(kwargs)

    monkeypatch.setattr(hp_live, "_hp_client_type", lambda _check: Transport)
    monkeypatch.setattr(hp_live, "validate_hp_spec",
                        lambda *_args, **_kwargs: None)
    bound = SimpleNamespace(
        identity=SimpleNamespace(
            run_dir=run_dir, task_path=tmp_path, codex_role_models=None,
            codex_model="fixture", codex_effort="max",
            product_src=tmp_path / "product-src",
            codex_executable=tmp_path / "codex",
            codex_executable_sha256="a" * 64),
        caps=SimpleNamespace(
            model_wall_seconds=1200, model_turn_seconds=600,
            bounded_nohint_dev=False),
        model_gate=object(), recheck=lambda: None)
    work = SimpleNamespace(function_id="function", direction_id="direction")

    pipeline = hp_live._pipeline_factory(
        bound, hp, "function_analysis", spec_path, spec_sha,
        hp_only=True)(work)

    assert pipeline is not None
    assert observed[0]["timeout_seconds"] == 600
    assert observed[0]["timeout_seconds"] != bound.caps.model_wall_seconds


def test_parallel_hp_pipeline_shares_sp_host_tool_boundary(tmp_path, monkeypatch):
    run_dir = tmp_path / "run"
    event_dir = run_dir / "model_events"
    event_dir.mkdir(parents=True, mode=0o700)
    hp = {"enabled": True, "max_items": 1, "max_model_calls": 4,
          "assets": {}}
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps({"hp": hp}, sort_keys=True))
    gate = object()
    lock = asyncio.Lock()

    def sp_factory(_role, _owner):
        raise AssertionError("pipeline construction must not start SP")

    sp_factory._fbv2_campaign_gate = gate
    sp_factory._fbv2_campaign_boundary_lock = lock

    class Transport:
        def __init__(self, **_kwargs):
            pass

    monkeypatch.setattr(hp_live, "_hp_client_type", lambda _check: Transport)
    monkeypatch.setattr(hp_live, "validate_hp_spec",
                        lambda *_args, **_kwargs: None)
    bound = SimpleNamespace(
        identity=SimpleNamespace(
            run_dir=run_dir, task_path=tmp_path, codex_role_models=None,
            codex_model="fixture", codex_effort="max",
            product_src=tmp_path / "product-src",
            codex_executable=tmp_path / "codex",
            codex_executable_sha256="a" * 64),
        caps=SimpleNamespace(model_turn_seconds=600,
                             bounded_nohint_dev=False),
        model_gate=gate, recheck=lambda: None,
        strategy=SimpleNamespace(llm_client_factory=sp_factory),
        executor=SimpleNamespace(parallel_hp_async_factory=object()))
    work = SimpleNamespace(function_id="function", direction_id="direction")

    for role in ("function_analysis", "assertion_generator"):
        pipeline = hp_live._pipeline_factory(
            bound, hp, role, spec_path, _sha(spec_path))(work)
        assert pipeline.provider._boundary_lock is lock

    sp_factory._fbv2_campaign_gate = object()
    with pytest.raises(ValueError, match="boundary is not shared"):
        hp_live._pipeline_factory(
            bound, hp, "function_analysis", spec_path, _sha(spec_path))


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
    # This fixture checks the one-shot claim, not Worker/DB settlement.
    monkeypatch.setattr(hp_live, "_preflight", lambda *_args: None)
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


def test_combined_hp_uses_shared_cap_and_makes_zero_calls_when_unavailable(
        tmp_path, monkeypatch):
    source, hp = _assets(tmp_path)
    hp["max_model_calls"] = 3
    run_dir = tmp_path / "combined-budget-run"
    run_dir.mkdir(mode=0o700)
    (run_dir / "model_events").mkdir(mode=0o700)
    spec = {
        "development_seed_scope": {
            "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_POST_WORKER_DEV_V1",
            "seed_directions": 1, "sp_function_limit": None,
            "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1",
            "security_invariant_focus": "LIFETIME_OWNERSHIP",
            "direction_selection":
                "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
            "pov_attempts_per_candidate": 3,
            "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2}},
        "hp": hp,
    }
    spec_path = tmp_path / "combined-budget-spec.json"
    spec_path.write_text(json.dumps(spec, sort_keys=True))
    spec_sha = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    gate = SimpleNamespace(snapshot=lambda: {"physical": 118})
    bound = SimpleNamespace(
        identity=SimpleNamespace(product_src=source, run_dir=run_dir,
                                 task_id="task", run_id="run"),
        model_gate=gate,
        process_ledger=SimpleNamespace(receipt_snapshot=lambda: (
            {"stop_status": None, "active": {}}, "a" * 64)),
        caps=SimpleNamespace(physical_model_calls=120,
                             bounded_nohint_dev=False,
                             sp_concurrent_queue=True),
        recheck=lambda: None)
    worker = {"status": "EXECUTED_UNVERIFIED", "task_id": "task",
              "run_id": "run", "sp_analysis_status": "COMPLETED",
              "original_result": {"worker_id": "worker"}}
    monkeypatch.setattr(
        hp_live, "_combined_concurrent_hp_selection",
        lambda *_args: (("function", "direction"), "b" * 64))
    monkeypatch.setattr(hp_live, "_preflight", lambda *_args: None)

    async def forbidden_hp(**_kwargs):
        raise AssertionError("HP must not call a model without shared budget")

    monkeypatch.setattr(hp_live, "run_post_worker_hp", forbidden_hp)
    result = hp_live.run_signed_hp_after_worker(
        bound, worker, hp, spec_path=spec_path, spec_sha256=spec_sha)
    assert result["status"] == "HP_POST_WORKER_BLOCKED"
    assert result["model_physical_calls"] == 0
    saved = json.loads(Path(result["result_path"]).read_text())
    assert saved["hp_result"]["reason"] == "HP_MODEL_BUDGET_UNAVAILABLE"
    assert not (run_dir / "HP_RUN_CLAIM.json").exists()


def test_bounded_hp_selection_is_bound_to_signed_receipt(tmp_path):
    run_dir = tmp_path / "run"
    result_dir = run_dir / "worker" / "results"
    result_dir.mkdir(parents=True)
    scope = {"kind": "BOUNDED_NOHINT_DEV_V1", "seed_directions": 2,
             "sp_functions": 1, "sp_max_iterations": 7,
             "selection": "DIRECTION_RISK_PHASE_CANONICAL_V1"}
    hp = {"enabled": True, "max_items": 1}
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps({"development_scope": scope, "hp": hp}))
    plan_sha = "a" * 64
    selected = [{"function_id": "function-one",
                 "direction_id": "direction-one"}]
    saved = {"kind": "BOUNDED_NOHINT_SELECTION_V1",
             "status": "PARTIAL_SCOPE", "task_id": "task", "run_id": "run",
             "selection": scope["selection"],
             "direction_plan_sha256": plan_sha,
             "function_limit": 1, "selected_functions": selected}
    receipt_path = result_dir / "BOUNDED_AUTO_SELECTION.json"
    receipt_path.write_text(json.dumps(saved))
    proof = {**saved, "selection_receipt_path": str(receipt_path),
             "selection_receipt_sha256": _sha(receipt_path)}
    auto_scope = {"sp_functions": 1}
    bound = SimpleNamespace(
        identity=SimpleNamespace(task_id="task", run_id="run", run_dir=run_dir),
        caps=SimpleNamespace(bounded_nohint_dev=True),
        executor=SimpleNamespace(development_auto_scope=auto_scope),
        strategy=SimpleNamespace(results_path=result_dir,
                                 _development_auto_scope=auto_scope,
                                 _development_sp_scope=proof,
                                 _development_direction_plan=(tmp_path, plan_sha)))
    worker = {"analysis_scope": dict(proof)}
    assert hp_live._signed_bounded_hp_pair(
        bound, worker, spec_path, _sha(spec_path)) == (
            "function-one", "direction-one")
    worker["analysis_scope"]["selected_functions"] = [
        {"function_id": "another", "direction_id": "direction-one"}]
    with pytest.raises(ValueError, match="HP_SIGNED_SELECTION_UNPROVEN"):
        hp_live._signed_bounded_hp_pair(bound, worker, spec_path,
                                        _sha(spec_path))
    worker["analysis_scope"] = dict(proof)
    receipt_path.write_text(json.dumps({**saved, "selected_functions": [
        {"function_id": "another", "direction_id": "direction-one"}]}))
    with pytest.raises(ValueError, match="HP_SIGNED_SELECTION_UNPROVEN"):
        hp_live._signed_bounded_hp_pair(bound, worker, spec_path,
                                        _sha(spec_path))


def test_bounded_hp_missing_selection_stops_before_claim_or_provider(
        tmp_path, monkeypatch):
    source, hp = _assets(tmp_path)
    hp["max_model_calls"] = 5
    run_dir = tmp_path / "run"
    run_dir.mkdir(mode=0o700)
    (run_dir / "model_events").mkdir(mode=0o700)
    spec_path = tmp_path / "signed-spec.json"
    spec_path.write_text(json.dumps({"hp": hp, "development_scope": {
        "kind": "BOUNDED_NOHINT_DEV_V1", "seed_directions": 2,
        "sp_functions": 1, "sp_max_iterations": 7,
        "selection": "DIRECTION_RISK_PHASE_CANONICAL_V1"}}))
    bound = SimpleNamespace(
        identity=SimpleNamespace(product_src=source, run_dir=run_dir,
                                 task_id="task", run_id="run"),
        caps=SimpleNamespace(physical_model_calls=48,
                             bounded_nohint_dev=True),
        model_gate=SimpleNamespace(snapshot=lambda: {"physical": 0}),
        process_ledger=SimpleNamespace(receipt_snapshot=lambda: (
            {"stop_status": None, "active": {}}, "a" * 64)),
        recheck=lambda: None)
    async def forbidden_hp(**_kwargs):
        raise AssertionError("HP provider must not be constructed")
    monkeypatch.setattr(hp_live, "run_post_worker_hp", forbidden_hp)
    result = hp_live.run_signed_hp_after_worker(
        bound, {"original_result": {"worker_id": "worker"}}, hp,
        spec_path=spec_path, spec_sha256=_sha(spec_path))
    assert result["status"] == "HP_POST_WORKER_BLOCKED"
    assert result["model_physical_calls"] == 0
    assert not (run_dir / "HP_RUN_CLAIM.json").exists()
    saved = json.loads(Path(result["result_path"]).read_text())
    assert saved["hp_result"]["reason"] == "HP_SIGNED_SELECTION_UNPROVEN"
