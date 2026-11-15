"""Exercise the real parallel HP runner's Guided crash to Gate handoff."""

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from devtools import original_hp_live_optin, original_hp_post_worker
from devtools import parallel_hp_analysis
from devtools import hp_gate_handoff
from devtools.original_hp_preparation import PreparedHPFunction


@pytest.mark.parametrize("gate_identity_ok", [True, False])
def test_parallel_runner_sends_guided_crash_to_bounded_hp_gate(
        tmp_path, monkeypatch, gate_identity_ok):
    task_id, run_id = "task", "run"
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    manifest = tmp_path / "catalog.json"
    manifest.write_text("{}")
    manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    policy = {
        "enabled": True, "max_leads": 1,
        "replay_timeout_seconds": 10,
        "replay_wall_seconds": 90,
        "source_wall_seconds": 90,
        "output_limit_bytes": 4_000_000,
    }
    hp = {"max_model_calls": 2,
          "physical": {"output_limit_bytes": 4_000_000}}
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps({
        "development_seed_scope": {
            "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_PARALLEL_DEV_V1",
            "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1",
            "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2}},
        "identity": {"task_id": task_id, "run_id": run_id},
        "caps": {"gate_aux_reservation_seconds_per_observation": 600},
        "hp_gate": policy,
    }))
    spec_sha = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    direction = SimpleNamespace(direction_id="direction")
    function = SimpleNamespace(function_id="function")
    work = PreparedHPFunction(
        task_id=task_id, function_id="function", function_name="parse",
        direction_id="direction", source_file="parse.c", source="int parse() {}",
        source_start_line=1, source_end_line=1, source_sha256="a" * 64,
        source_file_sha256="b" * 64, harness_path="harness.c",
        harness_sha256="c" * 64, binary_sha256="d" * 64,
        source_tree_sha256="e" * 64, contract_sha256="f" * 64,
        analysis_scope={}, selection_origin="PARALLEL_HP_PRE_SP_SELECTION_V1")
    strategy = SimpleNamespace(
        _development_direction_plan=(tmp_path / "plan", "1" * 64))
    ledger_rows = [
        {"owner_id": f"hp:function:direction:{role}", "role": role,
         "status": "COMPLETED", "request_id": role}
        for role in ("function_analysis", "assertion_generator")]
    model_gate = SimpleNamespace(
        snapshot=lambda: {"records": ledger_rows},
        verify_response_evidence=lambda _request_id: {"status": "VERIFIED"})
    executor = SimpleNamespace(
        fuzzer="fuzzer", _worker_context=SimpleNamespace(worker_id="worker"))
    strategy.executor = executor
    qualification = SimpleNamespace(
        source_tree_sha256="e" * 64, contract_sha256="f" * 64)
    bound = SimpleNamespace(
        identity=SimpleNamespace(task_id=task_id, run_id=run_id,
                                 run_dir=run_dir, product_src=tmp_path),
        admission=SimpleNamespace(qualification=qualification, summary={
            "manifest_path": str(manifest), "manifest_sha256": manifest_sha}),
        caps=SimpleNamespace(sp_concurrent_queue=True),
        strategy=strategy, executor=executor, model_gate=model_gate,
        process_ledger=object(), recheck=lambda: None,
        server=SimpleNamespace(repos=SimpleNamespace(
            functions=SimpleNamespace(find_by_task=lambda _task: [function]))))
    calls = []
    monkeypatch.setattr(original_hp_live_optin, "_check_signed_hp_spec",
                        lambda *_args: None)
    monkeypatch.setattr(original_hp_live_optin, "validate_hp_spec",
                        lambda *_args, **_kwargs: None)
    monkeypatch.setattr(original_hp_post_worker, "_current_direction_ids",
                        lambda _bound: {"direction"})
    monkeypatch.setattr(parallel_hp_analysis, "freeze_parallel_hp_selection",
                        lambda **_kwargs: ((function, direction), "2" * 64))
    monkeypatch.setattr(parallel_hp_analysis, "claim_parallel_hp_execution",
                        lambda **_kwargs: "3" * 64)
    monkeypatch.setattr(parallel_hp_analysis,
                        "verify_parallel_hp_execution_claim",
                        lambda **_kwargs: True)
    monkeypatch.setattr(parallel_hp_analysis, "prepare_hp_function",
                        lambda **_kwargs: work)

    class Provider:
        gate = model_gate

        async def close(self):
            return None

    monkeypatch.setattr(original_hp_live_optin, "_pipeline_factory",
                        lambda *_args, **_kwargs: lambda _work:
                        SimpleNamespace(provider=Provider()))

    async def analyze(**_kwargs):
        return {"status": "ASSERTIONS_PROPOSED_UNVERIFIED"}

    monkeypatch.setattr(parallel_hp_analysis, "run_prepared_hp_analysis",
                        analyze)

    def physical_factory(*_args, **_kwargs):
        def physical(_work, _row):
            calls.append("physical")
            return {
                "status": "HP_GUIDED_CRASH_OBSERVED_UNGATED",
                "assertion_id": "assertion",
                "security_gate_credit": "NOT_CREDITED",
                "discovery_credit": "NOT_CREDITED",
            }
        return physical

    monkeypatch.setattr(original_hp_live_optin, "_physical_handoff_factory",
                        physical_factory)

    def gate_handoff(**kwargs):
        calls.append("gate")
        assert kwargs["policy"] == policy
        assert kwargs["physical_row"]["assertion_id"] == "assertion"
        assert kwargs["process_ledger"] is bound.process_ledger
        return {
            "status": "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN",
            "task_id": task_id, "run_id": run_id,
            "assertion_id": ("assertion" if gate_identity_ok else "other"),
            "discovery_credit": "NOT_CREDITED",
            "result_path": str(run_dir / "hp-gate" / "HP_PARALLEL_GATE_RESULT.json"),
            "result_sha256": "4" * 64,
        }

    monkeypatch.setattr(hp_gate_handoff, "run_hp_gate_handoff", gate_handoff)
    result = asyncio.run(parallel_hp_analysis.run_parallel_hp_analysis(
        bound, strategy, [direction], hp=hp,
        spec_path=spec_path, spec_sha256=spec_sha))
    assert "error_type" not in result, result.get("error_type")
    assert calls == ["physical", "gate"]
    if gate_identity_ok:
        assert result["gate_status"] == "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN"
        assert result["gate_result_sha256"] == "4" * 64
    else:
        assert result["gate_status"] == "HP_GATE_INCOMPLETE"
        assert result["gate_error_type"] == "ValueError"
        assert "gate_result_sha256" not in result
    assert result["security_gate_credit"] == "NOT_CREDITED"
    physical_path = Path(result["physical_result_path"])
    assert hashlib.sha256(physical_path.read_bytes()).hexdigest() == (
        result["physical_result_sha256"])
