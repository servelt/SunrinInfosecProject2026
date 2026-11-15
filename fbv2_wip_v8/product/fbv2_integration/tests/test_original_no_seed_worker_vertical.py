"""Provider-free original Worker: clean zero Seed still reaches SP and settles."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

from bson import ObjectId
import pytest

from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.worker.executor import WorkerExecutor
from fuzzingbrain.worker.pipeline import PipelineConfig
from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy


EVAL_DIR = Path("/home/dawne/SunrinInfosecProject2026/reference/blind2_v2_preparation_20261027/evaluation_tools")
PRODUCT_SRC = Path("/home/dawne/work/SunrinInfosecProject2026/vulnerabilityanalysis/src")
PRODUCT_TESTS = PRODUCT_SRC.parent / "tests"
for root in (EVAL_DIR, PRODUCT_SRC, PRODUCT_TESTS):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from dev_accounted_global_campaign import AccountedGlobalCampaign
from dev_global_campaign import DevGlobalCampaign
from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
from test_official_v2_contract import Fixture

from devtools.original_global_bridge import OriginalGlobalBridge
from devtools import original_public_live as live


@pytest.mark.parametrize("seed_status", ["COMPLETED", "UNCERTAIN"])
def test_original_worker_no_seed_settlement_and_uncertain_refusal(
        tmp_path, monkeypatch, mock_db, repos, seed_status):
    task_id, direction_id, agent_id = (str(ObjectId()) for _ in range(3))
    run_id = "no_seed_vertical"
    q = Fixture(tmp_path / "authority").issue()
    assert q is not None and q.binary.is_file()
    assert repos.functions.save(Function(
        task_id=task_id, name="parse_input", file_path="parser.c",
        start_line=1, end_line=1,
        content="int parse_input(const char *p) { return *p; }"))
    process_ledger = PersistentProcessLedgerV2.create(
        tmp_path / "process-ledger.json", wall_total_seconds=30,
        fuzz_total_seconds=20)
    envelope = DevelopmentProcessEnvelopeV2(
        process_ledger, work_item_id=task_id, assertion_id="global_consumer",
        attempt_id=run_id, output_limit_bytes=4096,
        total_wall_seconds=30, pin_hook=lambda *_args: None)
    base = DevGlobalCampaign(
        tmp_path / "output", q, total_fuzz_seconds=20,
        global_seconds=1, global_wall_reservation_seconds=14,
        replay_limit=1, process_envelope=envelope,
        require_accounted_consumer=True)
    campaign = AccountedGlobalCampaign(
        base, process_ledger,
        reservation_key=f"GLOBAL_FUZZ:{task_id}:{run_id}")
    records = [{"request_id": "direction-turn", "role": "direction",
                "owner_id": task_id, "status": "COMPLETED",
                "response_evidence": {"status": "VERIFIED"},
                "tool_events": []},
               {"request_id": "seed-turn", "role": "seed",
                "owner_id": direction_id, "status": seed_status,
                "response_evidence": {"status": (
                    "VERIFIED" if seed_status == "COMPLETED" else "UNPROVEN")},
                "tool_events": []}]
    model_gate = SimpleNamespace(
        campaign_id=run_id,
        snapshot=lambda: {"campaign_id": run_id, "physical": 0,
                          "records": records},
        verify_response_evidence=lambda request_id: {
            "status": "UNPROVEN" if request_id == "seed-turn" and
            seed_status == "UNCERTAIN" else "VERIFIED"},
        verify_tool_event=lambda *_args: {"status": "VERIFIED"})
    events: list[str] = []

    def bridge_factory(path: Path, sha: str):
        return OriginalGlobalBridge(
            campaign=campaign, direction_plan_path=path,
            direction_plan_sha256=sha, seed_spool=tmp_path / "seed-spool",
            expected_binary_sha256=q.binary_sha256, model_gate=model_gate)

    class ScriptedClient:
        last_agent_response_was_final = True

        async def close(self):
            return None

    executor = WorkerExecutor(
        workspace_path=str(tmp_path / "worker"), project_name="fixture",
        fuzzer="fuzz_fixture", sanitizer="address", task_type="pov",
        repos=repos, task_id=task_id, fuzzer_binary_path=str(q.binary),
        llm_client_factory=lambda _role, _owner: ScriptedClient(),
        require_original_global_bridge=True,
        original_global_bridge_factory=bridge_factory)
    strategy = POVFullscanStrategy(
        executor, llm_client_factory=executor.llm_client_factory)

    class DirectionRole:
        stop_reason = None
        mcp_context_id = agent_id

        async def plan_directions_async(self, **_kwargs):
            events.append("direction")
            assert repos.directions.save(Direction(
                direction_id=direction_id, task_id=task_id,
                fuzzer="fuzz_fixture", created_by_agent_id=agent_id,
                name="parser", core_functions=["parse_input"],
                entry_functions=[]))
            return {"success": True, "directions_created": 1,
                    "direction_ids": [direction_id]}

    class SeedRole:
        stop_reason = None

        def __init__(self, **_kwargs):
            pass

        async def generate_direction_seeds(self, *, direction_id, **_kwargs):
            events.append("seed")
            return {"success": True, "direction_id": direction_id,
                    "seeds_generated": 0, "seed_tool_failures": 0,
                    "fatal_seed_cleanup": False}

    class SPRole:
        stop_reason = None

        def __init__(self, **_kwargs):
            pass

        async def analyze_async(self):
            events.append("sp")
            return {"success": True, "sp_created": False}

    original_config = PipelineConfig

    def quick_config(**kwargs):
        kwargs.update(num_verify_agents=1, num_pov_agents=1,
                      poll_interval=0.005, max_idle_cycles=6)
        return original_config(**kwargs)

    with patch("fuzzingbrain.db.get_database", return_value=mock_db), \
         patch("fuzzingbrain.llms.buffer.WorkerLLMBuffer"), \
         patch("fuzzingbrain.llms.buffer.set_worker_buffer"), \
         patch.object(executor, "_get_strategy", return_value=strategy), \
         patch("fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent",
               return_value=DirectionRole()), \
         patch("fuzzingbrain.worker.strategies.pov_fullscan.SeedAgent", SeedRole), \
         patch("fuzzingbrain.worker.strategies.pov_fullscan.FullSPGenerator", SPRole), \
         patch("fuzzingbrain.worker.pipeline.PipelineConfig",
               side_effect=quick_config):
        if seed_status == "UNCERTAIN":
            with pytest.raises(Exception):
                executor.run()
        else:
            original = executor.run()

    if seed_status == "UNCERTAIN":
        assert events == ["direction", "seed"]
        assert campaign.final_result is None
        assert not base.run_dir.exists()
        assert process_ledger.snapshot()["finished"] == []
        return

    assert events == ["direction", "seed", "sp"]
    assert original["worker_id"] == executor._worker_context.worker_id
    assert campaign.final_result["status"] == "SKIPPED_NO_SEED"
    assert campaign.final_result["physical_seconds"] == 0
    assert process_ledger.snapshot()["finished"] == []
    assert process_ledger.snapshot()["active"] == {}
    assert base.process is None

    entry = Path(live.__file__).resolve().parent / "original_public_live_entry.py"
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    import hashlib
    token = object()
    marker = {"pid": os.getpid(), "spec_path": str(spec),
              "spec_sha256": hashlib.sha256(spec.read_bytes()).hexdigest(),
              "token": token, "used": False,
              "engine_py_sha256": "a" * 64,
              "product_py_sha256": "b" * 64,
              "evaluation_py_sha256": "c" * 64}
    process, process_sha = process_ledger.receipt_snapshot()
    run_dir = tmp_path / "final-run"
    run_dir.mkdir()
    pov_root = tmp_path / "pov-runtime"
    pov_root.mkdir()
    identity = SimpleNamespace(task_id=task_id, run_id=run_id,
                               task_path=tmp_path, run_dir=run_dir,
                               engine_py_sha256="a" * 64,
                               product_py_sha256="b" * 64,
                               evaluation_py_sha256="c" * 64)
    bound = SimpleNamespace(
        recheck=lambda: None, bootstrap_token=token, identity=identity,
        executor=executor, strategy=strategy,
        server=SimpleNamespace(repos=repos,
                               socket_path=tmp_path / "unused.sock"),
        admission=SimpleNamespace(summary={"project_name": "fixture"}),
        process_ledger=process_ledger, model_gate=model_gate,
        global_campaign=campaign,
        pov_adapter=SimpleNamespace(root=pov_root))
    with patch.object(live, "_isolated_runtime", return_value=True), \
         patch.object(live, "require_journaled_mongo"), \
         patch.object(executor, "run", return_value=original), \
         patch.dict(sys.modules, {"__main__": SimpleNamespace(
             __file__=str(entry), _PINNED_PUBLIC_BOOTSTRAP=marker)}), \
         patch.object(sys, "argv", [str(entry), "--authorize-public-dev"]):
        result = live.run_original_public_dev(
            bound, explicit_public_dev_authorization=True)
    assert result["execution_status"] == "EXECUTED"
    assert result["status"] == "EXECUTED_UNVERIFIED"
    assert result["global_status"] == "SKIPPED_NO_SEED"
    assert result["model_physical_calls"] == 0
    assert result["process_wall_seconds"] == 0
