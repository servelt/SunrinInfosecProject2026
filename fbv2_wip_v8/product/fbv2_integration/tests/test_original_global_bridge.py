"""Provider-free FBv2 seed handoff into the existing guarded Global contract."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from bson import ObjectId

from devtools.original_global_bridge import (
    OriginalGlobalBridge,
    export_completed_direction_plan,
)
from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.fuzzer import get_fuzzer_manager, unregister_fuzzer_manager
from fuzzingbrain.worker.executor import WorkerExecutor
from fuzzingbrain.worker.pipeline import IncompleteInjectedAgent
from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy


class RecordingCampaign:
    def __init__(self, *, cleanup_complete=True, finish_status="RAN"):
        self.q = SimpleNamespace(
            product_issued=True,
            contract_kind="OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2",
            binary_sha256="b" * 64,
        )
        self.global_seconds = 2
        self.global_wall_reservation_seconds = 16
        self.require_accounted_consumer = True
        self.cleanup_complete = cleanup_complete
        self.finish_status = finish_status
        self.stage_calls = []
        self.starts = 0
        self.finishes = 0
        self.aborts = 0
        self.final_result = None

    def record_clean_no_seed(self, **kwargs):
        assert kwargs["direction_ids"] == ["direction_A"]
        assert self.starts == 0
        self.final_result = {"status": "SKIPPED_NO_SEED",
                             "cleanup_complete": True,
                             "physical_seconds": 0.0}
        return self.final_result

    def _authority_ok(self):
        return True

    def stage_direction_seeds(self, plan, sha, seeds):
        self.stage_calls.append((plan, sha, list(seeds)))

    def start(self):
        self.starts += 1
        return "ACTIVE"

    def finish(self):
        self.finishes += 1
        return {"status": self.finish_status,
                "cleanup_complete": self.cleanup_complete,
                "consumer_rows": []}

    def abort(self):
        self.aborts += 1
        return {"status": "STOPPED_ABORTED",
                "cleanup_complete": self.cleanup_complete}


def setup(tmp_path: Path, *, campaign=None):
    plan = tmp_path / "DIRECTION_PLAN.json"
    plan.write_text(json.dumps({
        "status": "COMPLETED", "direction_ids": ["direction_A"]
    }))
    plan_sha = hashlib.sha256(plan.read_bytes()).hexdigest()
    owner = campaign or RecordingCampaign()
    bridge = OriginalGlobalBridge(
        campaign=owner, direction_plan_path=plan,
        direction_plan_sha256=plan_sha, seed_spool=tmp_path / "seed-spool",
        expected_binary_sha256="b" * 64)
    return bridge, owner, plan


def direction_rows(*ids, agent_id="agent_1"):
    return [SimpleNamespace(direction_id=direction_id, task_id="task_1",
                            fuzzer="fuzz_input", created_by_agent_id=agent_id,
                            status="pending") for direction_id in ids]


def export_plan(tmp_path: Path, rows, *, ids=None, count=None, agent_final=True):
    selected = list(ids if ids is not None else [row.direction_id for row in rows])
    repos = SimpleNamespace(directions=SimpleNamespace(
        find_pending=lambda task_id, fuzzer: rows))
    output = tmp_path / "DIRECTION_PLAN.json"
    exported = export_completed_direction_plan(
        repos=repos, task_id="task_1", fuzzer="fuzz_input",
        agent_id="agent_1", agent_result={
            "success": True, "direction_ids": selected,
            "directions_created": len(selected) if count is None else count,
        }, agent_final=agent_final, output_path=output)
    return output, exported


def test_completed_original_agent_ids_export_atomic_pinned_plan(tmp_path):
    rows = direction_rows("direction_A", "direction_B")
    output, (path, digest) = export_plan(tmp_path, rows)
    assert path == output
    assert hashlib.sha256(output.read_bytes()).hexdigest() == digest
    assert output.stat().st_mode & 0o777 == 0o600
    assert list(tmp_path.glob("*.tmp")) == []
    plan = json.loads(output.read_text())
    assert plan["kind"] == "FBV2_DEV_DIRECTION_PLAN_V1"
    assert plan["status"] == "COMPLETED"
    assert plan["source"] == "ORIGINAL_FBV2_AGENT_TOOL_RESULTS"
    assert plan["direction_ids"] == ["direction_A", "direction_B"]
    campaign = RecordingCampaign()
    bridge = OriginalGlobalBridge(
        campaign=campaign, direction_plan_path=output,
        direction_plan_sha256=digest, seed_spool=tmp_path / "seed-spool",
        expected_binary_sha256="b" * 64)
    bridge.add_direction_seed(b"seed", "direction_B")
    assert len(bridge.direction_seeds) == 1


def test_export_reads_original_direction_repository_rows(tmp_path, repos):
    task_id = str(ObjectId())
    agent_id = str(ObjectId())
    direction = Direction(task_id=task_id, fuzzer="fuzz_input",
                          created_by_agent_id=agent_id, name="parser")
    assert repos.directions.save(direction)
    output = tmp_path / "DIRECTION_PLAN.json"
    path, digest = export_completed_direction_plan(
        repos=repos, task_id=task_id, fuzzer="fuzz_input",
        agent_id=agent_id, agent_result={
            "success": True, "directions_created": 1,
            "direction_ids": [direction.direction_id]},
        agent_final=True, output_path=output)
    assert path == output
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert json.loads(path.read_text())["direction_ids"] == [direction.direction_id]


@pytest.mark.parametrize("rows,ids,error", [
    (direction_rows("direction_A", "stale"), ["direction_A"],
     "pending Directions differ"),
    (direction_rows("direction_A"), ["direction_A", "unknown"],
     "pending Directions differ"),
    (direction_rows("direction_A"), ["direction_A", "direction_A"],
     "missing or duplicated"),
    (direction_rows("direction_A", agent_id="previous_agent"),
     ["direction_A"], "Direction owner"),
])
def test_export_rejects_stale_unknown_duplicate_or_foreign_direction(
        tmp_path, rows, ids, error):
    with pytest.raises(ValueError, match=error):
        export_plan(tmp_path, rows, ids=ids)
    assert not (tmp_path / "DIRECTION_PLAN.json").exists()


def test_export_requires_completed_agent_and_keeps_existing_plan(tmp_path):
    rows = direction_rows("direction_A")
    with pytest.raises(ValueError, match="did not finish"):
        export_plan(tmp_path, rows, agent_final=False)
    assert not (tmp_path / "DIRECTION_PLAN.json").exists()
    output, _ = export_plan(tmp_path, rows)
    original = output.read_bytes()
    with pytest.raises(ValueError, match="new plain absolute file"):
        export_plan(tmp_path, rows)
    assert output.read_bytes() == original


def test_original_direction_seed_is_staged_with_sha_and_reused_product_owner(tmp_path):
    bridge, campaign, plan = setup(tmp_path)
    seed_path = bridge.add_direction_seed(b"valid md4c input\n", "direction_A")
    assert seed_path.read_bytes() == b"valid md4c input\n"
    assert seed_path == bridge.add_direction_seed(b"valid md4c input\n", "direction_A")
    assert len(bridge.direction_seeds) == 1
    assert asyncio.run(bridge.start_global_fuzzer()) is True
    assert campaign.starts == 1
    staged_plan, staged_sha, staged_seeds = campaign.stage_calls[0]
    assert staged_plan == plan
    assert staged_sha == hashlib.sha256(plan.read_bytes()).hexdigest()
    assert staged_seeds[0].path == seed_path
    assert staged_seeds[0].direction_id == "direction_A"
    assert staged_seeds[0].sha256 == hashlib.sha256(seed_path.read_bytes()).hexdigest()
    result = asyncio.run(bridge.stop_global_fuzzer())
    assert result["status"] == "RAN"
    assert campaign.finishes == 1
    assert campaign.aborts == 0
    assert bridge.get_status()["active"] is False


def test_no_seed_never_starts_physical_global(tmp_path):
    bridge, campaign, _ = setup(tmp_path)
    assert asyncio.run(bridge.start_global_fuzzer()) is False
    assert campaign.stage_calls == []
    assert campaign.starts == 0
    with pytest.raises(RuntimeError, match="cannot be retried"):
        asyncio.run(bridge.start_global_fuzzer())


def test_completed_zero_seed_has_explicit_skip_and_failed_turn_has_none(tmp_path):
    bridge, campaign, _ = setup(tmp_path)
    gate = object()
    bridge.model_gate = gate
    direction = SimpleNamespace(direction_id="direction_A")
    clean = [{"direction": direction,
              "result": {"success": True, "direction_id": "direction_A",
                         "seeds_generated": 0, "seed_tool_failures": 0,
                         "fatal_seed_cleanup": False}}]
    result = bridge.record_clean_no_seed(
        seed_results=clean, expected_direction_ids=["direction_A"],
        model_gate=gate)
    assert result["status"] == "SKIPPED_NO_SEED"
    assert asyncio.run(bridge.stop_global_fuzzer()) == result
    assert campaign.starts == 0 and campaign.finishes == 0
    with pytest.raises(ValueError):
        bridge.record_clean_no_seed(seed_results=clean,
                                    expected_direction_ids=["direction_A"],
                                    model_gate=gate)

    other_root = tmp_path / "other"
    other_root.mkdir()
    other, owner, _ = setup(other_root)
    other.model_gate = gate
    failed = [{"direction": direction,
               "result": {**clean[0]["result"], "seed_tool_failures": 1}}]
    with pytest.raises(ValueError, match="completed zero"):
        other.record_clean_no_seed(seed_results=failed,
                                   expected_direction_ids=["direction_A"],
                                   model_gate=gate)
    assert owner.final_result is None

    with pytest.raises(ValueError, match="preconditions"):
        other.record_clean_no_seed(seed_results=clean,
                                   expected_direction_ids=["direction_A"],
                                   model_gate=object())
    assert owner.final_result is None


def test_wrong_plan_or_binary_pin_rejected_before_seed_spool(tmp_path):
    bridge, campaign, plan = setup(tmp_path)
    assert bridge is not None
    with pytest.raises(ValueError, match="Direction plan identity"):
        OriginalGlobalBridge(
            campaign=campaign, direction_plan_path=plan,
            direction_plan_sha256="0" * 64,
            seed_spool=tmp_path / "bad-plan-spool",
            expected_binary_sha256="b" * 64)
    assert not (tmp_path / "bad-plan-spool").exists()
    with pytest.raises(ValueError, match="official V2"):
        OriginalGlobalBridge(
            campaign=campaign, direction_plan_path=plan,
            direction_plan_sha256=hashlib.sha256(plan.read_bytes()).hexdigest(),
            seed_spool=tmp_path / "bad-binary-spool",
            expected_binary_sha256="a" * 64)
    assert not (tmp_path / "bad-binary-spool").exists()


def test_unaccounted_global_consumer_rejected_before_seed_spool(tmp_path):
    bridge, campaign, plan = setup(tmp_path)
    campaign.require_accounted_consumer = False
    with pytest.raises(ValueError, match="accounted Global Crash consumer"):
        OriginalGlobalBridge(
            campaign=campaign, direction_plan_path=plan,
            direction_plan_sha256=hashlib.sha256(plan.read_bytes()).hexdigest(),
            seed_spool=tmp_path / "unaccounted-spool",
            expected_binary_sha256="b" * 64)
    assert not (tmp_path / "unaccounted-spool").exists()
    assert bridge is not None


def test_unknown_direction_and_changed_seed_cannot_launch(tmp_path):
    bridge, campaign, _ = setup(tmp_path)
    with pytest.raises(ValueError, match="untrusted Direction seed"):
        bridge.add_direction_seed(b"x", "not-in-plan")
    seed_path = bridge.add_direction_seed(b"x", "direction_A")
    seed_path.write_bytes(b"changed")
    with pytest.raises(ValueError, match="Direction seed or pinned authority"):
        asyncio.run(bridge.start_global_fuzzer())
    assert campaign.stage_calls == []
    assert campaign.starts == 0


def test_changed_plan_cannot_launch_and_start_is_not_retried(tmp_path):
    bridge, campaign, plan = setup(tmp_path)
    bridge.add_direction_seed(b"x", "direction_A")
    plan.write_text(json.dumps({"status": "COMPLETED", "direction_ids": []}))
    with pytest.raises(ValueError, match="Direction seed or pinned authority"):
        asyncio.run(bridge.start_global_fuzzer())
    with pytest.raises(RuntimeError, match="cannot be retried"):
        asyncio.run(bridge.start_global_fuzzer())
    assert campaign.starts == 0


def test_cleanup_failure_is_never_reported_as_success(tmp_path):
    bridge, campaign, _ = setup(tmp_path,
                                campaign=RecordingCampaign(cleanup_complete=False))
    bridge.add_direction_seed(b"x", "direction_A")
    assert asyncio.run(bridge.start_global_fuzzer()) is True
    with pytest.raises(RuntimeError, match="cleanup is incomplete"):
        asyncio.run(bridge.stop_global_fuzzer())
    assert campaign.finishes == 1
    assert bridge.final_result["cleanup_complete"] is False
    assert bridge.get_status()["active"] is False


@pytest.mark.parametrize("status", [
    "INCOMPLETE_GLOBAL_REPORT_OR_CONSUMER",
    "STOPPED_AUTHORITY_CHANGED",
    "INCOMPLETE_FUZZ_OVERRUN",
    "CRASH_OBSERVED_INCOMPLETE",
])
def test_global_non_ran_status_cannot_complete(tmp_path, status):
    bridge, campaign, _ = setup(
        tmp_path, campaign=RecordingCampaign(finish_status=status))
    bridge.add_direction_seed(b"x", "direction_A")
    assert asyncio.run(bridge.start_global_fuzzer()) is True
    with pytest.raises(RuntimeError, match="result is incomplete"):
        asyncio.run(bridge.stop_global_fuzzer())
    with pytest.raises(RuntimeError, match="result is incomplete"):
        asyncio.run(bridge.stop_global_fuzzer())
    assert bridge.final_result["status"] == status
    assert campaign.finishes == 1


def test_retained_global_crash_returns_for_independent_verification(tmp_path):
    bridge, campaign, _ = setup(
        tmp_path, campaign=RecordingCampaign(finish_status="CRASH_OBSERVED_INCOMPLETE"))
    campaign.finish = lambda: {
        "status": "CRASH_OBSERVED_INCOMPLETE", "cleanup_complete": True,
        "observed_crash_count": 1,
        "consumer_rows": [{"crash_id": "observed-1",
                           "status": "PENDING_RUNTIME_ATTEMPT_LIMIT"}],
    }
    bridge.add_direction_seed(b"x", "direction_A")
    assert asyncio.run(bridge.start_global_fuzzer()) is True
    result = asyncio.run(bridge.stop_global_fuzzer())
    assert result["status"] == "CRASH_OBSERVED_INCOMPLETE"
    assert result["consumer_rows"][0]["status"] == "PENDING_RUNTIME_ATTEMPT_LIMIT"
    assert asyncio.run(bridge.stop_global_fuzzer()) == result


def test_abort_uses_same_existing_product_owner(tmp_path):
    bridge, campaign, _ = setup(tmp_path)
    bridge.add_direction_seed(b"x", "direction_A")
    assert asyncio.run(bridge.start_global_fuzzer()) is True
    result = asyncio.run(bridge.abort())
    assert result["status"] == "STOPPED_ABORTED"
    assert campaign.aborts == 1
    assert campaign.finishes == 0


def test_sp_targeted_fuzzing_is_explicitly_unavailable(tmp_path):
    bridge, _, _ = setup(tmp_path)
    with pytest.raises(RuntimeError, match="not integrated"):
        asyncio.run(bridge.start_sp_fuzzer("sp-id"))
    with pytest.raises(RuntimeError, match="not integrated"):
        bridge.add_pov_blob(b"poc", "sp-id")


def test_start_failure_after_guard_launch_calls_existing_abort(tmp_path):
    campaign = RecordingCampaign()
    campaign.process = None

    def start_then_fail():
        campaign.starts += 1
        campaign.process = object()
        raise RuntimeError("start receipt failed")

    campaign.start = start_then_fail
    bridge, _, _ = setup(tmp_path, campaign=campaign)
    bridge.add_direction_seed(b"x", "direction_A")
    with pytest.raises(RuntimeError, match="start receipt failed"):
        asyncio.run(bridge.start_global_fuzzer())
    assert campaign.aborts == 1
    assert campaign.finishes == 0
    with pytest.raises(RuntimeError, match="cannot be retried"):
        asyncio.run(bridge.start_global_fuzzer())


def test_cancelled_finish_joins_one_physical_settlement_before_abort(tmp_path):
    campaign = RecordingCampaign()
    finish_started = threading.Event()
    allow_finish = threading.Event()
    finish_running = threading.Event()
    concurrent_abort = []

    def slow_finish():
        campaign.finishes += 1
        finish_running.set()
        finish_started.set()
        assert allow_finish.wait(2)
        finish_running.clear()
        return {"status": "RAN", "cleanup_complete": True,
                "consumer_rows": []}

    def abort():
        concurrent_abort.append(finish_running.is_set())
        campaign.aborts += 1
        return {"status": "STOPPED_ABORTED", "cleanup_complete": True}

    campaign.finish = slow_finish
    campaign.abort = abort
    bridge, _, _ = setup(tmp_path, campaign=campaign)
    bridge.add_direction_seed(b"x", "direction_A")

    async def run():
        assert await bridge.start_global_fuzzer() is True
        finishing = asyncio.create_task(bridge.stop_global_fuzzer())
        assert await asyncio.to_thread(finish_started.wait, 2)
        finishing.cancel()
        aborting = asyncio.create_task(bridge.abort())
        await asyncio.sleep(0)
        assert campaign.aborts == 0
        allow_finish.set()
        with pytest.raises(asyncio.CancelledError):
            await finishing
        result = await aborting
        assert result["status"] == "RAN"

    asyncio.run(run())
    assert campaign.finishes == 1
    assert campaign.aborts == 0
    assert concurrent_abort == []
    assert bridge.final_result["cleanup_complete"] is True


def test_seed_corpus_has_an_explicit_development_bound(tmp_path, monkeypatch):
    import devtools.original_global_bridge as module

    monkeypatch.setattr(module, "MAX_STAGED_SEEDS", 1)
    bridge, campaign, _ = setup(tmp_path)
    bridge.add_direction_seed(b"x", "direction_A")
    with pytest.raises(ValueError, match="bounded Direction seed corpus"):
        bridge.add_direction_seed(b"y", "direction_A")
    assert campaign.starts == 0


def test_handoff_matches_existing_product_staging_api(tmp_path):
    """Use the real DevGlobalCampaign staging method; never launch a Fuzzer."""
    eval_tools = Path(
        "/home/dawne/SunrinInfosecProject2026/reference/"
        "blind2_v2_preparation_20261027/evaluation_tools")
    if not (eval_tools / "dev_global_campaign.py").is_file():
        pytest.skip("product development Global campaign is unavailable")
    sys.path.insert(0, str(eval_tools))
    try:
        from dev_global_campaign import DevGlobalCampaign
    finally:
        sys.path.remove(str(eval_tools))

    campaign = object.__new__(DevGlobalCampaign)
    campaign.q = SimpleNamespace(
        product_issued=True,
        contract_kind="OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2",
        binary_sha256="b" * 64)
    campaign.global_seconds = 2
    campaign.global_wall_reservation_seconds = 16
    campaign.require_accounted_consumer = True
    campaign.run_dir = tmp_path / "output" / "global_campaign"
    campaign._authority_ok = lambda: True
    campaign.start = lambda: "ACTIVE"  # Explicitly suppress physical execution.
    campaign.finish = lambda: {"status": "RAN", "cleanup_complete": True}
    campaign.abort = lambda: {"status": "STOPPED_ABORTED",
                              "cleanup_complete": True}
    bridge, _, _ = setup(tmp_path, campaign=campaign)
    bridge.add_direction_seed(b"model-authored seed bytes", "direction_A")
    assert asyncio.run(bridge.start_global_fuzzer()) is True
    receipt = json.loads((campaign.run_dir / "DIRECTION_SEEDS.json").read_text())
    assert receipt["seed_count"] == 1
    stored = Path(receipt["seeds"][0]["stored"])
    assert stored.read_bytes() == b"model-authored seed bytes"
    assert receipt["seeds"][0]["stored_sha256"] == hashlib.sha256(
        stored.read_bytes()).hexdigest()
    assert not (campaign.run_dir / "DEV_GLOBAL_START.json").exists()


def development_executor(tmp_path, *, factory=None):
    binary = tmp_path / "qualified-fuzzer"
    binary.write_bytes(b"pinned test binary")
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    campaign = RecordingCampaign()
    campaign.q.binary = binary
    campaign.q.binary_sha256 = digest
    plan = tmp_path / "DIRECTION_PLAN.json"
    plan.write_text(json.dumps({"status": "COMPLETED",
                                "direction_ids": ["direction_A"]}))
    plan_sha = hashlib.sha256(plan.read_bytes()).hexdigest()
    bridge = OriginalGlobalBridge(
        campaign=campaign, direction_plan_path=plan,
        direction_plan_sha256=plan_sha, seed_spool=tmp_path / "seed-spool",
        expected_binary_sha256=digest)
    executor = WorkerExecutor(
        workspace_path=str(tmp_path / "worker"), project_name="fixture",
        fuzzer="fuzz_input", sanitizer="address", task_type="pov",
        repos=None, task_id="task_1", fuzzer_binary_path=str(binary),
        require_original_global_bridge=True,
        original_global_bridge_factory=factory)
    return executor, bridge, campaign, plan, plan_sha


def test_opt_in_worker_refuses_docker_fallback_and_installs_exact_bridge(tmp_path):
    executor, bridge, campaign, plan, plan_sha = development_executor(tmp_path)
    with patch("fuzzingbrain.worker.executor.FuzzerManager") as original_docker:
        with pytest.raises(RuntimeError, match="not installed"):
            _ = executor.fuzzer_manager
        original_docker.assert_not_called()
        executor.install_original_global_bridge(
            bridge, plan_path=plan, plan_sha256=plan_sha)
        assert executor.fuzzer_manager is bridge
        assert get_fuzzer_manager(executor.worker_id) is bridge
        executor.release_original_global_bridge(bridge)
        with pytest.raises(RuntimeError, match="not installed"):
            _ = executor.fuzzer_manager
        original_docker.assert_not_called()
    assert get_fuzzer_manager(executor.worker_id) is None
    assert campaign.starts == 0


def test_opt_in_worker_rejects_wrong_binary_before_registry(tmp_path):
    executor, bridge, _, plan, plan_sha = development_executor(tmp_path)
    executor.fuzzer_binary_path.write_bytes(b"different binary")
    with pytest.raises(ValueError, match="identity does not match"):
        executor.install_original_global_bridge(
            bridge, plan_path=plan, plan_sha256=plan_sha)
    assert get_fuzzer_manager(executor.worker_id) is None


def test_opt_in_worker_rejects_an_already_started_bridge(tmp_path):
    executor, bridge, campaign, plan, plan_sha = development_executor(tmp_path)
    bridge.add_direction_seed(b"seed", "direction_A")
    assert asyncio.run(bridge.start_global_fuzzer()) is True
    with pytest.raises(ValueError, match="identity does not match"):
        executor.install_original_global_bridge(
            bridge, plan_path=plan, plan_sha256=plan_sha)
    assert get_fuzzer_manager(executor.worker_id) is None
    assert asyncio.run(bridge.abort())["cleanup_complete"] is True
    assert campaign.aborts == 1


def test_non_opt_in_worker_keeps_original_manager_path(tmp_path):
    binary = tmp_path / "fuzzer"
    binary.write_bytes(b"fixture")
    executor = WorkerExecutor(
        workspace_path=str(tmp_path / "worker"), project_name="fixture",
        fuzzer="fuzz_input", sanitizer="address", task_type="pov",
        repos=None, task_id="task_default", fuzzer_binary_path=str(binary))
    original_manager = object()
    with patch("fuzzingbrain.worker.executor.FuzzerManager",
               return_value=original_manager) as constructor:
        assert executor.fuzzer_manager is original_manager
        constructor.assert_called_once()
    assert get_fuzzer_manager(executor.worker_id) is original_manager
    unregister_fuzzer_manager(executor.worker_id)


def test_strategy_exports_actual_agent_result_before_seeds(tmp_path):
    rows = direction_rows("direction_A")
    repos = SimpleNamespace(directions=SimpleNamespace(
        find_pending=lambda task_id, fuzzer: rows))
    client = SimpleNamespace(last_agent_response_was_final=True)

    async def close():
        return None

    client.close = close
    executor, bridge, campaign, _, _ = development_executor(tmp_path)
    executor.repos = repos
    strategy = POVFullscanStrategy(
        executor, llm_client_factory=lambda role, owner: client)
    strategy._get_fuzzer_source_code = lambda: "/* pinned harness */"
    strategy._get_reachable_function_count = lambda: 1
    fake_agent = SimpleNamespace(
        mcp_context_id="agent_1", stop_reason=None,
        plan_directions_async=AsyncMock(return_value={
            "success": True, "direction_ids": ["direction_A"],
            "directions_created": 1}))
    # The existing fixture plan occupies the export filename only in tmp_path;
    # the strategy writes its own plan into the Worker results directory.
    with patch("fuzzingbrain.worker.strategies.pov_fullscan.DirectionPlanningAgent",
               return_value=fake_agent):
        found = asyncio.run(strategy._run_direction_planning_async())
    assert found == rows
    path, digest = strategy._development_direction_plan
    assert path == executor.results_path / "DIRECTION_PLAN.json"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert campaign.starts == 0
    assert bridge is not None


def test_strategy_installs_bridge_before_seed_phase_and_settles_finish(tmp_path):
    executor, bridge, campaign, plan, plan_sha = development_executor(tmp_path)
    executor.original_global_bridge_factory = lambda path, sha: bridge
    strategy = POVFullscanStrategy(executor)

    async def direction():
        strategy._development_direction_plan = (plan, plan_sha)
        return [SimpleNamespace(direction_id="direction_A")]

    async def seed_and_pipeline(directions):
        assert executor.fuzzer_manager is bridge
        assert get_fuzzer_manager(executor.worker_id) is bridge
        bridge.add_direction_seed(b"seed", "direction_A")
        assert await bridge.start_global_fuzzer() is True
        return SimpleNamespace(sp_verified=0)

    strategy._run_direction_planning_async = direction
    strategy._run_v2_pipeline_with_fuzzer_init = seed_and_pipeline
    result = asyncio.run(strategy._run_full_pipeline())
    assert result.sp_verified == 0
    assert campaign.starts == campaign.finishes == 1
    assert campaign.aborts == 0
    assert get_fuzzer_manager(executor.worker_id) is None


def test_strategy_rejects_incomplete_global_finish_and_preserves_receipt(tmp_path):
    executor, bridge, campaign, plan, plan_sha = development_executor(tmp_path)
    campaign.finish_status = "CRASH_OBSERVED_INCOMPLETE"
    executor.original_global_bridge_factory = lambda path, sha: bridge
    strategy = POVFullscanStrategy(executor)

    async def direction():
        strategy._development_direction_plan = (plan, plan_sha)
        return [SimpleNamespace(direction_id="direction_A")]

    async def seed_and_pipeline(directions):
        bridge.add_direction_seed(b"seed", "direction_A")
        assert await bridge.start_global_fuzzer() is True
        return SimpleNamespace(sp_verified=0)

    strategy._run_direction_planning_async = direction
    strategy._run_v2_pipeline_with_fuzzer_init = seed_and_pipeline
    with pytest.raises(RuntimeError, match="CRASH_OBSERVED_INCOMPLETE"):
        asyncio.run(strategy._run_full_pipeline())
    assert bridge.final_result["status"] == "CRASH_OBSERVED_INCOMPLETE"
    assert campaign.finishes == 1
    assert get_fuzzer_manager(executor.worker_id) is None


def test_strategy_finishes_bridge_on_sp_failure_and_preserves_error(tmp_path):
    executor, bridge, campaign, plan, plan_sha = development_executor(tmp_path)
    executor.original_global_bridge_factory = lambda path, sha: bridge
    strategy = POVFullscanStrategy(executor)

    async def direction():
        strategy._development_direction_plan = (plan, plan_sha)
        return [SimpleNamespace(direction_id="direction_A")]

    async def failing_pipeline(directions):
        bridge.add_direction_seed(b"seed", "direction_A")
        assert await bridge.start_global_fuzzer() is True
        raise ValueError("original SP failure")

    strategy._run_direction_planning_async = direction
    strategy._run_v2_pipeline_with_fuzzer_init = failing_pipeline
    with pytest.raises(ValueError, match="original SP failure"):
        asyncio.run(strategy._run_full_pipeline())
    assert campaign.aborts == 0
    assert campaign.finishes == 1
    assert get_fuzzer_manager(executor.worker_id) is None


def test_cancelled_sp_still_settles_started_global_observations(tmp_path):
    executor, bridge, campaign, plan, plan_sha = development_executor(tmp_path)
    executor.original_global_bridge_factory = lambda path, sha: bridge
    strategy = POVFullscanStrategy(executor)

    async def direction():
        strategy._development_direction_plan = (plan, plan_sha)
        return [SimpleNamespace(direction_id="direction_A")]

    async def cancelled_pipeline(directions):
        bridge.add_direction_seed(b"seed", "direction_A")
        assert await bridge.start_global_fuzzer() is True
        raise asyncio.CancelledError("caller stopped")

    strategy._run_direction_planning_async = direction
    strategy._run_v2_pipeline_with_fuzzer_init = cancelled_pipeline
    with pytest.raises(asyncio.CancelledError, match="caller stopped"):
        asyncio.run(strategy._run_full_pipeline())
    assert campaign.finishes == 1
    assert campaign.aborts == 0
    assert get_fuzzer_manager(executor.worker_id) is None


@pytest.mark.parametrize("finish_status", ["RAN", "CRASH_OBSERVED_INCOMPLETE"])
def test_model_stop_finishes_global_and_preserves_original_reason(tmp_path, finish_status):
    executor, bridge, campaign, plan, plan_sha = development_executor(tmp_path)
    campaign.finish_status = finish_status
    executor.original_global_bridge_factory = lambda path, sha: bridge
    strategy = POVFullscanStrategy(executor)

    async def direction():
        strategy._development_direction_plan = (plan, plan_sha)
        return [SimpleNamespace(direction_id="direction_A")]

    async def model_stopped(directions):
        bridge.add_direction_seed(b"seed", "direction_A")
        assert await bridge.start_global_fuzzer() is True
        raise IncompleteInjectedAgent("SP budget exhausted", reason="budget_before_transport")

    strategy._run_direction_planning_async = direction
    strategy._run_v2_pipeline_with_fuzzer_init = model_stopped
    with pytest.raises(IncompleteInjectedAgent, match="SP budget exhausted") as caught:
        asyncio.run(strategy._run_full_pipeline())
    assert caught.value.reason == "budget_before_transport"
    assert campaign.finishes == 1
    assert campaign.aborts == 0
    assert bridge.final_result["status"] == finish_status
    assert get_fuzzer_manager(executor.worker_id) is None
    if finish_status != "RAN":
        assert any("Global settlement failed" in note
                   for note in getattr(caught.value, "__notes__", []))


def test_cached_durable_global_result_rechecks_underlying_account(tmp_path):
    bridge, campaign, _ = setup(tmp_path)
    receipt = {"status": "RAN", "cleanup_complete": True,
               "durable_global_charge": {"key": "GLOBAL_FUZZ:task", "physical_seconds": 1}}
    campaign.final_result = receipt
    bridge.final_result = receipt
    assert bridge.final_result["status"] == "RAN"
    campaign.final_result = {**receipt, "status": "STOPPED_PIN_DRIFT"}
    with pytest.raises(RuntimeError, match="cached Global result differs"):
        _ = bridge.final_result


def test_opt_in_missing_factory_stops_before_seed_or_docker(tmp_path):
    executor, bridge, campaign, plan, plan_sha = development_executor(tmp_path)
    strategy = POVFullscanStrategy(executor)

    async def direction():
        strategy._development_direction_plan = (plan, plan_sha)
        return [SimpleNamespace(direction_id="direction_A")]

    strategy._run_direction_planning_async = direction
    strategy._run_v2_pipeline_with_fuzzer_init = AsyncMock()
    with patch("fuzzingbrain.worker.executor.FuzzerManager") as original_docker:
        with pytest.raises(RuntimeError, match="bridge is missing"):
            asyncio.run(strategy._run_full_pipeline())
        original_docker.assert_not_called()
    strategy._run_v2_pipeline_with_fuzzer_init.assert_not_awaited()
    assert get_fuzzer_manager(executor.worker_id) is None
    assert campaign.starts == 0
    assert bridge is not None
