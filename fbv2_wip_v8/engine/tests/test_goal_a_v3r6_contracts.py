"""Goal A (V3R6) provider-free counterexamples.

Seed cases run the real ``BaseAgent._run_agent_loop`` through the real
``SeedAgent`` and the real Fullscan Seed phase; only the model transport, the
MCP transport and the campaign ledger evidence checks are scripted.
"""

import asyncio
import contextvars
import hashlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from bson import ObjectId
import mongomock
import pytest

from devtools import original_public_live as live
from devtools.campaign_model_gate import CampaignLedgeredProvider, CampaignModelGate
from devtools.model_candidate_lineage import verify_candidate_lineage
from devtools.original_global_bridge import OriginalGlobalBridge
from fuzzingbrain.agents.base import BaseAgent
from fuzzingbrain.core.models.function import Function
from fuzzingbrain.core.models.pov import POV
from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint
from fuzzingbrain.db.repository import RepositoryManager
from fuzzingbrain.worker.pipeline import (
    AgentPipeline, IncompleteInjectedAgent, PipelineConfig,
    public_incomplete_reason, require_injected_agent_complete,
)
from tests.test_fullscan_client_factory import make_strategy
from tests.test_model_candidate_lineage import _record

DIRECTION = "6af2db04f34a38a2cc411af8"
AGENT_ID = "6af2db99f34a38a2cc411afd"


# --------------------------------------------------------------------------
# Seed fixtures
# --------------------------------------------------------------------------

def _bridge(tmp_path):
    """A real OriginalGlobalBridge Seed stage without a Global campaign."""
    bridge = object.__new__(OriginalGlobalBridge)
    spool = tmp_path / "direction-seeds"
    spool.mkdir()
    bridge.spool = spool
    bridge.direction_ids = frozenset({DIRECTION})
    bridge.direction_seeds = []
    bridge._seed_keys = {}
    bridge._staged_seed_bytes = 0
    bridge._start_attempted = False
    bridge._authority_ok = lambda: True
    return bridge


def create(seeds, *, report_paths=True):
    def run(bridge, _tmp):
        paths = [str(bridge.add_direction_seed(seed, DIRECTION)) for seed in seeds]
        return {"success": True, "seeds_generated": len(seeds),
                "seed_paths": paths if report_paths else []}
    return run


def failed(_bridge, _tmp):
    return {"success": False, "error": "generator raised"}


def fatal(_bridge, _tmp):
    return {"success": False, "error": "cleanup", "fatal_sandbox_cleanup": True}


def foreign_writer(bridge, _tmp):
    """Another writer stages Seeds; this agent's receipt names none of them."""
    for index in range(5):
        bridge.add_direction_seed(b"foreign-%d" % index, DIRECTION)
    return {"success": True, "seeds_generated": 5, "seed_paths": []}


def tamper_after(seeds):
    def run(bridge, tmp):
        result = create(seeds)(bridge, tmp)
        Path(result["seed_paths"][0]).write_bytes(b"tampered")
        return result
    return run


def unique(count, tag="s"):
    return [f"{tag}-{index}".encode() for index in range(count)]


class FakeAgentContext:
    """AgentContext's progress interface without MongoDB persistence."""

    def __init__(self, agent_id):
        self.agent_id = agent_id

    def increment_iteration(self):
        pass

    def increment_tool_calls(self):
        pass

    def set_seeds_generated(self, _count):
        pass


class SeedHarness:
    """Scripted model/MCP transports plus a ledger mirror for one Seed run."""

    def __init__(self, tmp_path, plan, *, uncertain_on=None,
                 event_status="COMPLETED", event_agent=AGENT_ID):
        self.tmp = tmp_path
        self.plan = list(plan)
        self.uncertain_on = uncertain_on
        self.event_status = event_status
        self.event_agent = event_agent
        self.rows = []
        self.calls = 0
        self.gate = CampaignModelGate(tmp_path / "model-ledger.json", "run",
                                      40, 60, create=True)
        self.gate.snapshot = lambda: {"records": [dict(row) for row in self.rows]}
        self.gate.verify_response_evidence = MagicMock(
            return_value={"status": "VERIFIED"})
        self.gate.verify_tool_event = MagicMock(
            return_value={"status": "VERIFIED"})
        self.bridge = _bridge(tmp_path)
        self.bridge.model_gate = self.gate
        self.bridge.campaign = SimpleNamespace(ledger=SimpleNamespace(
            snapshot=lambda: {"stop_status": None, "active": {}}))
        self.bridge.start_global_fuzzer = AsyncMock(return_value=True)
        self.client = None

    # -- injected model client ------------------------------------------
    def factory(self, role, owner_id):
        harness = self
        provider = CampaignLedgeredProvider(object(), self.gate, role=role,
                                            owner_id=owner_id)

        class Client:
            codex_model = "scripted"
            last_agent_response_was_final = False

            def __init__(self):
                self.provider = provider
                self.agent_id = None

            def reset_tried_models(self):
                pass

            async def acall_with_tools(self, **_kwargs):
                harness.calls += 1
                request_id = uuid4().hex
                self.provider.issued_request_ids.append(request_id)
                if harness.calls == harness.uncertain_on:
                    harness.rows.append({
                        "request_id": request_id, "role": role,
                        "owner_id": owner_id, "status": "UNCERTAIN",
                        "tool_events": []})
                    error = RuntimeError("transport lost")
                    error.fbv2_stop_reason = "uncertain_remote"
                    raise error
                harness.rows.append({
                    "request_id": request_id, "role": role,
                    "owner_id": owner_id, "status": "COMPLETED",
                    "tool_events": []})
                return SimpleNamespace(content="", tool_calls=[{
                    "id": f"call-{harness.calls}",
                    "function": {"name": "create_seed", "arguments": json.dumps(
                        {"generator_code": "def generate(n): return b''",
                         "num_seeds": 5})}}])

            async def close(self):
                pass

        self.client = Client()
        return self.client

    # -- MCP transport ---------------------------------------------------
    async def list_tools(self):
        return [SimpleNamespace(
            name="create_seed", description="Generate seeds",
            inputSchema={"type": "object", "properties": {
                "generator_code": {"type": "string"},
                "num_seeds": {"type": "integer"}},
                "required": ["generator_code"]})]

    async def call_tool(self, name, _args):
        payload = self.plan.pop(0)(self.bridge, self.tmp)
        raw = json.dumps(payload).encode()
        path = self.tmp / f"tool-{uuid4().hex}.json"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
        self.rows[-1]["tool_events"] = self.rows[-1]["tool_events"] + [{
            "status": self.event_status, "name": name,
            "call_id": f"call-{self.calls}", "agent_id": self.event_agent,
            "result_path": str(path),
            "result_sha256": hashlib.sha256(raw).hexdigest()}]
        return SimpleNamespace(content=[SimpleNamespace(text=raw.decode())])


def run_seed_phase(tmp_path, harness, *, max_iterations=20, required=5,
                   prior=()):
    for seed in prior:
        harness.bridge.add_direction_seed(seed, DIRECTION)
    strategy, _ = make_strategy(harness.factory)
    strategy._get_fuzzer_source_code = lambda: "/* harness */"
    strategy.executor.fuzzer_manager = harness.bridge
    strategy.executor.results_path = tmp_path
    strategy._development_seed_required_unique = required
    direction = SimpleNamespace(direction_id=DIRECTION, name="parser",
                                risk_level="high", risk_reason="fixture",
                                core_functions=["parse"])
    created = []

    async def base_run_async(self, **kwargs):
        # The production BaseAgent.run_async minus AgentContext/MCP server
        # construction; the real loop and its exception settlement remain.
        self._context = FakeAgentContext(AGENT_ID)
        self.llm_client.agent_id = AGENT_ID
        created.append(self)
        try:
            return await self._run_agent_loop(
                harness, self.get_initial_message(**kwargs))
        except Exception as exc:
            if self.stop_reason is None:
                self.stop_reason = getattr(exc, "fbv2_stop_reason", "error")
            return f"Agent failed: {exc}"

    real_init = __import__("fuzzingbrain.fuzzer.seed_agent",
                           fromlist=["SeedAgent"]).SeedAgent.__init__

    def init(self, *args, **kwargs):
        kwargs["max_iterations"] = max_iterations
        real_init(self, *args, **kwargs)

    with patch.object(BaseAgent, "run_async", base_run_async), \
            patch("fuzzingbrain.fuzzer.seed_agent.SeedAgent.__init__", init):
        try:
            asyncio.run(strategy._generate_direction_seeds_and_start_global_fuzzer(
                [direction]))
            error = None
        except IncompleteInjectedAgent as exc:
            error = exc
    return error, created[0]


# --------------------------------------------------------------------------
# Seed completion contract
# --------------------------------------------------------------------------

def test_first_create_seed_meeting_k_completes_without_more_turns(tmp_path):
    harness = SeedHarness(tmp_path, [create(unique(5))])
    error, agent = run_seed_phase(tmp_path, harness)
    assert error is None
    assert agent.completion_reason == "SEED_CORPUS_READY"
    assert agent.stop_reason is None
    assert len(agent.new_unique_seed_digests) == 5
    assert harness.calls == 1
    harness.bridge.start_global_fuzzer.assert_awaited_once()


@pytest.mark.parametrize("required", [1, 2, 3, 4])
def test_smaller_seed_minimum_settles_real_agent_loop(tmp_path, required):
    harness = SeedHarness(tmp_path, [create(unique(required))])
    error, agent = run_seed_phase(tmp_path, harness, required=required)
    assert error is None
    assert agent.completion_reason == "SEED_CORPUS_READY"
    assert len(agent.new_unique_seed_digests) == required
    assert harness.calls == 1
    harness.bridge.start_global_fuzzer.assert_awaited_once()


def test_settled_generator_failure_then_success_completes(tmp_path):
    harness = SeedHarness(tmp_path, [failed, create(unique(5))])
    error, agent = run_seed_phase(tmp_path, harness)
    assert error is None
    assert agent.seed_tool_failures == 1
    assert agent.completion_reason == "SEED_CORPUS_READY"
    assert harness.calls == 2


def test_creation_events_with_only_duplicates_never_complete(tmp_path):
    same = [b"dup"] * 5
    harness = SeedHarness(tmp_path, [create(same), create(same)])
    error, agent = run_seed_phase(tmp_path, harness, max_iterations=2)
    assert agent.seeds_generated == 10          # creation events
    assert len(agent.new_unique_seed_digests) == 1
    assert agent.completion_reason is None
    assert error is not None and error.reason == "max_iterations"
    harness.bridge.start_global_fuzzer.assert_not_awaited()


def test_prior_run_seeds_never_count_toward_current_run(tmp_path):
    prior = unique(5, "prior")
    harness = SeedHarness(tmp_path, [create(prior), create(prior)])
    error, agent = run_seed_phase(tmp_path, harness, max_iterations=2,
                                  prior=prior)
    assert len(agent.seed_corpus_baseline) == 5
    assert agent.new_unique_seed_digests == frozenset()
    assert error is not None and error.reason == "max_iterations"


def test_last_turn_create_seed_success_is_not_max_iterations(tmp_path):
    harness = SeedHarness(tmp_path, [failed, create(unique(2, "a")),
                                     create(unique(3, "b"))])
    error, agent = run_seed_phase(tmp_path, harness, max_iterations=3)
    assert error is None
    assert agent.stop_reason is None
    assert agent.completion_reason == "SEED_CORPUS_READY"
    assert harness.calls == 3


def test_uncertain_last_request_is_never_promoted(tmp_path):
    harness = SeedHarness(tmp_path, [create(unique(3))], uncertain_on=2)
    error, agent = run_seed_phase(tmp_path, harness)
    assert agent.completion_reason is None
    assert error is not None and error.reason == "uncertain_remote"


def test_incomplete_tool_event_blocks_settlement(tmp_path):
    harness = SeedHarness(tmp_path, [create(unique(5))], event_status="STARTED")
    error, agent = run_seed_phase(tmp_path, harness)
    assert agent.completion_reason == "SEED_CORPUS_READY"
    assert error is not None and error.reason == "seed_corpus_unverified"
    harness.bridge.start_global_fuzzer.assert_not_awaited()


def test_fatal_sandbox_cleanup_keeps_its_structured_reason(tmp_path):
    harness = SeedHarness(tmp_path, [fatal])
    error, agent = run_seed_phase(tmp_path, harness)
    assert agent.fatal_seed_cleanup is True
    assert error is not None and error.reason == "sandbox_cleanup_uncertain"


def test_bridge_spool_filename_digest_mismatch_fails_closed(tmp_path):
    harness = SeedHarness(tmp_path, [tamper_after(unique(5))])
    error, agent = run_seed_phase(tmp_path, harness)
    assert agent.completion_reason is None
    assert error is not None and error.reason == "seed_corpus_unverified"
    with pytest.raises(ValueError, match="digest mismatch"):
        harness.bridge.verified_direction_seed_digests(DIRECTION)


def test_other_agent_receipt_cannot_settle_this_run(tmp_path):
    harness = SeedHarness(tmp_path, [create(unique(5))],
                          event_agent="6af2db99f34a38a2cc411aff")
    error, _ = run_seed_phase(tmp_path, harness)
    assert error is not None and error.reason == "seed_corpus_unverified"


def test_seeds_not_named_by_this_agents_receipts_cannot_settle(tmp_path):
    harness = SeedHarness(tmp_path, [foreign_writer])
    error, agent = run_seed_phase(tmp_path, harness)
    assert agent.completion_reason == "SEED_CORPUS_READY"
    assert error is not None and error.reason == "seed_corpus_unverified"


def test_past_request_rows_are_outside_this_clients_issued_ids(tmp_path):
    harness = SeedHarness(tmp_path, [create(unique(5))])
    stale = {"request_id": "stale", "role": "seed", "owner_id": DIRECTION,
             "status": "COMPLETED", "tool_events": []}
    harness.rows.append(stale)
    error, agent = run_seed_phase(tmp_path, harness)
    assert error is None
    assert "stale" not in agent.llm_client.provider.issued_request_ids


@pytest.mark.parametrize("other_status", ["STARTED", "UNCERTAIN"])
def test_parallel_hp_model_request_does_not_invalidate_owned_seed_corpus(
        tmp_path, other_status):
    harness = SeedHarness(tmp_path, [create(unique(5))])
    harness.rows.append({
        "request_id": "other-hp-request", "role": "function_analysis",
        "owner_id": "hp-function", "status": other_status,
        "tool_events": [],
    })
    error, agent = run_seed_phase(tmp_path, harness)
    assert error is None
    assert agent.completion_reason == "SEED_CORPUS_READY"
    assert len(agent.new_unique_seed_digests) == 5
    harness.bridge.start_global_fuzzer.assert_awaited_once()


def test_parallel_hp_physical_process_does_not_invalidate_owned_seed_corpus(
        tmp_path):
    harness = SeedHarness(tmp_path, [create(unique(5))])
    harness.bridge.campaign.ledger.snapshot = lambda: {
        "stop_status": None,
        "active": {"hp-guided": {"role": "hp"}},
    }
    error, agent = run_seed_phase(tmp_path, harness)
    assert error is None
    assert agent.completion_reason == "SEED_CORPUS_READY"
    harness.bridge.start_global_fuzzer.assert_awaited_once()


def test_campaign_process_stop_still_blocks_seed_settlement(tmp_path):
    harness = SeedHarness(tmp_path, [create(unique(5))])
    harness.bridge.campaign.ledger.snapshot = lambda: {
        "stop_status": "WALL_LIMIT", "active": {},
    }
    error, agent = run_seed_phase(tmp_path, harness)
    assert agent.completion_reason == "SEED_CORPUS_READY"
    assert error is not None and error.reason == "seed_corpus_unverified"
    harness.bridge.start_global_fuzzer.assert_not_awaited()


def test_seed_contract_requires_k_and_snapshot_together():
    from fuzzingbrain.fuzzer.seed_agent import SeedAgent
    with pytest.raises(ValueError):
        SeedAgent(task_id="t", worker_id="w", fuzzer="f", sanitizer="address",
                  fuzzer_manager=None, repos=None, llm_client=MagicMock(),
                  required_unique_seed_count=5)


def test_public_reason_allowlist_preserves_structure():
    assert public_incomplete_reason("max_iterations") == ("max_iterations", None)
    assert public_incomplete_reason("free text <script>")[0] == "incomplete_unknown"
    assert public_incomplete_reason(None)[0] == "incomplete_unknown"


# --------------------------------------------------------------------------
# Verifier disposition contract
# --------------------------------------------------------------------------

def _update(mode, **kwargs):
    from fuzzingbrain.tools import suspicious_points as tools
    client = MagicMock()
    client.update_suspicious_point.return_value = {"updated": True}
    token = tools.set_sp_pov_admission_mode(mode)
    try:
        with patch.object(tools, "_ensure_client", return_value=None), \
                patch.object(tools, "_get_client", return_value=client):
            result = tools.update_suspicious_point_impl("sp", **kwargs)
    finally:
        tools.reset_sp_pov_admission_mode(token)
    return result, client


def test_explicit_mode_rejects_missing_disposition_before_db():
    result, client = _update("explicit_disposition", is_checked=True,
                             is_important=True, pov_guidance="input")
    assert result["success"] is False
    client.update_suspicious_point.assert_not_called()


@pytest.mark.parametrize("disposition", ["TESTABLE_UNCERTAIN", "SUPPORTED"])
def test_explicit_mode_admits_enabled_dispositions(disposition):
    result, client = _update("explicit_disposition", is_checked=True,
                             score=0.1, is_important=False,
                             verification_disposition=disposition,
                             pov_guidance="input")
    assert result["success"] is True
    assert client.update_suspicious_point.call_args.kwargs[
        "pov_admission_mode"] == "explicit_disposition"


def test_legacy_mode_keeps_previous_behavior():
    result, client = _update("legacy_score", is_checked=True, score=0.2)
    assert result["success"] is True
    client.update_suspicious_point.assert_called_once()


def test_refuted_stays_disabled_in_both_modes():
    for mode in ("legacy_score", "explicit_disposition"):
        result, client = _update(mode, is_checked=True,
                                 verification_disposition="REFUTED",
                                 pov_guidance="x")
        assert result["success"] is False
        client.update_suspicious_point.assert_not_called()


def test_host_rejects_missing_disposition_before_any_write():
    from fuzzingbrain.analyzer.server import AnalysisServer
    server = object.__new__(AnalysisServer)
    server.repos = MagicMock()
    server._log = lambda *args, **kwargs: None

    async def run_sync(func, *args):
        return func(*args)

    server._run_sync = run_sync
    with pytest.raises(ValueError, match="explicit disposition"):
        asyncio.run(server._update_suspicious_point({
            "id": "sp", "is_checked": True,
            "pov_admission_mode": "explicit_disposition"}))
    server.repos.suspicious_points.update_verifier_fields.assert_not_called()
    with pytest.raises(ValueError, match="unknown PoV admission mode"):
        asyncio.run(server._update_suspicious_point({
            "id": "sp", "pov_admission_mode": "relaxed"}))


def test_admission_mode_does_not_leak_between_concurrent_agents():
    from fuzzingbrain.tools import suspicious_points as tools
    seen = {}

    async def agent(name, mode):
        token = tools.set_sp_pov_admission_mode(mode)
        try:
            await asyncio.sleep(0)
            seen[name] = await asyncio.to_thread(
                contextvars.copy_context().run, tools.get_sp_pov_admission_mode)
        finally:
            tools.reset_sp_pov_admission_mode(token)

    async def main():
        await asyncio.gather(agent("a", "explicit_disposition"),
                             agent("b", "legacy_score"))
        return tools.get_sp_pov_admission_mode()

    assert asyncio.run(main()) is None
    assert seen == {"a": "explicit_disposition", "b": "legacy_score"}


def test_low_score_disposition_keeps_pov_eligibility():
    point = SimpleNamespace(score=0.05, is_important=False,
                            verification_disposition="TESTABLE_UNCERTAIN")
    assert AgentPipeline._should_admit_pov(
        PipelineConfig(pov_admission_mode="explicit_disposition"), point)
    assert not AgentPipeline._should_admit_pov(
        PipelineConfig(pov_admission_mode="legacy_score"), point)


# --------------------------------------------------------------------------
# High-Recall lineage
# --------------------------------------------------------------------------

def _low_score_case(tmp_path, repos):
    task_id, direction_id, sp_id, pov_id = (str(ObjectId()) for _ in range(4))
    creator, verifier, pov_agent = (str(ObjectId()) for _ in range(3))
    function = Function(task_id=task_id, name="parse_input", file_path="parse.c",
                        content="int parse_input(void) {return 0;}")
    assert repos.functions.save(function)
    point = SuspiciousPoint(
        suspicious_point_id=sp_id, task_id=task_id, direction_id=direction_id,
        function_name="parse_input", description="candidate",
        vuln_type="use-after-free", score=0.1, is_checked=True,
        is_important=False, verification_notes="weak",
        verification_disposition="TESTABLE_UNCERTAIN", pov_guidance="input",
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}],
        created_by_agent_id=creator, verified_by_agent_id=verifier)
    repos.suspicious_points.collection.insert_one(point.to_dict())
    code = "def generate(variant): return b'abc'"
    import base64
    assert repos.povs.save(POV(
        pov_id=pov_id, task_id=task_id, suspicious_point_id=sp_id,
        generation_id=str(ObjectId()), agent_id=pov_agent, source="agent",
        harness_name="fuzz", sanitizer="address", gen_blob=code,
        blob=base64.b64encode(b"abc").decode()))
    gate = CampaignModelGate(tmp_path / "campaign.json", "fixture", 4, 60,
                             create=True)
    sp_call = _record(gate, "sp1", "sp",
                      f"{direction_id}:{function.function_id}:0",
                      "create_suspicious_point",
                      {"function_name": "parse_input",
                       "description": "candidate",
                       "vuln_type": "use-after-free"},
                      {"success": True, "created": True, "id": sp_id}, creator)
    verify_call = _record(gate, "verify1", "verifier", f"verify_1:{sp_id}",
                          "update_suspicious_point",
                          {"suspicious_point_id": sp_id, "is_checked": True,
                           "is_important": False, "score": 0.1,
                           "verification_notes": "weak",
                           "verification_disposition": "TESTABLE_UNCERTAIN",
                           "pov_guidance": "input"},
                          {"success": True, "updated": True,
                           "server_result": {"updated": True}}, verifier)
    pov_call = _record(gate, "pov1", "pov", f"pov_1:{sp_id}", "create_pov",
                       {"generator_code": code},
                       {"success": True, "pov_ids": [pov_id], "count": 1,
                        "attempt": 1}, pov_agent)
    return dict(gate=gate, repos=repos, task_id=task_id,
                direction_id=direction_id, sp_id=sp_id,
                sp_request_id="sp1", sp_call_id=sp_call,
                verifier_request_id="verify1", verifier_call_id=verify_call,
                pov_request_id="pov1", pov_call_id=pov_call)


def test_low_score_high_recall_candidate_keeps_lineage(tmp_path, repos):
    args = _low_score_case(tmp_path, repos)
    explicit = verify_candidate_lineage(
        **args, pov_admission_mode="explicit_disposition")
    assert explicit["status"] == "VERIFIED"
    assert explicit["automatic_discovery"] is False
    legacy = verify_candidate_lineage(**args, pov_admission_mode="legacy_score")
    assert legacy["reason"] == "VERIFIER_DB_OR_OWNER_MISMATCH"
    assert verify_candidate_lineage(**args, pov_admission_mode=None)[
        "reason"] == "POV_ADMISSION_MODE_INVALID"


def test_explicit_lineage_requires_matching_db_disposition(tmp_path, repos):
    args = _low_score_case(tmp_path, repos)
    repos.suspicious_points.collection.update_one(
        {"_id": ObjectId(args["sp_id"])},
        {"$set": {"verification_disposition": "SUPPORTED"}})
    assert verify_candidate_lineage(
        **args, pov_admission_mode="explicit_disposition")[
            "reason"] == "VERIFIER_DB_OR_OWNER_MISMATCH"


# --------------------------------------------------------------------------
# Gate result axes, run_id and HP boundary
# --------------------------------------------------------------------------

def _caps():
    return live.PublicDevCaps(
        physical_model_calls=3, model_wall_seconds=30,
        calls_per_agent=2, total_wall_seconds=1000,
        total_fuzz_seconds=45, global_fuzz_seconds=5,
        global_reservation_seconds=42.5, global_replay_limit=1,
        pov_timeout_seconds=2, pov_wall_seconds=12,
        process_output_limit_bytes=4096)


def _public_dev(tmp_path, monkeypatch, gate_rows, *, lineage_ids=(),
                task_id=None, run_id="run", run_dir=None, pov_root=None,
                finished=None, proven_verified_ids=None, setup_repos=None,
                process_active=None, model_records=(), capture_bound=None):
    entry = Path(live.__file__).resolve().parent / "original_public_live_entry.py"
    spec = tmp_path / "spec.json"
    spec.write_text("{}")
    token = object()
    marker = {"pid": os.getpid(), "spec_path": str(spec),
              "spec_sha256": hashlib.sha256(spec.read_bytes()).hexdigest(),
              "token": token, "used": False,
              "engine_py_sha256": "a" * 64, "product_py_sha256": "b" * 64,
              "evaluation_py_sha256": "c" * 64}
    monkeypatch.setitem(sys.modules, "__main__", SimpleNamespace(
        __file__=str(entry), _PINNED_PUBLIC_BOOTSTRAP=marker))
    monkeypatch.setattr(sys, "argv", [str(entry), "--authorize-public-dev"])
    monkeypatch.setattr(live, "_isolated_runtime", lambda: True)
    monkeypatch.setattr(live, "require_journaled_mongo", lambda *_a: None)
    from devtools import product_qualified_runtime as qualified_runtime
    monkeypatch.setattr(qualified_runtime, "consume_qualified_pov_observation",
                        lambda _adapter, pov_id, **_kw: dict(gate_rows[pov_id]))
    monkeypatch.setattr(live, "_model_lineage_gate_verified_pov_ids",
                        lambda *_a: list(lineage_ids))
    if proven_verified_ids is not None:
        # Status-axis tests with synthetic rows stub the Goal A.1.2
        # replay-identity proof; the proof itself is tested on real rows.
        monkeypatch.setattr(live, "_authenticated_verified_gate_pov_ids",
                            lambda *_a: set(proven_verified_ids))
    task = tmp_path / "task"
    (task / "repo").mkdir(parents=True)
    if pov_root is None:
        pov_root = tmp_path / "pov"
        pov_root.mkdir()
    for pov_id in gate_rows:
        (pov_root / pov_id).mkdir(exist_ok=True)
        if not (pov_root / pov_id / "runtime.json").exists():
            (pov_root / pov_id / "runtime.json").write_text(
                '{"status":"CRASH_OBSERVED"}')
    task_id = task_id or str(ObjectId())
    repos = RepositoryManager(mongomock.MongoClient().goal_a)
    if setup_repos is not None:
        setup_repos(repos, task_id)
    worker = SimpleNamespace(task_id=task_id, repos=repos,
                             development_pov_admission_mode="explicit_disposition")
    worker._get_strategy = lambda: SimpleNamespace(executor=worker)
    worker.run = lambda: {"pov_generated": 0}
    clean = {"stop_status": None, "active": process_active or {}, "wall_spent_seconds": 1.0,
             "fuzz_spent_seconds": 1.0, "revision": 2,
             "finished": list(finished or [])}
    if run_dir is None:
        run_dir = tmp_path / "run"
        run_dir.mkdir()
    bound = SimpleNamespace(
        recheck=lambda: None, bootstrap_token=token,
        identity=SimpleNamespace(task_id=task_id, run_id=run_id, task_path=task,
                                 run_dir=run_dir, engine_py_sha256="a" * 64,
                                 product_py_sha256="b" * 64,
                                 evaluation_py_sha256="c" * 64),
        caps=_caps(), executor=worker,
        server=SimpleNamespace(repos=repos, socket_path=tmp_path / "x.sock"),
        admission=SimpleNamespace(summary={"project_name": "fixture"},
                                  qualification=SimpleNamespace(
                                      binary_sha256="b" * 64)),
        process_ledger=SimpleNamespace(receipt_snapshot=lambda: (clean, "e" * 64)),
        model_gate=SimpleNamespace(snapshot=lambda: {
            "physical": len(model_records), "records": list(model_records)}),
        global_campaign=SimpleNamespace(final_result={"status": "RAN"},
                                        campaign=SimpleNamespace(
                                            run_dir=run_dir / "global")),
        pov_adapter=SimpleNamespace(root=pov_root))
    if capture_bound is not None:
        capture_bound(bound)
    return live.run_original_public_dev(bound, explicit_public_dev_authorization=True)


OUTCOME = "FBV2_POV_PRODUCT_GATE_OUTCOME_V1"


def test_bare_blocked_status_is_not_terminal(tmp_path, monkeypatch):
    # Goal A.1 (G-1): a BLOCKED_* label without an authenticated structured
    # TERMINAL_REJECTED resolution stays pending. Proven terminal cases are in
    # tests/test_goal_a1_gate_resolution.py.
    pov = str(ObjectId())
    result = _public_dev(tmp_path, monkeypatch, {pov: {
        "kind": OUTCOME, "pov_id": pov,
        "product_gate_status": "BLOCKED_ROOT_CAUSE"}})
    assert result["pov_crashes_pending_independent_validation"] == 1
    assert result["pov_crashes_gate_terminal_not_verified_count"] == 0
    assert result["verification_status"] == "PENDING_INDEPENDENT_VALIDATION"
    assert result["status"] == "INCOMPLETE"
    assert result["automatic_discovery_verified_count"] == 0


@pytest.mark.parametrize("row", [
    {"product_gate_status": "INCOMPLETE_CONSUMPTION", "error_type": "OSError"},
    {"kind": "FBV2_POV_PRODUCT_GATE_INCOMPLETE_V1",
     "product_gate_status": "BLOCKED_ROOT_CAUSE"},
    {"kind": OUTCOME,
     "product_gate_status": "TARGET_OOB_OBSERVED_PENDING_CAUSAL_EVIDENCE"},
])
def test_unconsumed_or_incomplete_gate_stays_pending(tmp_path, monkeypatch, row):
    pov = str(ObjectId())
    result = _public_dev(tmp_path, monkeypatch, {pov: {**row, "pov_id": pov}})
    assert result["pov_crashes_pending_independent_validation"] == 1
    assert result["status"] == "INCOMPLETE"
    assert result["verification_status"] == "PENDING_INDEPENDENT_VALIDATION"


def test_gate_verified_and_discovery_unproven_are_separate(tmp_path, monkeypatch):
    pov = str(ObjectId())
    result = _public_dev(tmp_path, monkeypatch, {pov: {
        "kind": OUTCOME, "pov_id": pov, "product_gate_status": "VERIFIED"}},
        lineage_ids=[pov], proven_verified_ids=[pov])
    assert result["status"] == "EXECUTED_GATE_VERIFIED_DISCOVERY_UNPROVEN"
    assert result["verification_status"] == (
        "MODEL_POV_PRODUCT_GATE_VERIFIED_DISCOVERY_UNPROVEN")
    assert result["pov_crashes_gate_verified_count"] == 1
    assert result["automatic_discovery_verified_count"] == 0
    assert result["pov_lineage_rows"][0]["automatic_discovery"] is False


def test_gate_verified_without_model_lineage_is_reported(tmp_path, monkeypatch):
    pov = str(ObjectId())
    result = _public_dev(tmp_path, monkeypatch, {pov: {
        "kind": OUTCOME, "pov_id": pov, "product_gate_status": "VERIFIED"}},
        proven_verified_ids=[pov])
    assert result["status"] == "EXECUTED_UNVERIFIED"
    assert result["verification_status"] == (
        "PRODUCT_GATE_VERIFIED_MODEL_ORIGIN_UNPROVEN")


def test_unproven_verified_label_is_pending_even_with_lineage(tmp_path, monkeypatch):
    # Goal A.1.2: a VERIFIED label without a re-proven replay identity is not
    # success, not lineage credit, and keeps the run INCOMPLETE.
    pov = str(ObjectId())
    result = _public_dev(tmp_path, monkeypatch, {pov: {
        "kind": OUTCOME, "pov_id": pov, "product_gate_status": "VERIFIED",
        "gate_resolution": "VERIFIED", "gate_resolution_reason": "GATE_VERIFIED"}},
        lineage_ids=[pov])
    assert result["pov_crashes_gate_verified_count"] == 0
    assert result["model_lineage_gate_verified_pov_count"] == 0
    assert result["pov_crashes_pending_independent_validation"] == 1
    assert result["status"] == "INCOMPLETE"


def _combined_spec(tmp_path):
    spec = {"development_seed_scope": {
        "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_HP_POST_WORKER_DEV_V1",
        "seed_directions": 1, "sp_function_limit": None,
        "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1",
        "security_invariant_focus": "LIFETIME_OWNERSHIP",
        "direction_selection": "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
        "pov_attempts_per_candidate": 3,
        "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2}},
        "hp": {"enabled": True, "max_items": 1, "max_model_calls": 3}}
    path = (tmp_path / "spec.json").resolve()
    path.write_text(json.dumps(spec))
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("receipt", [
    {"status": "EXECUTED_GATE_VERIFIED_DISCOVERY_UNPROVEN",
     "verification_status": "MODEL_POV_PRODUCT_GATE_VERIFIED_DISCOVERY_UNPROVEN",
     "pov_crashes_gate_verified_count": 1},
    {"status": "EXECUTED_UNVERIFIED",
     "verification_status": "POV_CRASH_GATE_TERMINAL_NOT_VERIFIED",
     "pov_crashes_gate_terminal_not_verified_count": 1},
])
def test_hp_reports_exact_gate_result_block(tmp_path, receipt):
    from devtools.original_hp_live_optin import _combined_concurrent_hp_selection
    path, sha = _combined_spec(tmp_path)
    bound = SimpleNamespace(server=SimpleNamespace(repos=MagicMock()))
    with pytest.raises(ValueError, match="^HP_BLOCKED_GATE_RESULT_NOT_QUEUE_SETTLED$"):
        _combined_concurrent_hp_selection(bound, receipt, path, sha)
    bound.server.repos.suspicious_points.collection.find.assert_not_called()


def test_signed_concurrent_branch_binds_run_id_and_seed_k():
    source = Path(live.__file__).read_text()
    branch = source[source.index("elif caps.seed_direction_limit == 1:"):]
    branch = branch[:branch.index("bound = BoundOriginalPublicDev(")]
    assert "executor.development_run_id = identity.run_id" in branch
    assert "executor.development_seed_required_unique = caps.seed_required_unique" in branch
    full = source[source.index("elif caps.full_nohint_sp:"):
                  source.index("elif caps.seed_direction_limit == 1:")]
    assert "executor.development_run_id = identity.run_id" in full


def test_direction_receipt_carries_development_run_id(tmp_path):
    from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy
    strategy, _ = make_strategy(lambda role, owner: None)
    strategy.executor.development_run_id = "6af2c1e06dda348f0c04f678"
    strategy.results_path = tmp_path
    directions = [SimpleNamespace(direction_id=DIRECTION, name="parser",
                                  risk_level="high", core_functions=["parse"])]
    strategy._development_direction_plan = (tmp_path / "plan.json", "0" * 64)
    receipt = POVFullscanStrategy._write_direction_selection_receipt(
        strategy, directions, directions, 1)
    if receipt is None:
        pytest.skip("selection receipt is written only for scoped development runs")
    written = json.loads(Path(receipt["path"]).read_text())
    assert written["run_id"] == "6af2c1e06dda348f0c04f678"


def test_unavailable_admission_mode_fails_closed_without_crashing():
    assert live._signed_pov_admission_mode(SimpleNamespace()) is None
    assert live._signed_pov_admission_mode(SimpleNamespace(
        executor=SimpleNamespace(development_pov_admission_mode="relaxed"))) is None
    assert live._signed_pov_admission_mode(SimpleNamespace(
        executor=SimpleNamespace(
            development_pov_admission_mode="explicit_disposition"))) == (
        "explicit_disposition")
