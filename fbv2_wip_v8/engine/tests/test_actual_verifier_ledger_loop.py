"""Actual Verifier/bridge/ledger/repository seam, with scripted transports."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from devtools.campaign_model_gate import CampaignLedgeredProvider, CampaignModelGate
from fuzzingbrain.agents.base import BaseAgent
from fuzzingbrain.agents.sp_generators import FullSPGenerator
from fuzzingbrain.core.models import SPStatus
from fuzzingbrain.core.models.suspicious_point import SuspiciousPoint
from fuzzingbrain.llms.codex_tool_bridge import CodexToolBridge
from fuzzingbrain.worker.pipeline import AgentPipeline, IncompleteInjectedAgent, PipelineConfig
from tests.test_campaign_candidate_states import setup_candidate
from tests.test_campaign_model_gate import ReceiptRequest, ReceiptTransport
from tests.test_fullscan_client_factory import make_strategy


@pytest.mark.parametrize("disposition", ["TESTABLE_UNCERTAIN", "SUPPORTED"])
@pytest.mark.parametrize("missing_completion", [False, True])
def test_actual_verifier_last_tool_settles_from_real_ledger(
        tmp_path, disposition, missing_completion):
    task_id, point, repo, repos = setup_candidate(SPStatus.PENDING_VERIFY)
    agent_id = "a" * 24
    args = {"suspicious_point_id": point.suspicious_point_id,
            "is_checked": True, "is_real": False, "is_important": False,
            "score": 0.1, "verification_disposition": disposition}
    gate = CampaignModelGate(tmp_path / "model-ledger.json", "actual-loop", 2, 60,
                             create=True)

    def factory(role, owner):
        transport = ReceiptTransport(
            tmp_path / role, missing_completion=missing_completion,
            tool_calls=[{"name": "update_suspicious_point",
                         "arguments": json.dumps(args)}])
        provider = CampaignLedgeredProvider(transport, gate, role=role, owner_id=owner)
        return CodexToolBridge(provider, ReceiptRequest, codex_model="fixture",
                               role=role, max_calls=1)

    factory._fbv2_campaign_gate = gate

    class MemoryMCP:
        async def list_tools(self):
            return [SimpleNamespace(
                name="update_suspicious_point", description="fixture transport",
                inputSchema={"type": "object", "properties": {}})]

        async def call_tool(self, name, values):
            assert name == "update_suspicious_point"
            current = repo.find_by_id(point.suspicious_point_id)
            assert repo.update_verifier_fields(
                point.suspicious_point_id,
                {**{k: v for k, v in values.items() if k != "suspicious_point_id"},
                 "verified_by_agent_id": agent_id},
                processor_id=current.processor_id,
                claim_token=current.verification_claim_token)
            return SimpleNamespace(content=[SimpleNamespace(text=json.dumps({
                "success": True, "updated": True, "server_result": {"updated": True}}))])

    async def without_db_context_and_mcp_startup(self, **kwargs):
        # Replace only Mongo AgentContext/server construction. The production
        # agent, loop, bridge, ledger proofs, queue and repository CAS run.
        self._context = SimpleNamespace(agent_id=agent_id,
                                        increment_iteration=lambda: None,
                                        increment_tool_calls=lambda: None)
        self.llm_client.agent_id = agent_id
        return await self._run_agent_loop(MemoryMCP(), self.get_initial_message(**kwargs))

    pipeline = AgentPipeline(
        task_id, repos, fuzzer="fuzz", sanitizer="address", llm_client_factory=factory,
        config=PipelineConfig(num_verify_agents=1, num_pov_agents=0,
                              verifier_max_iterations=1, poll_interval=0,
                              pov_admission_mode="explicit_disposition"))
    pipeline._sp_finding_done = True
    with patch.object(BaseAgent, "run_async", without_db_context_and_mcp_startup):
        if missing_completion:
            with pytest.raises(IncompleteInjectedAgent):
                asyncio.run(pipeline.run())
        else:
            asyncio.run(pipeline.run())
    stored = repo.find_by_id(point.suspicious_point_id)
    records = gate.snapshot()["records"]
    assert len(records) == 1
    if missing_completion:
        assert stored.status == SPStatus.INCOMPLETE_UNCERTAIN.value
        assert not stored.is_checked
        assert not records[0].get("tool_events")
    else:
        assert stored.status == SPStatus.PENDING_POV.value
        assert stored.is_checked and not stored.is_important and stored.score == 0.1
        assert stored.verification_claim_token is None
        assert gate.verify_response_evidence(records[0]["request_id"])["status"] == "VERIFIED"
        event = records[0]["tool_events"][0]
        assert event["agent_id"] == agent_id and event["status"] == "COMPLETED"
        assert gate.verify_tool_event(records[0]["request_id"], event["call_id"])["status"] == "VERIFIED"
        assert pipeline.stats.sp_verified == 1 and pipeline.stats.sp_verified_fp == 0


@pytest.mark.parametrize("missing_completion", [False, True])
def test_actual_discovery_last_create_has_verified_owned_db_receipt(tmp_path, missing_completion):
    task_id, _prior, repo, repos = setup_candidate(SPStatus.PENDING_VERIFY)
    direction, agent_id, owner = "b" * 24, "a" * 24, "direction:function:0"
    gate = CampaignModelGate(tmp_path / "discovery-ledger.json", "actual-sp", 2, 60,
                             create=True)
    args = {"function_name": "parse_input", "vuln_type": "buffer-overflow",
            "description": "scripted source candidate", "score": 0.1}
    transport = ReceiptTransport(
        tmp_path / "sp", missing_completion=missing_completion,
        tool_calls=[{"name": "create_suspicious_point", "arguments": json.dumps(args)}])
    provider = CampaignLedgeredProvider(transport, gate, role="sp", owner_id=owner)
    client = CodexToolBridge(provider, ReceiptRequest, codex_model="fixture",
                             role="sp", max_calls=1)
    client.agent_id = agent_id

    class MemoryMCP:
        async def list_tools(self):
            return [SimpleNamespace(name="create_suspicious_point",
                                    description="fixture transport",
                                    inputSchema={"type": "object", "properties": {}})]

        async def call_tool(self, name, values):
            assert name == "create_suspicious_point"
            point = SuspiciousPoint(
                task_id=task_id, direction_id=direction,
                created_by_agent_id=agent_id, **values,
                sources=[{"harness_name": "fixture_fuzzer", "sanitizer": "address"}])
            repo.collection.insert_one(point.to_dict())
            return SimpleNamespace(content=[SimpleNamespace(text=json.dumps({
                "success": True, "created": True, "id": point.suspicious_point_id}))])

    agent = FullSPGenerator(
        function_name="parse_input", function_source="int parse_input(char *p) { return p[0]; }",
        function_file="parser.c", function_lines=(1, 1),
        llm_client=client, max_iterations=1, verbose=False,
        require_context_sufficiency=True)
    agent._context = SimpleNamespace(agent_id=agent_id,
                                     increment_iteration=lambda: None,
                                     increment_tool_calls=lambda: None)
    asyncio.run(agent._run_agent_loop(MemoryMCP(), agent.get_initial_message()))
    strategy, _ = make_strategy(lambda *_: client)
    strategy.task_id, strategy.repos = task_id, repos
    strategy._development_sp_concurrent_queue = True
    ledger = SimpleNamespace(snapshot=lambda: {"stop_status": None})
    strategy.executor.development_process_ledger = ledger
    strategy.executor.fuzzer_manager = SimpleNamespace(
        model_gate=gate, campaign=SimpleNamespace(ledger=ledger))
    settled = strategy._settled_created_sp_limit_verified(
        client=client, agent=agent, role="sp", owner=owner,
        function_name="parse_input", direction_id=direction)
    if missing_completion:
        assert not agent.sp_created and settled is None
    else:
        assert agent.stop_reason == "max_iterations"
        assert settled == (1, 1, tuple(agent.created_sp_ids))
        current = repo.find_by_id(settled[2][0])
        assert current.created_by_agent_id == agent_id and current.score == 0.1
        row = gate.snapshot()["records"][0]
        assert gate.verify_response_evidence(row["request_id"])["status"] == "VERIFIED"
        event = row["tool_events"][0]
        assert gate.verify_tool_event(row["request_id"], event["call_id"])["status"] == "VERIFIED"
