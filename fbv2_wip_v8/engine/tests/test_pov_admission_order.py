"""An opt-in PoV budget refusal cannot start a physical SP Fuzzer."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from devtools.campaign_model_gate import (
    CampaignPendingBudget, campaign_candidate_owner_id,
)
from fuzzingbrain.worker.pipeline import (
    AgentPipeline, IncompleteInjectedAgent, PipelineConfig,
)


def test_presend_pov_budget_refusal_does_not_start_sp_fuzzer():
    repos = MagicMock()
    point = SimpleNamespace(
        suspicious_point_id="sp-id",
        function_name="target",
        pov_claim_token="pov-claim-token",
        to_dict=lambda: {"suspicious_point_id": "sp-id"},
    )
    repos.suspicious_points.claim_for_pov.side_effect = [point]
    manager = SimpleNamespace(
        start_sp_fuzzer=AsyncMock(return_value=True),
        stop_sp_fuzzer=AsyncMock(),
    )
    factory_calls = []

    def refuse_before_transport(role, owner_id):
        factory_calls.append((role, owner_id))
        raise CampaignPendingBudget("PRE_SEND_BUDGET")

    pipeline = AgentPipeline(
        "task", repos, fuzzer="f", sanitizer="address",
        config=PipelineConfig(poll_interval=0),
        llm_client_factory=refuse_before_transport,
    )
    pipeline._fuzzer_manager = manager

    with pytest.raises(IncompleteInjectedAgent) as caught:
        asyncio.run(pipeline._run_pov_agent("pov_1"))

    assert caught.value.reason == "budget_before_transport"
    assert factory_calls == [("pov", campaign_candidate_owner_id(
        agent_id="pov_1", task_id="task", harness_name="f",
        sanitizer="address", sp_id="sp-id"))]
    manager.start_sp_fuzzer.assert_not_awaited()
    manager.stop_sp_fuzzer.assert_not_awaited()
    assert pipeline._incomplete_error == "PRE_SEND_BUDGET"
    assert pipeline._incomplete_reason == "budget_before_transport"
    repos.suspicious_points.complete_pov.assert_not_called()
    repos.suspicious_points.preserve_incomplete_candidate.assert_called_once()


def test_default_pov_path_still_starts_fuzzer_before_agent_construction():
    repos = MagicMock()
    point = SimpleNamespace(
        suspicious_point_id="sp-id",
        function_name="target",
        pov_claim_token="pov-claim-token",
        to_dict=lambda: {"suspicious_point_id": "sp-id"},
    )
    repos.suspicious_points.claim_for_pov.side_effect = [point] + [None] * 6
    repos.suspicious_points.count_by_status.return_value = 0
    manager = SimpleNamespace(
        start_sp_fuzzer=AsyncMock(return_value=True),
        stop_sp_fuzzer=AsyncMock(),
    )
    pipeline = AgentPipeline(
        "task", repos, fuzzer="f", sanitizer="address",
        config=PipelineConfig(poll_interval=0),
    )
    pipeline._fuzzer_manager = manager
    pipeline._sp_finding_done = True

    from unittest.mock import patch
    with patch("fuzzingbrain.worker.pipeline.POVAgent") as agent:
        def construct(**kwargs):
            assert manager.start_sp_fuzzer.await_count == 1
            mock = MagicMock()
            mock.generate_pov_async = AsyncMock(return_value=SimpleNamespace(
                success=False, pov_id=None))
            return mock

        agent.side_effect = construct
        asyncio.run(pipeline._run_pov_agent("pov_1"))

    manager.start_sp_fuzzer.assert_awaited_once_with("sp-id")
    manager.stop_sp_fuzzer.assert_awaited_once_with("sp-id")
