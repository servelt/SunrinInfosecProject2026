"""Provider-free check that original zero-Seed completion reaches SP eligibility."""

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from fuzzingbrain.worker.pipeline import IncompleteInjectedAgent
from fuzzingbrain.worker.strategies import pov_fullscan


def _run_phase(monkeypatch, *, seed_result, seed_limit=None,
               direction_count=1):
    calls = []
    seed_owners = []
    bridge = SimpleNamespace(
        model_gate=object(),
        record_clean_no_seed=lambda **kwargs: calls.append(kwargs))

    @asynccontextmanager
    async def client(*args):
        seed_owners.append(args[2])
        yield object()

    class ScriptedSeedAgent:
        def __init__(self, **_kwargs):
            pass

        async def generate_direction_seeds(self, **_kwargs):
            if isinstance(seed_result, Exception):
                raise seed_result
            return seed_result

    monkeypatch.setattr(pov_fullscan, "SeedAgent", ScriptedSeedAgent)
    monkeypatch.setattr(pov_fullscan, "injected_agent_client", client)
    monkeypatch.setattr(pov_fullscan, "require_injected_agent_complete",
                        lambda *_args: None)
    executor = SimpleNamespace(fuzzer_manager=bridge,
                               qualified_seed_generator=lambda **_kwargs: [],
                               require_original_global_bridge=True)
    strategy = SimpleNamespace(
        executor=executor, llm_client_factory=lambda *_args: object(),
        _get_fuzzer_source_code=lambda: "", agent_log_dir=None,
        task_id="task", worker_id="worker", fuzzer="fuzzer",
        sanitizer="address", repos=object(),
        _development_seed_limit=seed_limit,
        log_info=lambda *_args: None, log_warning=lambda *_args: None,
        log_debug=lambda *_args: None)
    directions = [SimpleNamespace(direction_id=f"direction_{chr(65 + n)}",
                                  name="input", core_functions=[],
                                  risk_level="high", risk_reason="")
                  for n in range(direction_count)]
    asyncio.run(pov_fullscan.POVFullscanStrategy.
                _generate_direction_seeds_and_start_global_fuzzer(
                    strategy, directions))
    bridge.seed_owners = seed_owners
    bridge.seed_phase = getattr(strategy, "_direction_seed_phase", None)
    return calls, bridge


def test_clean_zero_seed_records_explicit_global_skip(monkeypatch):
    result = {"success": True, "direction_id": "direction_A",
              "seeds_generated": 0, "seed_tool_failures": 0,
              "fatal_seed_cleanup": False}
    calls, bridge = _run_phase(monkeypatch, seed_result=result)
    assert len(calls) == 1
    assert calls[0]["expected_direction_ids"] == ["direction_A"]
    assert calls[0]["seed_results"][0]["result"] == result
    assert calls[0]["model_gate"] is bridge.model_gate


def test_one_seed_dev_limits_only_seed_phase(monkeypatch):
    result = {"success": True, "direction_id": "direction_A",
              "seeds_generated": 0, "seed_tool_failures": 0,
              "fatal_seed_cleanup": False}
    calls, bridge = _run_phase(monkeypatch, seed_result=result,
                               seed_limit=1, direction_count=3)
    assert bridge.seed_owners == ["direction_A"]
    assert calls[0]["expected_direction_ids"] == ["direction_A"]
    assert bridge.seed_phase["status"] == "PARTIAL_SEED_SCOPE"
    assert bridge.seed_phase["selected_direction_ids"] == ["direction_A"]
    assert bridge.seed_phase["skipped_direction_ids"] == [
        "direction_B", "direction_C"]


def test_failed_seed_turn_never_records_global_skip(monkeypatch):
    calls = []

    @asynccontextmanager
    async def client(*_args):
        yield object()

    class FailedSeedAgent:
        def __init__(self, **_kwargs):
            pass

        async def generate_direction_seeds(self, **_kwargs):
            raise RuntimeError("provider refused")

    monkeypatch.setattr(pov_fullscan, "SeedAgent", FailedSeedAgent)
    monkeypatch.setattr(pov_fullscan, "injected_agent_client", client)
    monkeypatch.setattr(pov_fullscan, "require_injected_agent_complete",
                        lambda *_args: None)
    bridge = SimpleNamespace(
        model_gate=object(),
        record_clean_no_seed=lambda **kwargs: calls.append(kwargs))
    strategy = SimpleNamespace(
        executor=SimpleNamespace(fuzzer_manager=bridge,
                                 require_original_global_bridge=True),
        llm_client_factory=lambda *_args: object(),
        _get_fuzzer_source_code=lambda: "", agent_log_dir=None,
        task_id="task", worker_id="worker", fuzzer="fuzzer",
        sanitizer="address", repos=object(),
        log_info=lambda *_args: None, log_warning=lambda *_args: None,
        log_debug=lambda *_args: None)
    direction = SimpleNamespace(direction_id="direction_A", name="input",
                                core_functions=[], risk_level="high",
                                risk_reason="")
    with pytest.raises(IncompleteInjectedAgent):
        asyncio.run(pov_fullscan.POVFullscanStrategy.
                    _generate_direction_seeds_and_start_global_fuzzer(
                        strategy, [direction]))
    assert calls == []
