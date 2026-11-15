"""Provider-free check that original zero-Seed completion reaches SP eligibility."""

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from fuzzingbrain.worker.pipeline import IncompleteInjectedAgent
from fuzzingbrain.worker.strategies import pov_fullscan


def _run_phase(monkeypatch, *, seed_result):
    calls = []
    bridge = SimpleNamespace(
        model_gate=object(),
        record_clean_no_seed=lambda **kwargs: calls.append(kwargs))

    @asynccontextmanager
    async def client(*_args):
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
                               require_original_global_bridge=True)
    strategy = SimpleNamespace(
        executor=executor, llm_client_factory=lambda *_args: object(),
        _get_fuzzer_source_code=lambda: "", agent_log_dir=None,
        task_id="task", worker_id="worker", fuzzer="fuzzer",
        sanitizer="address", repos=object(),
        log_info=lambda *_args: None, log_warning=lambda *_args: None,
        log_debug=lambda *_args: None)
    direction = SimpleNamespace(direction_id="direction_A", name="input",
                                core_functions=[], risk_level="high",
                                risk_reason="")
    asyncio.run(pov_fullscan.POVFullscanStrategy.
                _generate_direction_seeds_and_start_global_fuzzer(
                    strategy, [direction]))
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
