"""Provider-free accounting checks for qualified PoV generator containers."""

from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from fuzzingbrain.core.models.suspicious_point import SPStatus
from fuzzingbrain.fuzzer.seed_sandbox import (
    IMAGE_ID_ENV, SeedSandboxCleanupError, SeedSandboxOutputLimitError,
)
from fuzzingbrain.tools.pov import _execute_generator_code
from fuzzingbrain.tools.qualified_runtime import (
    QualifiedGeneratorRequest, QualifiedRuntimeBinding,
)


EVAL_TOOLS = Path(__file__).resolve().parents[2] / "evaluation_tools"
if str(EVAL_TOOLS) not in sys.path:
    sys.path.insert(0, str(EVAL_TOOLS))

from dev_persistent_process_ledger_v2 import PersistentProcessLedgerV2
from devtools.product_qualified_runtime import ProductQualifiedPoVAdapter


def _setup(tmp_path, *, wall_seconds=60):
    ledger = PersistentProcessLedgerV2.create(
        tmp_path / "physical.json", wall_total_seconds=wall_seconds,
        fuzz_total_seconds=0)
    point = SimpleNamespace(
        task_id="task-1", status=SPStatus.GENERATING_POV.value,
        sources=[{"harness_name": "fuzz", "sanitizer": "address"}])
    adapter = object.__new__(ProductQualifiedPoVAdapter)
    adapter.task_id = "task-1"
    adapter.run_id = "run-1"
    adapter.fuzzer = "fuzz"
    adapter.sanitizer = "address"
    adapter.repos = SimpleNamespace(suspicious_points=SimpleNamespace(
        find_by_id=lambda value: point if value == "sp-1" else None))
    adapter.ledger = ledger
    adapter.binding = QualifiedRuntimeBinding(
        object(), Mock(), adapter.generate)
    request = QualifiedGeneratorRequest(
        task_id="task-1", suspicious_point_id="sp-1",
        worker_id="pov-1", attempt=1,
        code="def generate(n): return b'x'", num_variants=3)
    return adapter, request, ledger


def test_generator_docker_is_reserved_before_launch_and_settled(tmp_path):
    adapter, request, ledger = _setup(tmp_path)
    calls = []

    def generator(code, count):
        calls.append((code, count))
        active = ledger.snapshot()["active"]
        assert len(active) == 1
        assert next(iter(active.values()))["kind"] == "AUX_PROCESS"
        return [b"x", b"y", b"z"]

    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(tmp_path / "binary", "0" * 64)), \
         patch("fuzzingbrain.fuzzer.seed_sandbox.execute_seed_generator",
               side_effect=generator):
        assert adapter.generate(request) == [b"x", b"y", b"z"]
    assert calls == [(request.code, 3)]
    state = ledger.snapshot()
    assert state["active"] == {}
    assert state["stop_status"] is None
    assert len(state["finished"]) == 1
    row = state["finished"][0]
    assert row["kind"] == "AUX_PROCESS"
    assert row["cleanup_complete"] is True
    assert row["output_limited"] is False
    assert row["overrun"] is False
    assert "task-1:sp-1:pov_generator:pov-1:1:" in row["key"]
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(tmp_path / "binary", "0" * 64)), \
         patch("fuzzingbrain.fuzzer.seed_sandbox.execute_seed_generator") as again:
        with pytest.raises(ValueError, match="reservation not eligible"):
            adapter.generate(request)
    again.assert_not_called()


def test_missing_image_pin_still_fails_without_host_fallback(
        tmp_path, monkeypatch):
    adapter, request, ledger = _setup(tmp_path)
    monkeypatch.delenv(IMAGE_ID_ENV, raising=False)
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(tmp_path / "binary", "0" * 64)):
        with pytest.raises(RuntimeError, match="pinned local image ID"):
            adapter.generate(request)
    state = ledger.snapshot()
    assert state["active"] == {}
    assert len(state["finished"]) == 1
    assert state["finished"][0]["cleanup_complete"] is True


@pytest.mark.parametrize("error,stop_status", [
    (SeedSandboxCleanupError("cleanup unconfirmed"),
     "STOPPED_CLEANUP_INCOMPLETE"),
    (SeedSandboxOutputLimitError("output exceeded byte limit"),
     "STOPPED_OUTPUT_LIMIT"),
])
def test_generator_failure_stops_account_when_physical_state_requires_it(
        tmp_path, error, stop_status):
    adapter, request, ledger = _setup(tmp_path)
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(tmp_path / "binary", "0" * 64)), \
         patch("fuzzingbrain.fuzzer.seed_sandbox.execute_seed_generator",
               side_effect=error):
        expected_error = (SeedSandboxCleanupError if
                          stop_status == "STOPPED_CLEANUP_INCOMPLETE" else
                          RuntimeError)
        with pytest.raises(expected_error):
            adapter.generate(request)
    state = ledger.snapshot()
    assert state["active"] == {}
    assert state["stop_status"] == stop_status
    assert state["finished"][0]["cleanup_complete"] is (
        stop_status != "STOPPED_CLEANUP_INCOMPLETE")


def test_generator_rejects_mismatched_identity_and_budget_before_launch(
        tmp_path):
    adapter, request, ledger = _setup(tmp_path, wall_seconds=20)
    with patch.object(QualifiedRuntimeBinding, "pinned_binary",
                      return_value=(tmp_path / "binary", "0" * 64)), \
         patch("fuzzingbrain.fuzzer.seed_sandbox.execute_seed_generator") as run:
        with pytest.raises(ValueError, match="identity changed"):
            adapter.generate(QualifiedGeneratorRequest(
                **{**request.__dict__, "task_id": "another-task"}))
        with pytest.raises(ValueError, match="exceeds a cap"):
            adapter.generate(request)
    run.assert_not_called()
    assert ledger.snapshot()["active"] == {}
    assert ledger.snapshot()["finished"] == []


def test_qualified_pov_tool_requires_accounted_generator_callback():
    context = {"qualified_runtime_required": True, "task_id": "task-1",
               "suspicious_point_id": "sp-1", "worker_id": "pov-1",
               "attempt": 1, "qualified_runtime_binding":
               QualifiedRuntimeBinding(object(), Mock())}
    with patch("fuzzingbrain.fuzzer.seed_sandbox.execute_seed_generator") as run:
        with pytest.raises(RuntimeError, match="process accounting unavailable"):
            _execute_generator_code(
                "def generate(n): return b'x'", 3, context=context)
    run.assert_not_called()
