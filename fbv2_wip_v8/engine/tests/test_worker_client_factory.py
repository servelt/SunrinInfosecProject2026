"""The original WorkerExecutor passes an opt-in client factory to Fullscan."""

from unittest.mock import MagicMock, patch

from fuzzingbrain.worker.executor import WorkerExecutor
from fuzzingbrain.worker.strategies.pov_fullscan import POVFullscanStrategy


def test_worker_executor_passes_process_local_factory_to_original_fullscan(tmp_path):
    factory = lambda role, owner: None
    executor = WorkerExecutor(
        workspace_path=str(tmp_path / "worker"), project_name="fixture",
        fuzzer="fixture_fuzzer", sanitizer="address", task_type="pov",
        repos=MagicMock(), task_id="task-id", scan_mode="full",
        enable_fuzzer_worker=False, llm_client_factory=factory,
    )
    with patch.object(POVFullscanStrategy, "_setup_tool_contexts"):
        strategy = executor._get_strategy()
    assert isinstance(strategy, POVFullscanStrategy)
    assert strategy.llm_client_factory is factory


def test_worker_executor_keeps_original_default_client_construction(tmp_path):
    executor = WorkerExecutor(
        workspace_path=str(tmp_path / "worker"), project_name="fixture",
        fuzzer="fixture_fuzzer", sanitizer="address", task_type="pov",
        repos=MagicMock(), task_id="task-id", scan_mode="full",
        enable_fuzzer_worker=False,
    )
    with patch.object(POVFullscanStrategy, "_setup_tool_contexts"):
        strategy = executor._get_strategy()
    assert strategy.llm_client_factory is None
