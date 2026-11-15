from loguru import logger

from fuzzingbrain.agents.base import BaseAgent


class _LoggingAgent(BaseAgent):
    @property
    def system_prompt(self):
        return "test"

    def get_initial_message(self):
        return "test"


def test_legacy_agent_logs_are_unique_for_same_worker_and_second(tmp_path):
    """Concurrent SP agents must not truncate or interleave one another."""
    first = _LoggingAgent(worker_id="shared-worker", log_dir=tmp_path, index=1)
    second = _LoggingAgent(worker_id="shared-worker", log_dir=tmp_path, index=2)
    try:
        first._setup_logging_legacy()
        second._setup_logging_legacy()
        assert first._log_file != second._log_file
        assert "_1_" in first._log_file.name
        assert "_2_" in second._log_file.name
        assert first._log_file.exists()
        assert second._log_file.exists()
    finally:
        for agent in (first, second):
            if agent._log_sink_id is not None:
                logger.remove(agent._log_sink_id)
                agent._log_sink_id = None
