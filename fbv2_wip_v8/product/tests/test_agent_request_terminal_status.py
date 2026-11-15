"""A physical request must not be logged as completed after an abrupt stop."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from vulnerabilityanalysis.agents import AgentPipeline  # noqa: E402


class BudgetStop(BaseException):
    pass


class Provider:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error

    async def generate(self, request):
        if self.error is not None:
            raise self.error
        return self.result


class AgentRequestTerminalStatusTests(unittest.TestCase):
    def _record(self, provider):
        with tempfile.TemporaryDirectory() as temp:
            pipeline = AgentPipeline(provider, schema_error_dir=Path(temp))
            try:
                asyncio.run(pipeline._ask("function_analysis", {}, {"type": "object"}))
            except BaseException as exc:
                raised = type(exc)
            else:
                raised = None
            rows = [json.loads(line) for line in
                    (Path(temp) / "agent_requests.jsonl").read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            return raised, rows[0]

    def test_abrupt_budget_stop_is_incomplete(self):
        raised, row = self._record(Provider(error=BudgetStop()))
        self.assertIs(raised, BudgetStop)
        self.assertEqual(row["status"], "INCOMPLETE")
        self.assertIsNone(row["response_artifact"])

    def test_normal_exception_is_error(self):
        raised, row = self._record(Provider(error=RuntimeError("provider failed")))
        self.assertIs(raised, RuntimeError)
        self.assertEqual(row["status"], "ERROR")

    def test_validated_response_is_completed(self):
        raised, row = self._record(Provider(result={}))
        self.assertIsNone(raised)
        self.assertEqual(row["status"], "COMPLETED")
        self.assertIsNotNone(row["response_artifact"])


if __name__ == "__main__":
    unittest.main()
