"""Public development must not start the original unaccounted SP dedup LLM."""

import asyncio
from types import SimpleNamespace

from bson import ObjectId
import pytest

from fuzzingbrain.analyzer.server import AnalysisServer
from fuzzingbrain.core import sp_dedup


class _SPRepo:
    def __init__(self):
        self.rows = []

    def find_by_function(self, task_id, function_name):
        return [row for row in self.rows
                if str(row.task_id) == str(task_id) and
                row.function_name == function_name]

    def save(self, row):
        self.rows.append(row)
        return True


@pytest.mark.parametrize("allow_llm_sp_dedup", [False, True])
def test_second_sp_uses_original_dedup_only_when_explicitly_allowed(
        tmp_path, monkeypatch, allow_llm_sp_dedup):
    checked = []

    async def check_duplicate(description, existing):
        checked.append((description, len(existing)))
        return None

    monkeypatch.setattr(sp_dedup, "check_sp_duplicate_async", check_duplicate)
    server = AnalysisServer(
        task_id=str(ObjectId()), task_path=str(tmp_path),
        project_name="fixture", sanitizers=["address"],
        allow_llm_sp_dedup=allow_llm_sp_dedup)
    repo = _SPRepo()
    server.repos = SimpleNamespace(suspicious_points=repo)
    params = {"function_name": "md_lookup_line", "harness_name": "fuzz-mdhtml",
              "sanitizer": "address", "description": "first distinct hypothesis",
              "vuln_type": "out-of-bounds access", "score": 0.9}
    try:
        first = asyncio.run(server._create_suspicious_point(params))
        second = asyncio.run(server._create_suspicious_point(
            {**params, "description": "second distinct hypothesis"}))
    finally:
        server._executor.shutdown(wait=True)
    assert first["created"] is True and second["created"] is True
    assert first["id"] != second["id"]
    assert len(repo.rows) == 2
    assert checked == ([('second distinct hypothesis', 1)]
                       if allow_llm_sp_dedup else [])


def test_original_analyzer_defaults_to_semantic_dedup(tmp_path):
    server = AnalysisServer(task_id=str(ObjectId()), task_path=str(tmp_path),
                            project_name="fixture", sanitizers=["address"])
    try:
        assert server.allow_llm_sp_dedup is True
    finally:
        server._executor.shutdown(wait=True)
