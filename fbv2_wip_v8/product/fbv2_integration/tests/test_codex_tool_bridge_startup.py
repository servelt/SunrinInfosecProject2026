"""Narrow compatibility check for CLI 0.166.0 MCP startup status."""

import asyncio
from copy import deepcopy
from pathlib import Path
import sys

import pytest

from fuzzingbrain.llms.codex_tool_bridge import scoped_mcp_startup_client_class


PRODUCT_SRC = Path(__file__).resolve().parents[2] / "vulnerabilityanalysis" / "src"
if not PRODUCT_SRC.is_dir():
    pytest.skip("product transport not available beside integration worktree",
                allow_module_level=True)
sys.path.insert(0, str(PRODUCT_SRC))
from vulnerabilityanalysis.llm import CodexAppServerClient  # noqa: E402


ScopedClient = scoped_mcp_startup_client_class(CodexAppServerClient)


def client(tmp_path):
    result = ScopedClient(cwd=tmp_path, model="test-model",
                          mcp_startup_server_name="ctf-autosolver")
    result._active_thread_id = "thread-1"
    result._fbv2_request_stage = "turn/start"
    return result


def status(**overrides):
    row = {"method": "mcpServer/startupStatus/updated", "params": {
        "threadId": "thread-1", "name": "ctf-autosolver",
        "status": "starting", "error": None, "failureReason": None}}
    row["params"].update(overrides)
    return row


def test_exact_startup_notice_passes_only_before_turn_and_in_queued_collect(tmp_path):
    transport = client(tmp_path)
    event = status()
    assert transport._unapproved_event_label(event) is None
    transport._fbv2_request_stage = None
    assert transport._unapproved_event_label(event) is None
    assert transport._unapproved_event_label(event) == "MCP_STARTUP_STATUS_UNAPPROVED"
    assert "mcpServer/startupStatus/updated" in transport.PURE_STARTUP_NOTIFICATIONS


@pytest.mark.parametrize("change", [
    {"name": "unapproved-server"}, {"threadId": "other-thread"},
    {"status": "ready"}, {"error": "failed"},
    {"failureReason": "failed"}, {"extra": "unexpected"},
])
def test_other_startup_status_shapes_remain_blocked(tmp_path, change):
    assert client(tmp_path)._unapproved_event_label(status(**change)) == (
        "MCP_STARTUP_STATUS_UNAPPROVED")


def test_repeated_status_and_server_request_remain_blocked(tmp_path):
    transport = client(tmp_path)
    first = status()
    assert transport._unapproved_event_label(first) is None
    assert transport._unapproved_event_label(deepcopy(first)) == (
        "MCP_STARTUP_STATUS_UNAPPROVED")
    request = status()
    request["id"] = 4
    assert client(tmp_path)._unapproved_event_label(request) == (
        "MCP_STARTUP_STATUS_UNAPPROVED")


def test_actual_tool_event_is_still_forbidden(tmp_path):
    transport = client(tmp_path)
    event = {"method": "item/completed", "params": {
        "threadId": "thread-1", "turnId": "turn-1", "item": {
            "type": "functionCall", "name": "write_file"}}}
    assert transport._unapproved_event_label(event) is not None


def test_startup_notice_outside_turn_start_is_blocked(tmp_path):
    transport = client(tmp_path)
    transport._fbv2_request_stage = "thread/start"
    assert transport._unapproved_event_label(status()) == (
        "MCP_STARTUP_STATUS_UNAPPROVED")


def test_product_request_queue_and_collect_consume_exact_status_once(tmp_path):
    transport = client(tmp_path)
    transport._fbv2_request_stage = None
    events = iter([
        status(),
        {"id": 1, "result": {"turn": {"id": "turn-1"}}},
        {"method": "item/completed", "params": {
            "threadId": "thread-1", "turnId": "turn-1",
            "item": {"type": "agentMessage", "text": "{}"}}},
        {"method": "turn/completed", "params": {
            "threadId": "thread-1", "turn": {"id": "turn-1",
                                               "status": "completed"}}},
    ])

    async def send(_message):
        pass

    async def read():
        return next(events)

    transport._send = send
    transport._read = read
    transport._record_server_event = lambda _message: None

    async def run():
        response = await transport._request("turn/start", {"threadId": "thread-1"})
        assert response == {"turn": {"id": "turn-1"}}
        assert len(transport._notifications) == 1
        return await transport._collect("thread-1", "turn-1")

    assert asyncio.run(run()) == "{}"
    assert not transport._fbv2_pending_startup
