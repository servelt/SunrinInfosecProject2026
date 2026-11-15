"""The bridge disables Codex-managed MCP servers without weakening event checks."""

import asyncio
from copy import deepcopy
from pathlib import Path
import sys

import pytest

from fuzzingbrain.llms.codex_tool_bridge import (
    CodexBridgeProtocolError, isolated_codex_appserver_client_class,
    product_codex_bridge,
)


PRODUCT_SRC = Path(__file__).resolve().parents[2] / "vulnerabilityanalysis" / "src"
if not PRODUCT_SRC.is_dir():
    pytest.skip("product transport not available beside integration worktree",
                allow_module_level=True)
sys.path.insert(0, str(PRODUCT_SRC))
from vulnerabilityanalysis.llm import CodexAppServerClient  # noqa: E402


def test_isolated_client_forces_process_local_mcp_disable(tmp_path, monkeypatch):
    client_type = isolated_codex_appserver_client_class(CodexAppServerClient)
    client = client_type(cwd=tmp_path, model="test-model")
    launches = []
    pinned = []

    class Process:
        returncode = 0

        async def communicate(self):
            return b"Logged in using ChatGPT", b""

    async def launch(*argv, **kwargs):
        launches.append((argv, kwargs))
        return Process()

    async def request(method, params):
        assert method == "initialize"
        return {}

    async def send(message):
        assert message == {"method": "initialized"}

    async def drain():
        pass

    monkeypatch.setattr("fuzzingbrain.llms.codex_tool_bridge.shutil.which",
                        lambda _name: "/usr/local/bin/codex")
    monkeypatch.setattr("fuzzingbrain.llms.codex_tool_bridge.asyncio.create_subprocess_exec",
                        launch)
    client._verify_executable_identity = pinned.append
    client._request = request
    client._send = send
    client._drain_stderr = drain

    asyncio.run(client.start())
    assert len(launches) == 2
    assert launches[0][0] == ("/usr/local/bin/codex", "login", "status")
    assert launches[1][0] == (
        "/usr/local/bin/codex", "app-server", "-c", "features.plugins=false",
        "-c", "features.apps=false", "--stdio")
    assert pinned == ["/usr/local/bin/codex"] * 2
    assert client.PURE_STARTUP_NOTIFICATIONS == (
        CodexAppServerClient.PURE_STARTUP_NOTIFICATIONS)


def test_factory_defaults_to_isolated_transport(tmp_path):
    bridge = product_codex_bridge(cwd=tmp_path, codex_model="gpt-5.6-luna",
                                  role="direction", max_calls=1)
    assert type(bridge.provider) is not CodexAppServerClient
    assert bridge.provider.PURE_STARTUP_NOTIFICATIONS == (
        CodexAppServerClient.PURE_STARTUP_NOTIFICATIONS)


def test_isolation_and_startup_exception_cannot_be_combined(tmp_path):
    with pytest.raises(ValueError, match="exclusive"):
        product_codex_bridge(cwd=tmp_path, codex_model="gpt-5.6-luna",
                             role="direction", max_calls=1,
                             mcp_startup_server_name="ctf-autosolver")


def settings_event(tmp_path):
    return {"method": "thread/settings/updated", "params": {
        "threadId": "thread-1", "threadSettings": {
            "activePermissionProfile": None,
            "approvalPolicy": "never",
            "approvalsReviewer": "user",
            "collaborationMode": {"mode": "default", "settings": {
                "developer_instructions": None, "model": "gpt-5.6-luna",
                "reasoning_effort": "low"}},
            "cwd": str(tmp_path), "disabledPluginIds": [],
            "effort": "low", "model": "gpt-5.6-luna",
            "modelProvider": "openai",
            "multiAgentMode": "explicitRequestOnly", "personality": None,
            "sandboxPolicy": {"networkAccess": False, "type": "readOnly"},
            "serviceTier": "default", "summary": None,
        },
    }}


def active_isolated_client(tmp_path):
    client_type = isolated_codex_appserver_client_class(CodexAppServerClient)
    client = client_type(cwd=tmp_path, model="gpt-5.6-luna")
    client._active_thread_id = "thread-1"
    client._active_model_effort = ("gpt-5.6-luna", "low")
    client._fbv2_request_stage = "turn/start"
    return client


def test_exact_settings_notice_passes_once_through_queue(tmp_path):
    client = active_isolated_client(tmp_path)
    event = settings_event(tmp_path)
    assert client._unapproved_event_label(event) is None
    client._fbv2_request_stage = None
    assert client._unapproved_event_label(event) is None
    assert client._unapproved_event_label(deepcopy(event)) == (
        "FBV2_THREAD_SETTINGS_UNAPPROVED")
    assert client.PURE_STARTUP_NOTIFICATIONS == (
        CodexAppServerClient.PURE_STARTUP_NOTIFICATIONS)


@pytest.mark.parametrize("field,value", [
    ("approvalPolicy", "on-request"),
    ("cwd", "/other"),
    ("disabledPluginIds", ["plug"]),
    ("effort", "high"),
    ("model", "other"),
    ("modelProvider", "other"),
    ("sandboxPolicy", {"networkAccess": True, "type": "readOnly"}),
    ("serviceTier", None),
])
def test_other_settings_remain_blocked(tmp_path, field, value):
    client = active_isolated_client(tmp_path)
    event = settings_event(tmp_path)
    event["params"]["threadSettings"][field] = value
    assert client._unapproved_event_label(event) == (
        "FBV2_THREAD_SETTINGS_UNAPPROVED")


def test_settings_wrong_thread_stage_or_server_request_blocked(tmp_path):
    event = settings_event(tmp_path)
    client = active_isolated_client(tmp_path)
    client._fbv2_request_stage = "thread/start"
    assert client._unapproved_event_label(event) == (
        "FBV2_THREAD_SETTINGS_UNAPPROVED")
    client._fbv2_request_stage = "turn/start"
    event["params"]["threadId"] = "thread-2"
    assert client._unapproved_event_label(event) == (
        "FBV2_THREAD_SETTINGS_UNAPPROVED")
    event["params"]["threadId"] = "thread-1"
    event["id"] = 3
    assert client._unapproved_event_label(event) == (
        "FBV2_THREAD_SETTINGS_UNAPPROVED")


def test_settings_notice_survives_product_request_and_collect(tmp_path):
    client = active_isolated_client(tmp_path)
    client._fbv2_request_stage = None
    events = iter([
        settings_event(tmp_path),
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

    client._send = send
    client._read = read
    client._record_server_event = lambda _message: None

    async def run():
        response = await client._request("turn/start", {"threadId": "thread-1"})
        assert response == {"turn": {"id": "turn-1"}}
        return await client._collect("thread-1", "turn-1")

    assert asyncio.run(run()) == "{}"
    assert not client._fbv2_pending_settings


def test_isolated_thread_instructions_distinguish_host_proposals_from_codex_tools(
        tmp_path, monkeypatch):
    client = active_isolated_client(tmp_path)
    captured = {}

    async def parent_request(_self, method, params):
        captured.update(params)
        return {}

    monkeypatch.setattr(CodexAppServerClient, "_request", parent_request)
    params = {
        "cwd": str(tmp_path), "ephemeral": True,
        "approvalPolicy": "never", "sandbox": "read-only",
        "dynamicTools": [],
        "baseInstructions": (
            "Analyze only supplied local source and artifacts. Do not call tools, "
            "browse, modify files, or invent evidence. Return strict JSON."),
        "developerInstructions": (
            "Unknown is not safe. Source and runtime evidence outrank guesses."),
    }
    asyncio.run(client._request("thread/start", params))
    assert "Do not invoke Codex tools" in captured["baseInstructions"]
    assert "host MCP tool proposal in JSON is data" in captured["baseInstructions"]
    assert "propose an advertised read-only host MCP tool" in (
        captured["developerInstructions"])
    assert captured["dynamicTools"] == []
    assert captured["sandbox"] == "read-only"
    assert captured["approvalPolicy"] == "never"
    assert params["baseInstructions"].startswith("Analyze only supplied")

    with pytest.raises(CodexBridgeProtocolError):
        asyncio.run(client._request("thread/start", {**params,
                                                     "dynamicTools": ["bad"]}))
