"""Regression coverage for App Server response-envelope forwarding."""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys
from typing import Any


PRODUCT_SRC = Path(__file__).resolve().parents[2] / "product_src"
sys.path.insert(0, str(PRODUCT_SRC))

from fuzzingbrain.llms.codex_tool_bridge import (  # noqa: E402
    isolated_codex_appserver_client_class,
    scoped_mcp_startup_client_class,
)
from devtools.original_hp_live_optin import _hp_client_type  # noqa: E402
from vulnerabilityanalysis.llm import CodexAppServerClient  # noqa: E402


class _ForwardingBase:
    PURE_STARTUP_NOTIFICATIONS = frozenset()
    STARTUP_NOTIFICATION_AUDIT_MAX_BYTES = 4096

    def __init__(self, **_kwargs: Any) -> None:
        self.forwarded = None

    async def _request(self, method: str, params: dict[str, Any], *,
                       response_envelope: Any = None) -> dict[str, Any]:
        self.forwarded = (method, params, response_envelope)
        return {"ok": True}

    @staticmethod
    def _has_embedded_item(_params: object) -> bool:
        return False


def test_isolated_client_forwards_response_envelope() -> None:
    client_type = isolated_codex_appserver_client_class(_ForwardingBase)
    client = client_type()
    envelope = object()
    result = asyncio.run(client._request(
        "turn/start", {"threadId": "thread"}, response_envelope=envelope))
    assert result == {"ok": True}
    assert client.forwarded == (
        "turn/start", {"threadId": "thread"}, envelope)
    assert client._fbv2_request_stage is None


def test_scoped_mcp_client_forwards_response_envelope() -> None:
    client_type = scoped_mcp_startup_client_class(_ForwardingBase)
    client = client_type(mcp_startup_server_name="server")
    envelope = object()
    result = asyncio.run(client._request(
        "turn/start", {"threadId": "thread"}, response_envelope=envelope))
    assert result == {"ok": True}
    assert client.forwarded == (
        "turn/start", {"threadId": "thread"}, envelope)
    assert client._fbv2_request_stage is None


def test_hp_client_forwards_response_envelope(monkeypatch, tmp_path) -> None:
    observed: list[tuple[str, dict[str, Any], object]] = []

    async def request(_self, method: str, params: dict[str, Any], *,
                      response_envelope=None):
        observed.append((method, params, response_envelope))
        return {"ok": True}

    monkeypatch.setattr(CodexAppServerClient, "_request", request)
    client_type = _hp_client_type(lambda: None)
    client = client_type(cwd=tmp_path, model="test-model")
    envelope = object()
    result = asyncio.run(client._request(
        "turn/start", {"threadId": "thread"}, response_envelope=envelope))
    assert result == {"ok": True}
    assert observed == [("turn/start", {"threadId": "thread"}, envelope)]
    assert client._fbv2_request_stage is None
