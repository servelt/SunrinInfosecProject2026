"""Provider-free proof that development adapters preserve one turn envelope."""
import asyncio
import pytest
from vulnerabilityanalysis.llm import CodexAppServerClient
from dev_global_appserver_bridge import DevelopmentGlobalAppServer
from blind3_hp_iteration_live_dev import LiveHPAppServer


@pytest.mark.parametrize("client_type", [DevelopmentGlobalAppServer, LiveHPAppServer])
def test_request_preserves_response_envelope(monkeypatch, client_type):
    envelope = object()
    seen = []

    async def wire(self, method, params, *, response_envelope=None):
        seen.append((method, params, response_envelope))
        return {"ok": True}

    monkeypatch.setattr(CodexAppServerClient, "_request", wire)
    client = object.__new__(client_type)
    assert asyncio.run(client._request("ping", {}, response_envelope=envelope)) == {"ok": True}
    assert seen == [("ping", {}, envelope)]


def test_collect_preserves_same_deadline_and_response_envelope(monkeypatch):
    envelope = object()
    seen = []

    async def collect(self, thread_id, turn_id, **kwargs):
        seen.append((thread_id, turn_id, kwargs))
        return "{}"

    monkeypatch.setattr(CodexAppServerClient, "_collect", collect)
    client = object.__new__(DevelopmentGlobalAppServer)
    client._notifications = []
    assert asyncio.run(client._collect("thread", "turn", response_envelope=envelope)) == "{}"
    assert seen == [("thread", "turn", {"deadline": None,
                    "response_limit_bytes": None, "response_envelope": envelope})]
