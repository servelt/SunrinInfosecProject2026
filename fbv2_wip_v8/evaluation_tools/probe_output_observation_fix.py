"""Future probe client fix; archived approved probe runner remains byte-identical."""
from assertion_schema_probe_runner import NoRetryProbeClient


class OutputAwareProbeClient(NoRetryProbeClient):
    async def _collect(self, thread_id: str, turn_id: str) -> str:
        for message in self._notifications:
            params = message.get("params") or {}
            if params.get("turnId") != turn_id:
                continue
            if message.get("method") == "item/agentMessage/delta" and params.get("delta"):
                self._visible_output = True
            elif message.get("method") == "item/completed":
                item = params.get("item") or {}
                if item.get("type") == "agentMessage" and item.get("text"):
                    self._visible_output = True
        return await super()._collect(thread_id, turn_id)
