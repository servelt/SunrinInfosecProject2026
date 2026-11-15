import asyncio
from pathlib import Path
import unittest

from probe_output_observation_fix import OutputAwareProbeClient


class ProbeOutputObservationTests(unittest.TestCase):
    def test_queued_visible_text_is_not_mistaken_for_empty_output(self):
        client = OutputAwareProbeClient(route_hash="0" * 64, cwd=Path.cwd())
        client._notifications.extend([
            {"method": "item/agentMessage/delta", "params": {
                "turnId": "v", "itemId": "i", "delta": "visible model text"}},
            {"method": "turn/completed", "params": {
                "threadId": "t", "turn": {"id": "v", "status": "completed"}}},
        ])
        self.assertEqual(asyncio.run(client._collect("t", "v")), "visible model text")
        self.assertTrue(client._visible_output)
