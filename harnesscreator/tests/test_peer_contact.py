"""A peer_stream seed counts only when the program connected to the peer and got its bytes."""

import asyncio
import collections
from pathlib import Path

from harnesscreator.contexts.execution import RunObservation
from harnesscreator.contexts.model import Seed
from harnesscreator.contexts.workflow import SeedWorkflow


def _workflow(tmp_path: Path, observation: RunObservation) -> SeedWorkflow:
    flow = object.__new__(SeedWorkflow)
    flow.delivery, flow.peer_trigger, flow.results, flow.counts = "peer_stream", None, {}, collections.Counter()
    flow.covered_functions, flow.covered_lines = set(), set()
    flow.baseline_functions, flow.baseline_lines = set(), set()
    flow.out, flow.key, flow.context_id, flow.context = tmp_path, "ctx-p-peer_stream", "ctx-p", {}
    flow.emit = lambda message: None
    flow.accepted = {}
    flow._name = lambda fid: fid
    (tmp_path / "corpus" / "ctx-p").mkdir(parents=True, exist_ok=True)

    async def execute(messages, paced=True):
        # The trigger alone made the program's own front end run a new function.
        return observation, {"fn-line-reader"}, {("fn-line-reader", 10)}, ""

    flow._execute = execute
    return flow


def _seed() -> Seed:
    return Seed(seed_id="s1", context_id="ctx-p", delivery="peer_stream",
                messages_hex=[b"QUERY".hex(), (b"\x00" * 13).hex()], origin="generator")


def test_coverage_from_the_trigger_alone_is_not_a_peer_seed(tmp_path: Path):
    no_contact = RunObservation(error="RuntimeError: the program did not connect to the peer listener",
                                peer_contact=False)
    result = asyncio.run(_workflow(tmp_path, no_contact).verify(_seed()))
    assert result.status == "REJECTED_NO_PEER_CONTACT"


def test_a_seed_whose_peer_bytes_were_delivered_is_accepted(tmp_path: Path):
    contact = RunObservation(responses=[b""], peer_contact=True)
    result = asyncio.run(_workflow(tmp_path, contact).verify(_seed()))
    assert result.status == "ACCEPTED_NEW"
