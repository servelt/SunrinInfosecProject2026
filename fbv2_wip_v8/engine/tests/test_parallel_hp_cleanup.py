"""No-transport checks of owned HP provider shutdown."""

import asyncio
import threading
from types import SimpleNamespace

import pytest

from devtools.parallel_hp_analysis import (
    _close_hp_role_pipelines, _join_gate_handoff,
    _join_physical_handoff)


def test_cancelled_parallel_hp_waits_for_physical_settlement():
    async def run():
        entered = threading.Event()
        release = threading.Event()

        def handoff(_work, _row):
            entered.set()
            assert release.wait(2), "physical settlement was never released"
            return {"status": "SETTLED"}

        task = asyncio.create_task(_join_physical_handoff(handoff, None, {}))
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done(), "physical process was abandoned on cancellation"
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())


def test_cancelled_parallel_hp_waits_for_gate_replay_settlement():
    async def run():
        entered = threading.Event()
        release = threading.Event()

        def gate_handoff():
            entered.set()
            assert release.wait(2), "Gate replay was never released"
            return {"status": "SETTLED"}

        task = asyncio.create_task(_join_gate_handoff(gate_handoff))
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done(), "Gate process was abandoned on cancellation"
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())


def test_repeated_cancellation_waits_for_both_provider_closes():
    async def run():
        entered = asyncio.Event()
        release = asyncio.Event()
        closed = []

        async def first_close():
            entered.set()
            await release.wait()
            closed.append("first")

        async def second_close():
            closed.append("second")

        pipelines = tuple(SimpleNamespace(provider=SimpleNamespace(close=close))
                          for close in (first_close, second_close))
        task = asyncio.create_task(_close_hp_role_pipelines(pipelines))
        await asyncio.wait_for(entered.wait(), timeout=2)
        try:
            for _ in range(3):
                task.cancel()
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                assert not task.done(), "provider cleanup was abandoned"
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert closed == ["first", "second"]

    asyncio.run(run())


@pytest.mark.parametrize("error", [ValueError, asyncio.CancelledError])
def test_failed_close_still_attempts_remaining_provider(error):
    async def run():
        closed = []

        async def first_close():
            closed.append("first")
            raise error("synthetic close failure")

        async def second_close():
            closed.append("second")

        pipelines = tuple(SimpleNamespace(provider=SimpleNamespace(close=close))
                          for close in (first_close, second_close))
        if error is asyncio.CancelledError:
            with pytest.raises(asyncio.CancelledError):
                await _close_hp_role_pipelines(pipelines)
        else:
            assert await _close_hp_role_pipelines(pipelines) is True
        assert closed == ["first", "second"]

    asyncio.run(run())
