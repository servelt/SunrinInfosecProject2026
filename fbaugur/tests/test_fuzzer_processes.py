"""One global fuzzer at a time, and none outlives the pipeline that started it."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import fbaugur.fuzzing as fuzzing
from fbaugur.fuzzing import GlobalFuzzer
from fbaugur.store import Store

started: list["FakeProcess"] = []


class FakeProcess:
    """Spawning takes a while, like create_subprocess_exec; until then it is not running."""

    def __init__(self, spec):
        self.spec, self.process, self.stopped = spec, None, False
        started.append(self)

    @property
    def running(self):
        return self.process is not None and not self.stopped

    async def start(self):
        await asyncio.sleep(0.05)
        self.process = type("P", (), {"returncode": None})()

    async def stop(self, grace: float = 5.0):
        self.stopped = True
        if self.process is not None:
            self.process.returncode = -2


def test_a_swap_and_a_poll_never_leave_two_fuzzers(tmp_path: Path, monkeypatch):
    started.clear()
    monkeypatch.setattr(fuzzing, "FuzzerProcess", FakeProcess)
    fuzzer = GlobalFuzzer(Store(tmp_path / "state.db"), run_dir=tmp_path, worker="w", harness="h",
                          binary=tmp_path / "v0", seeds=[])

    async def scenario():
        await fuzzer.start()
        # The build lane swaps while the fuzzing lane polls, as they do in a run.
        await asyncio.gather(fuzzer.swap(tmp_path / "v1", []), fuzzer.poll(), fuzzer.poll(),
                             fuzzer.swap(tmp_path / "v2", []), fuzzer.poll())
        alive.append(sum(1 for p in started if not p.stopped))
        await fuzzer.stop()

    alive: list[int] = []
    asyncio.run(scenario())
    assert alive == [1]                                   # one fuzzer after the swaps and polls
    assert len(started) == 3 and all(p.stopped for p in started)     # nothing left running


def test_a_fuzzer_dies_with_the_process_that_started_it(tmp_path: Path):
    script = textwrap.dedent(f"""
        import asyncio, sys
        sys.path.insert(0, {str(Path(fuzzing.__file__).parents[1])!r})
        from fbaugur.fuzzing import _die_with_parent
        async def main():
            child = await asyncio.create_subprocess_exec("sleep", "60", start_new_session=True,
                                                         preexec_fn=_die_with_parent)
            print(child.pid, flush=True)
            await asyncio.sleep(60)
        asyncio.run(main())
    """)
    parent = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
    child = int(parent.stdout.readline())
    started = _start_time(child)                    # identifies this process; a pid can be reused
    assert started is not None
    parent.kill()
    parent.wait()
    deadline = time.time() + 10
    while time.time() < deadline:
        now = _start_time(child)
        if now != started or _state(child) in (None, "Z"):
            return                                  # gone (or its pid now names another process)
        time.sleep(0.05)
    if _start_time(child) == started:               # still the same process: clean it up, then fail
        os.kill(child, 9)
    raise AssertionError("the child outlived its parent")


def _stat(pid: int) -> list[str] | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    return text[text.rindex(")") + 2:].split()      # fields after the command name


def _start_time(pid: int) -> str | None:
    fields = _stat(pid)
    return fields[19] if fields else None           # field 22 of stat: start time


def _state(pid: int) -> str | None:
    fields = _stat(pid)
    return fields[0] if fields else None
