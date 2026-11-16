from __future__ import annotations

import bisect
import collections
import shutil
import subprocess
from pathlib import Path

HOOK_SOURCE = Path(__file__).with_name("thread_trace_hook.c")

BUILD_HELP = (
    "Build the original program a second time with every function instrumented and the hook linked in, for "
    "example: CFLAGS='-O0 -g -finstrument-functions' LIBS='<hook.o>' ./configure && make. "
    "`harnesscreator thread-trace-hook <hook.o>` compiles the hook object."
)


def build_hook_object(output: Path, *, compiler: str | None = None) -> Path:
    compiler = compiler or shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        raise FileNotFoundError("no C compiler found to build the thread-trace hook")
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([compiler, "-c", "-O2", "-fPIC", "-o", str(output), str(HOOK_SOURCE)], check=True)
    return output


class SymbolTable:
    """Function symbols of a binary by link-time address (from ``nm``)."""

    def __init__(self, binary: Path):
        done = subprocess.run(["nm", "--defined-only", "-n", str(binary)], capture_output=True, text=True, check=False)
        self.addresses: list[int] = []
        self.names: list[str] = []
        for line in done.stdout.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] in "tTwW":
                self.addresses.append(int(parts[0], 16))
                self.names.append(parts[2])
        if not self.addresses:
            raise ValueError(f"nm found no function symbols in {binary} (stripped binary?)")

    def name(self, address: int) -> str | None:
        index = bisect.bisect_right(self.addresses, address) - 1
        if index < 0 or self.addresses[index] != address:
            return None  # __cyg_profile_func_enter reports function entry addresses exactly
        return self.names[index]


def read_trace(path: Path, symbols: SymbolTable) -> dict[int, set[str]]:
    """Thread index -> names of the functions that thread executed."""

    threads: dict[int, set[str]] = collections.defaultdict(set)
    if not path.is_file():
        return threads
    for line in path.read_text(encoding="ascii", errors="replace").splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        name = symbols.name(int(parts[1], 16))
        if name:
            threads[int(parts[0])].add(name)
    return threads


def request_functions(threads: dict[int, set[str]], entry_functions: set[str]) -> set[str]:
    """Functions executed by the thread(s) that executed an Entry function of the context.

    This is the request path as measured: code run by other threads (periodic
    maintenance, shutdown helpers) is left out.
    """

    selected: set[str] = set()
    for functions in threads.values():
        if functions & entry_functions:
            selected |= functions
    return selected
