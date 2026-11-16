"""The pipeline's end time, changeable while it runs.

The pipeline writes the end of its whole budget (epoch seconds) to RUN_ROOT/deadline.  The web
console rewrites the file when the user changes the time limit of a running scan; stage 1, each
stage-2 scan and the fuzzing after the agents read it again, so a longer or shorter limit takes
effect without a restart.
"""

from __future__ import annotations

import time
from pathlib import Path

_cache: dict[str, tuple[float, float]] = {}


def write(path: Path, when: float) -> None:
    path = Path(path)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(f"{when:.0f}\n", encoding="utf-8")
    tmp.replace(path)
    _cache.pop(str(path), None)


def read(path: Path | str | None, default: float) -> float:
    """The current end time; re-read at most every 10 s; `default` when there is no file."""
    if not path:
        return default
    key = str(path)
    now = time.time()
    cached = _cache.get(key)
    if cached and now - cached[0] < 10:
        return cached[1]
    try:
        value = float(Path(path).read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError, IndexError):
        value = default
    _cache[key] = (now, value)
    return value
