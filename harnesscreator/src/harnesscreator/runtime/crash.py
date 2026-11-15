from __future__ import annotations

import hashlib
import re
import signal
from pathlib import Path

from ..models import CrashSignature


_RUNTIME_FRAME_TOKENS = (
    "libfuzzer",
    "fuzzer::",
    "__sanitizer",
    "__asan",
    "__ubsan",
    "__msan",
    "__tsan",
    "libc_start",
    "start_thread",
    "clone",
    "raise",
    "abort",
)


def extract_crash_signature(
    output: str,
    returncode: int | None = None,
) -> CrashSignature | None:
    """Extract a comparison-safe signature from sanitizer/GDB diagnostics.

    Addresses, container prefixes and harness-runtime frames are intentionally
    removed.  A signature without a bug class or signal is not evidence of a
    crash and is returned as ``None``.
    """

    family = ""
    bug_class = ""
    if "AddressSanitizer" in output:
        family = "AddressSanitizer"
        match = re.search(r"ERROR:\s*AddressSanitizer:\s*([^\s]+)", output)
        if match:
            bug_class = match.group(1).casefold()
    elif "MemorySanitizer" in output:
        family = "MemorySanitizer"
        match = re.search(r"WARNING:\s*MemorySanitizer:\s*([^\n]+)", output)
        bug_class = _slug(match.group(1)) if match else "memory-error"
    elif "ThreadSanitizer" in output:
        family = "ThreadSanitizer"
        match = re.search(r"WARNING:\s*ThreadSanitizer:\s*([^\n]+)", output)
        bug_class = _slug(match.group(1)) if match else "data-race"
    elif "UndefinedBehaviorSanitizer" in output or "runtime error:" in output:
        family = "UndefinedBehaviorSanitizer"
        match = re.search(r"runtime error:\s*([^\n]+)", output)
        bug_class = _slug(match.group(1)) if match else "undefined-behavior"

    signal_name = ""
    match = re.search(r"(?:Program received signal|terminated with signal)\s+(SIG[A-Z0-9]+)", output)
    if match:
        signal_name = match.group(1)
    elif re.search(r"\bSegmentation fault\b", output, re.IGNORECASE):
        signal_name = "SIGSEGV"
    elif returncode is not None and returncode < 0:
        try:
            signal_name = signal.Signals(-returncode).name
        except (ValueError, OSError):
            signal_name = f"SIGNAL_{-returncode}"

    if not family and signal_name:
        family = "signal"
    if not bug_class and signal_name:
        bug_class = signal_name.casefold()
    if not family or not bug_class:
        return None

    frames = _normalized_frames(output)
    canonical = "\x1f".join((family, bug_class, signal_name, *frames))
    return CrashSignature(
        sanitizer_family=family,
        bug_class=bug_class,
        signal=signal_name,
        normalized_frames=frames,
        digest=hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20],
    )


def crash_signatures_match(
    expected: CrashSignature | None,
    observed: CrashSignature | None,
) -> bool:
    """Require the same sanitizer fault class and primary target fault frame.

    Signal-only failures have no stable target identity and therefore fail
    closed.  This prevents an unrelated abort in the original program from
    laundering a harness crash into a target finding.
    """

    if expected is None or observed is None:
        return False
    if (
        expected.sanitizer_family != observed.sanitizer_family
        or expected.bug_class != observed.bug_class
    ):
        return False
    # The first non-runtime frame is the normalized fault location. A shared
    # dispatch caller is not evidence that two different failing sinks have
    # the same root cause. Require this primary frame to match, including its
    # file and line when symbolization provides them.
    if not expected.normalized_frames or not observed.normalized_frames:
        return False
    return expected.normalized_frames[0] == observed.normalized_frames[0]


def _normalized_frames(output: str) -> list[str]:
    result: list[str] = []
    patterns = (
        re.compile(
            r"^\s*#\d+\s+(?:0x[0-9a-fA-F]+\s+)?(?:in\s+)?"
            r"(?P<function>[^\s(]+).*?(?P<file>(?:[A-Za-z]:)?[/\\][^\s:]+|[^\s:]+\.(?:c|cc|cpp|cxx|h|hpp)):(?P<line>\d+)"
        ),
        re.compile(
            r"^\s*#\d+\s+(?:0x[0-9a-fA-F]+\s+)?(?:in\s+)?"
            r"(?P<function>[A-Za-z_~][A-Za-z0-9_:~.]*)"
        ),
    )
    for raw in output.splitlines():
        match = next((pattern.search(raw) for pattern in patterns if pattern.search(raw)), None)
        if match is None:
            continue
        function = match.groupdict().get("function", "").strip()
        if not function or any(token in function.casefold() for token in _RUNTIME_FRAME_TOKENS):
            continue
        file_value = match.groupdict().get("file", "")
        line = match.groupdict().get("line", "")
        frame = function
        if file_value:
            normalized_file = file_value.replace(chr(92), "/")
            frame += f"@{Path(normalized_file).name}"
            if line:
                frame += f":{line}"
        if frame not in result:
            result.append(frame)
        if len(result) >= 12:
            break
    return result


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")[:120]
