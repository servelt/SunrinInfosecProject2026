"""Run a harness binary on one input, isolated in its own network namespace.

Every harness starts the original daemon on a fixed loopback port, so concurrent
runs (global fuzzer, SP fuzzers, PoV checks, triage replays) would collide.
`unshare -n` gives each process a private loopback interface.
"""

from __future__ import annotations

import dataclasses
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

NETNS = ["unshare", "-n", "sh", "-c", 'ip link set lo up && exec "$0" "$@"']

_ERROR = re.compile(r"==\d+==ERROR: (AddressSanitizer|LeakSanitizer|libFuzzer|UndefinedBehaviorSanitizer): ?([^\n]*)")
_FRAME = re.compile(r"^\s*#(\d+) 0x[0-9a-fA-F]+ in (\S+)(?: (\S+?):(\d+)(?::\d+)?)?\s*$", re.M)
_UBSAN = re.compile(r"^(\S+?):(\d+):\d+: runtime error: (.*)$", re.M)
# An unsymbolized frame: ASan prints `#3 0x52bbce (/path/to/binary+0x52bbce) (BuildId: ...)`
# when it has no working llvm-symbolizer.  Without resolving these, every crash in the program
# itself gets a signature made only of the libc frames ASan could name, so unrelated bugs share
# the signature `start_thread:442 | __clone3:81` and are filed as duplicates of each other.
_FRAME_RAW = re.compile(r"^\s*#(\d+) 0x[0-9a-fA-F]+ +\((/\S+?)\+0x([0-9a-fA-F]+)\)", re.M)
_VIOLATION = re.compile(r"FBA_PHI_VIOLATION:(\d+)")
_REACHED = re.compile(r"FBA_PHI_REACHED:(\d+)")
_COVERED = re.compile(r"^COVERED_FUNC: hits: \d+ edges: \d+/\d+ (\S+)", re.M)
_TYPE = re.compile(r"(heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|heap-use-after-free|"
                   r"stack-use-after-return|stack-use-after-scope|double-free|attempting free on address|"
                   r"SEGV on unknown address|stack-overflow|negative-size-param|memcpy-param-overlap|"
                   r"alloc-dealloc-mismatch|deadly signal|out-of-memory|timeout)")


_SYMBOL_CACHE: dict[tuple[str, int], tuple[str, str | None, int | None]] = {}


def symbolize(binary: str, offset: int) -> tuple[str, str | None, int | None]:
    """(function, file, line) for one address, via addr2line; ('', None, None) if unknown.

    ASan needs llvm-symbolizer and cannot drive addr2line, so when llvm-symbolizer is absent
    the frames arrive as binary+offset and this fills them in afterwards.  Measured on the
    LightFTP run: without this the real stack (strcat / writelogentry / ftp_client_thread)
    never reached the crash signature.
    """
    key = (binary, offset)
    if key in _SYMBOL_CACHE:
        return _SYMBOL_CACHE[key]
    answer: tuple[str, str | None, int | None] = ("", None, None)
    tool = shutil.which("addr2line")
    if tool and Path(binary).is_file():
        try:
            proc = subprocess.run([tool, "-f", "-C", "-e", binary, hex(offset)],
                                  capture_output=True, text=True, timeout=20)
            lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            # addr2line writes DWARF warnings to stderr, so stdout is the pair we want:
            # the function name, then `file:line` (either may be `??`).
            if lines:
                name = lines[0] if lines[0] != "??" else ""
                where = lines[1] if len(lines) > 1 else ""
                path, _, number = where.rpartition(":")
                answer = (name, path or None if path not in ("", "??") else None,
                          int(number) if number.split(" ")[0].isdigit() else None)
        except (OSError, subprocess.SubprocessError, ValueError):
            answer = ("", None, None)
    _SYMBOL_CACHE[key] = answer
    return answer


def sanitizer_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:allocator_may_return_null=1:symbolize=1:handle_abort=1"
    # The combined ASan+UBSan build reports UB but keeps running (HarnessCreator recorded
    # misaligned-access reports on normal memcached inputs); crashes come from ASan and signals.
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=0"
    # Only llvm-symbolizer speaks the protocol the sanitizers use; pointing them at addr2line
    # only produces "invalid path to external symbolizer".  When it is missing the frames come
    # back as binary+offset and `symbolize()` resolves them after the fact.
    symbolizer = shutil.which("llvm-symbolizer")
    if symbolizer:
        env["ASAN_SYMBOLIZER_PATH"] = symbolizer
    env.pop("FBA_PHI_CONTINUE", None)
    env.pop("FBA_PHI_TRACE", None)
    if extra:
        env.update(extra)
    return env


@dataclasses.dataclass
class RunResult:
    returncode: int | None
    timed_out: bool
    crashed: bool
    kind: str | None              # AddressSanitizer / libFuzzer / ... or None
    crash_type: str | None
    frames: list[dict[str, Any]]
    ubsan: list[dict[str, Any]]
    violations: list[int]
    reached: list[int]
    stderr_tail: str
    # Reach markers in the order they were printed (trace mode only).  The last one names the
    # assertion that was being evaluated when the process died, which is the only attribution
    # available for a fault inside an assertion that carries no line information.
    reach_order: list[int] = dataclasses.field(default_factory=list)

    def summary(self, limit: int = 6) -> str:
        if self.timed_out:
            return "timeout"
        if self.violations and not self.crashed:
            return f"invariant violation {self.violations}"
        if not self.crashed:
            return "no crash (exit %s)" % self.returncode
        top = ", ".join(f"{f['function']} {f.get('file') or ''}:{f.get('line') or ''}" for f in self.frames[:limit])
        return f"{self.kind}: {self.crash_type} | {top}"


def parse_report(stderr: str, returncode: int | None, timed_out: bool) -> RunResult:
    error = _ERROR.search(stderr)
    frames: list[dict[str, Any]] = []
    if error:
        # One pass over both frame shapes so the stack keeps its order: a report may mix
        # symbolized libc frames with unsymbolized frames of the program's own binary.
        matches = sorted([(m.start(), "named", m) for m in _FRAME.finditer(stderr, error.end())] +
                         [(m.start(), "raw", m) for m in _FRAME_RAW.finditer(stderr, error.end())])
        for _, shape, match in matches:
            index = int(match.group(1))
            if frames and index == 0:
                break   # second stack (allocation / free site) follows
            if shape == "named":
                frames.append({"index": index, "function": match.group(2), "file": match.group(3),
                               "line": int(match.group(4)) if match.group(4) else None})
                continue
            name, path, line = symbolize(match.group(2), int(match.group(3), 16))
            frames.append({"index": index, "function": name or f"{Path(match.group(2)).name}+0x{match.group(3)}",
                           "file": path, "line": line})
    kind = error.group(1) if error else None
    detail = error.group(2) if error else ""
    type_match = _TYPE.search(detail) or (_TYPE.search(stderr) if error else None)
    crash_type = type_match.group(1) if type_match else (detail.split(" ")[0] if detail else None)
    violations = sorted({int(v) for v in _VIOLATION.findall(stderr)})
    # fba_phi_violate calls abort(), which the sanitizer reports as ABRT / "deadly signal".
    # That abort is the invariant signal, not a program crash; any other fault in the same
    # run (SEGV, buffer overflow, ...) is still a crash even when an invariant was violated.
    own_abort = bool(violations) and (crash_type in ("ABRT", "deadly signal")
                                      or any(f["function"] == "fba_phi_violate" for f in frames))
    crashed = bool(error) and kind != "LeakSanitizer" and not own_abort
    if timed_out:
        crashed = False
    order = [int(v) for v in _REACHED.findall(stderr)]
    return RunResult(returncode, timed_out, crashed, kind, crash_type, frames,
                     [{"file": f, "line": int(l), "message": m.strip()} for f, l, m in _UBSAN.findall(stderr)][:20],
                     violations, sorted(set(order)), stderr[-6000:], order)


def run_input(binary: Path, data: bytes, *, timeout: int = 10, env_extra: dict[str, str] | None = None,
              workdir: Path | None = None) -> RunResult:
    with tempfile.TemporaryDirectory(dir=str(workdir) if workdir else None) as tmp:
        path = Path(tmp) / "input"
        path.write_bytes(data)
        argv = [*NETNS, str(binary), f"-timeout={timeout}", "-rss_limit_mb=4096", str(path)]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout + 30, cwd=tmp,
                                  env=sanitizer_env(env_extra))
            stderr = proc.stderr.decode("utf-8", errors="replace")
            timed_out = "ALARM: working on the last Unit" in stderr or "ERROR: libFuzzer: timeout" in stderr
            return parse_report(stderr, proc.returncode, timed_out)
        except subprocess.TimeoutExpired as exc:
            stderr = (exc.stderr or b"").decode("utf-8", errors="replace")
            return parse_report(stderr, None, True)


def covered_functions(binary: Path, data: bytes, *, timeout: int = 10) -> list[str]:
    """Functions the input executes (libFuzzer -print_coverage on a one-file corpus)."""
    with tempfile.TemporaryDirectory() as tmp:
        corpus = Path(tmp) / "corpus"
        corpus.mkdir()
        (corpus / "input").write_bytes(data)
        argv = [*NETNS, str(binary), "-runs=0", "-print_coverage=1", f"-timeout={timeout}", str(corpus)]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout + 60, cwd=tmp, env=sanitizer_env())
        except subprocess.TimeoutExpired:
            return []
        return sorted(set(_COVERED.findall(proc.stderr.decode("utf-8", errors="replace"))))


def gdb_violation_state(binary: Path, data: bytes, phi_num: int, operands: list[str], *,
                        timeout: int = 60) -> str:
    """Stop at the invariant's violation hook and print the program state at the assertion site."""
    gdb = shutil.which("gdb")
    if not gdb:
        return "gdb unavailable"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "input"
        path.write_bytes(data)
        commands = ["set pagination off", "set confirm off", "set print pretty on",
                    f"break fba_phi_violate if id == {phi_num}", "run", "bt 12", "frame 1", "info args", "info locals"]
        commands += [f"print {expr}" for expr in operands[:8]]
        commands += ["kill", "quit"]
        argv = [*NETNS, gdb, "-batch", "-nx"]
        for command in commands:
            argv += ["-ex", command]
        argv += ["--args", str(binary), "-timeout=20", str(path)]
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout, cwd=tmp, env=sanitizer_env())
            text = proc.stdout.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired as exc:
            text = (exc.stdout or b"").decode("utf-8", errors="replace") + "\n[gdb timed out]"
    keep = [line for line in text.splitlines() if not line.startswith(("[New Thread", "[Thread ", "[Inferior",
                                                                          "Using host libthread_db"))]
    return "\n".join(keep)[-8000:]


def program_frames(frames: list[dict[str, Any]], source_root: Path, harness_source: Path) -> list[dict[str, Any]]:
    """Frames that lie in the original program's source (not libc, sanitizer runtime or harness)."""
    out = []
    root = str(source_root)
    for frame in frames:
        file = frame.get("file") or ""
        if file.startswith(root) or (file and not file.startswith("/") and "sanitizer" not in file):
            out.append(frame)
    return out


def in_harness(frames: list[dict[str, Any]], harness_source: Path) -> bool:
    """True when the first frame with source information is in the harness file."""
    for frame in frames:
        file = frame.get("file")
        if not file or "compiler-rt" in file or "/sanitizer" in file or file.startswith("/build/"):
            continue
        return Path(file).name == harness_source.name
    return False
