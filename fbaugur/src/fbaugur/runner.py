"""Run a harness binary on one input, isolated in its own network namespace.

Every harness starts the original daemon on a fixed loopback port, so concurrent
runs (global fuzzer, SP fuzzers, PoV checks, triage replays) would collide.
`unshare -n` gives each process a private loopback interface.
"""

from __future__ import annotations

import dataclasses
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

# A non-root user needs a user namespace as well (-r maps the caller to root inside it).
NETNS = ["unshare", "-n" if os.geteuid() == 0 else "-rn", "sh", "-c", 'ip link set lo up && exec "$0" "$@"']

# MemorySanitizer reports with WARNING, not ERROR: `==N==WARNING: MemorySanitizer: use-of-uninitialized-value`.
_ERROR = re.compile(r"==\d+==(?:ERROR|WARNING): (AddressSanitizer|LeakSanitizer|libFuzzer|UndefinedBehaviorSanitizer|"
                    r"MemorySanitizer): ?([^\n]*)")
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
_TYPE = re.compile(r"(use-of-uninitialized-value|heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|heap-use-after-free|"
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


def find_symbolizer() -> str | None:
    """llvm-symbolizer, unversioned or the newest versioned one (apt.llvm.org installs llvm-symbolizer-20)."""
    found = shutil.which("llvm-symbolizer")
    if found:
        return found
    for version in range(30, 9, -1):
        found = shutil.which(f"llvm-symbolizer-{version}")
        if found:
            return found
    return None


def sanitizer_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:allocator_may_return_null=1:symbolize=1:handle_abort=1"
    # The combined ASan+UBSan build reports UB but keeps running (HarnessCreator recorded
    # misaligned-access reports on normal memcached inputs); crashes come from ASan and signals.
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=0"
    # Only llvm-symbolizer speaks the protocol the sanitizers use; pointing them at addr2line
    # only produces "invalid path to external symbolizer".  When it is missing the frames come
    # back as binary+offset and `symbolize()` resolves them after the fact.
    env["MSAN_OPTIONS"] = "halt_on_error=1:symbolize=1:print_stats=0"
    symbolizer = find_symbolizer()
    if symbolizer:
        env["ASAN_SYMBOLIZER_PATH"] = symbolizer
        env["MSAN_SYMBOLIZER_PATH"] = symbolizer
    env.pop("FBA_PHI_CONTINUE", None)
    env.pop("FBA_PHI_TRACE", None)
    if extra:
        env.update(extra)
    return env


_SOURCE_ROOT: Path | None = None
_RESOLVED: dict[str, str] = {}


def set_source_root(root: Path | str | None) -> None:
    """The program's source root, against which reported paths are made relative (per process)."""
    global _SOURCE_ROOT
    _SOURCE_ROOT = Path(root).resolve() if root else None
    _RESOLVED.clear()


def source_path(path: Any) -> str:
    """A reported source path, relative to the source root when the file is found there.

    Sanitizers print the path the compiler saw: the checkout, a build copy, or the copy an
    invariant build compiles.  The longest trailing part that names a file under the source root
    is used; a path that matches nothing is kept whole (normalised), never reduced to its file
    name, so files of one name in two directories are never taken for each other."""
    text = Path(str(path or "")).as_posix()
    if not text or text in (".", "None"):
        return "?"
    if text in _RESOLVED:
        return _RESOLVED[text]
    resolved = text[2:] if text.startswith("./") else text
    if _SOURCE_ROOT is not None:
        parts = Path(text).parts
        for index in range(len(parts)):
            tail = Path(*parts[index:])
            if not tail.is_absolute() and (_SOURCE_ROOT / tail).is_file():
                resolved = tail.as_posix()
                break
    _RESOLVED[text] = resolved
    return resolved


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

    def ub_sites(self) -> list[str]:
        """`path:line` of every UBSan report, in order, without duplicates.

        The path is relative to the program's source root (see `source_path`), so two files of
        one name in different directories stay apart, and the same file compiled from another
        copy of the tree (an instrumented build) is still the same site."""
        seen: list[str] = []
        for item in self.ubsan:
            site = f"{source_path(item.get('file'))}:{item.get('line')}"
            if site not in seen:
                seen.append(site)
        return seen

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


def new_ub_sites(result: RunResult, baseline: set[str] | None) -> list[str]:
    """UBSan sites in `result` that verified normal inputs do not already produce.

    The sanitizer build runs with halt_on_error=0 because some programs report UB on ordinary
    input (memcached: misaligned access in the binary protocol), so UBSan never aborts and a
    UB-only defect never set `crashed`.  On LightFTP that discarded a real one: `PORT 1,2,3,200,0,21`
    makes `ftpPORT` shift 200 left by 24 bits in an int (ftpserv.c:551), UBSan reported it on
    every run, and the PoV was still recorded as failed.  A site the normal inputs also reach
    is the program's background noise and is not a finding; any other site is.
    """
    known = baseline or set()
    return [site for site in result.ub_sites()
            if site not in known and _LEGACY_SITE + _basename_site(site) not in known]


_LEGACY_SITE = "basename:"      # entries of a ub-baseline.json written before paths were kept


def _basename_site(site: str) -> str:
    path, _, line = site.rpartition(":")
    return f"{Path(path).name}:{line}"


def is_finding(result: RunResult, baseline: set[str] | None) -> bool:
    """A sanitizer fault, or undefined behaviour at a site normal inputs never trigger."""
    return result.crashed or bool(new_ub_sites(result, baseline))


def finding_type(result: RunResult, baseline: set[str] | None) -> str | None:
    if result.crashed:
        return result.crash_type
    sites = new_ub_sites(result, baseline)
    if not sites:
        return None
    message = next((u.get("message", "") for u in result.ubsan
                    if f"{source_path(u.get('file'))}:{u.get('line')}" == sites[0]), "")
    return f"undefined-behavior: {message}"[:160]


_RUNTIME_FUNCTION = re.compile(r"^(__interceptor_|__asan|__ubsan|__sanitizer|__lsan|__msan|__interceptor|"
                               r"___interceptor|start_thread|__clone|clone3?$|__libc_|_start$|__GI_|fba_phi_)")
_RUNTIME_FILE = re.compile(r"compiler-rt|/sanitizer|nptl/|sysdeps/|csu/|/build/glibc|libc-start")


def program_frames(frames: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Frames of the program itself: sanitizer interceptors and libc thread entry removed.

    A frame counts by its function name; a file is not required.  Without llvm-symbolizer the
    program's frames are resolved by `symbolize()`, which gets the function name from addr2line
    but no file or line on builds whose DWARF it cannot read.  Requiring a file kept exactly the
    wrong frames: on LightFTP every signature became `start_thread:442 | __clone3:81`.
    """
    kept = []
    for frame in frames:
        name = str(frame.get("function") or "")
        if not name or _RUNTIME_FUNCTION.match(name) or _RUNTIME_FILE.search(str(frame.get("file") or "")):
            continue
        kept.append(frame)
    return kept


def _frame_site(frame: dict[str, Any]) -> str:
    """`function@path:line`, or `function@?` when the report gave no location."""
    if frame.get("file") and frame.get("line"):
        return f"{frame['function']}@{source_path(frame['file'])}:{frame['line']}"
    return f"{frame['function']}@?"


def crash_signature(result: RunResult, baseline: set[str] | None = None, depth: int = 3) -> str:
    """Bug class and top program frames with their source location; for UB only, its site.

    The class is part of it (a use-after-free and an overflow at one line are two bugs) and so
    is the file (two static `parse` functions in two files are two places).  A frame without a
    location is kept as `function@?`: such a signature is not used to merge findings."""
    if not result.crashed:
        sites = new_ub_sites(result, baseline)
        if sites:
            return "UB " + sites[0]
    parts = [_frame_site(frame) for frame in program_frames(result.frames)[:depth]]
    kind = result.crash_type or "?"
    return f"{kind} | " + " | ".join(parts) if parts else kind


def fault_key(result: RunResult, baseline: set[str] | None = None) -> str:
    """Bug class and the place it happens: `stack-buffer-overflow@writelogentry@src/x.c:435`.

    Two findings with the same fault key are one root cause reached by different paths -- the
    same strcat overflowed from two callers -- even though their full signatures differ.  Line
    numbers and paths are part of it, so two different defects in one function stay apart.
    """
    if not result.crashed:
        sites = new_ub_sites(result, baseline)
        return f"undefined-behavior@{sites[0]}" if sites else ""
    frames = program_frames(result.frames)
    if not frames:
        return ""
    return f"{result.crash_type}@{_frame_site(frames[0])}"


def finding_identities(result: RunResult, baseline: set[str] | None = None) -> list[tuple[str, str, str]]:
    """Every distinct finding in one run: (identity, type, UB site or "").

    A sanitizer fault is one; each new UBSan site is one more (UBSan does not halt here, so one
    input can report several, and each may be a different defect)."""
    out: list[tuple[str, str, str]] = []
    if result.crashed:
        out.append((fault_key(result, baseline) or (result.crash_type or "?"), result.crash_type or "?", ""))
    for site in new_ub_sites(result, baseline):
        message = next((u.get("message", "") for u in result.ubsan
                        if f"{source_path(u.get('file'))}:{u.get('line')}" == site), "")
        out.append((f"undefined-behavior@{site}", f"undefined-behavior: {message}"[:160], site))
    return out


def resolved(identity: str) -> bool:
    """A signature or fault key whose locations are all known (it may be compared)."""
    return bool(identity) and "@?" not in identity and not identity.startswith("?")


def same_fault(a: RunResult, b: RunResult, baseline: set[str] | None = None, site: str = "") -> bool | None:
    """Are two findings the same defect?  None when their locations do not allow saying so.

    `site` is the UBSan site of a candidate made for that one site (one run can report several,
    each its own candidate): then it is the same defect only when both runs report that site.
    Comparing the fault keys would compare the runs' first new site, so a candidate for a second
    site would be counted as reproduced by a run where only the first one appeared.
    """
    if site:
        return site in a.ub_sites() and site in b.ub_sites()
    if not (is_finding(a, baseline) and is_finding(b, baseline)):
        return False
    ka, kb = fault_key(a, baseline), fault_key(b, baseline)
    if not (resolved(ka) and resolved(kb)):
        return None
    return ka == kb


def find_duplicate(signature: str, key: str, earlier: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str]:
    """The earlier finding this one repeats, and how: ("same stack" | "same fault site", or "").

    FuzzingBrain V2 de-duplicates crashes by the SHA-1 of the input bytes, so two inputs reaching
    one bug are two findings.  Here the stack decides, in two steps: the same top program frames
    (the same bug by the same path), then the same fault key (the same bug by another path).
    Identities with an unknown location never merge: the finding stays a separate candidate
    until symbolization can tell.
    """
    if resolved(signature):
        for row in earlier:
            if row.get("signature") == signature:
                return row, "same stack"
    if resolved(key):
        for row in earlier:
            if (row.get("details") or {}).get("fault_key") == key:
                return row, "same fault site"
    return None, ""


def load_ub_baseline(run_dir: Path) -> set[str]:
    """Sites normal inputs reach.  Version 2 keeps paths; an older list kept file names only,
    and its entries are marked so they still match by file name rather than not at all."""
    path = Path(run_dir) / "ub-baseline.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if isinstance(raw, dict):
        return set(raw.get("sites") or [])
    return {_LEGACY_SITE + str(site) for site in raw}


def write_ub_baseline(run_dir: Path, sites: set[str]) -> None:
    (Path(run_dir) / "ub-baseline.json").write_text(
        json.dumps({"version": 2, "sites": sorted(sites)}), encoding="utf-8")


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


_HARNESS_FUNCTIONS: dict[str, set[str]] = {}


def harness_functions(harness_source: Path) -> set[str]:
    """Names of the functions the harness file defines."""
    key = str(harness_source)
    if key not in _HARNESS_FUNCTIONS:
        try:
            text = Path(harness_source).read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        _HARNESS_FUNCTIONS[key] = set(re.findall(r"^[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{",
                                                  text, re.M))
    return _HARNESS_FUNCTIONS[key]


def in_harness(frames: list[dict[str, Any]], harness_source: Path) -> bool:
    """True when the innermost program frame belongs to the harness.

    Decided by file when the frame has one, otherwise by function name: unsymbolized builds
    give names but no files, and a file-only rule then never recognised a harness fault.
    """
    for frame in program_frames(frames):
        file = frame.get("file")
        if file:
            return Path(file).name == Path(harness_source).name
        return str(frame.get("function")) in harness_functions(harness_source)
    return False


@dataclasses.dataclass
class DaemonReplay:
    started: bool
    result: RunResult | None       # the program's own sanitizer report, parsed
    sent: int
    note: str
    closed_mid_input: str = ""     # the program closed or reset the connection before all bytes were sent


_ALLOCATOR_ERROR = re.compile(r"(free\(\)|malloc\(\)|realloc\(\)|munmap_chunk\(\)|malloc_consolidate\(\)|"
                              r"double free|corrupted size|corrupted double-linked|corrupted top size)[^\n]*")


@dataclasses.dataclass
class PlainReplay:
    """The same input sent, repeatedly, to the program built WITHOUT sanitizers."""
    started: bool
    requested: int
    runs_sent: int
    died: bool
    returncode: int | None
    allocator_errors: list[str]
    response: bytes
    note: str

    @property
    def effect(self) -> bool:
        return self.died or bool(self.allocator_errors)


def plain_replay(command: str, data: bytes, *, port: int, delivery: str = "stream", cwd: str | None = None,
                 repeat: int = 200, env: dict[str, str] | None = None, host: str = "127.0.0.1",
                 trigger: bytes = b"") -> PlainReplay:
    """What the finding does in a normal build: does the program die, does glibc see heap damage?

    A sanitizer reports the first bad access and stops; whether that access does anything in the
    program people actually run is a separate, measurable question.  On tinyproxy 1.11.1 the
    use-after-free killed the normal build on the first request ("free(): double free detected
    in tcache 2"), while the one-byte overflow ran 300 of 300 requests with no error.  Validators
    that could not see this disagreed with each other about the same overflow (0.0, 4.8 and 3.7).
    """
    import sys
    out = _run_replay_helper({"command": command, "cwd": cwd, "port": port, "host": host, "delivery": delivery,
                              "input_hex": data.hex(), "repeat": repeat, "io_timeout": 5, "settle": 2,
                              "trigger_hex": trigger.hex(),
                              "env": dict(env or {})}, timeout=120 + 2 * repeat, python=sys.executable)
    if not out.get("started"):
        return PlainReplay(False, repeat, 0, False, None, [], b"", out.get("error", "did not start"))
    stderr = out.get("stderr", "")
    errors = sorted({m.group(0).strip()[:160] for m in _ALLOCATOR_ERROR.finditer(stderr)})
    died = bool(out.get("crashed_on_its_own"))
    return PlainReplay(True, repeat, int(out.get("runs_sent", 0)), died, out.get("returncode"), errors,
                       bytes.fromhex(out.get("response_hex", "")), "")


def _elf_kind(path: str) -> tuple[int, int] | None:
    """(class, machine) from an ELF header: (2, 62) is 64-bit x86-64, (1, 3) 32-bit i386."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(20)
    except OSError:
        return None
    if len(head) < 20 or head[:4] != b"\x7fELF":
        return None
    return head[4], int.from_bytes(head[18:20], "little" if head[5] == 1 else "big")


def debug_allocator_library(program: str | None = None) -> str | None:
    """glibc's malloc debugging library (glibc >= 2.34) for the program's architecture.

    A library of the wrong word size is skipped by the loader without an error -- the first
    version of this check preloaded the i386 copy into a 64-bit tinyproxy and measured nothing.
    """
    want = _elf_kind(program) if program else _elf_kind(sys.executable)
    candidates = sorted({p for pattern in ("/usr/lib/*/libc_malloc_debug.so.0", "/lib/*/libc_malloc_debug.so.0",
                                           "/usr/lib64/libc_malloc_debug.so.0", "/lib64/libc_malloc_debug.so.0")
                         for p in glob.glob(pattern)})
    for path in candidates:
        if want is None or _elf_kind(os.path.realpath(path)) == want:
            return path
    return None


def daemon_replay(command: str, data: bytes, *, port: int, delivery: str = "stream", cwd: str | None = None,
                  host: str = "127.0.0.1", timeout: int = 60, trigger: bytes = b"") -> DaemonReplay:
    """Start the real program as a server in a private network namespace and send `data` to it.

    No harness is involved: the bytes reach the program through its own socket, as they would
    from a remote peer.  See daemon_replay.py.
    """
    import sys
    last = DaemonReplay(False, None, 0, "not run")
    for _ in range(3):
        # A sanitizer build can fault before main() on WSL (measured: an ASan PIE build of
        # LightFTP died at startup with SIGSEGV; the same build linked -no-pie started 15/15).
        # A start that fails is retried; a start that succeeds is never repeated.
        last = _daemon_replay_once(command, data, port=port, delivery=delivery, cwd=cwd, host=host,
                                   timeout=timeout, python=sys.executable, trigger=trigger)
        if last.started:
            return last
    return last


def _run_replay_helper(spec: dict[str, Any], timeout: int, python: str) -> dict[str, Any]:
    """Run daemon_replay.py in a private network namespace; its JSON, or {"error": ...}."""
    with tempfile.TemporaryDirectory(prefix="fba-daemon-") as tmp:
        path = Path(tmp) / "spec.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        package_root = str(Path(__file__).resolve().parent.parent)
        env = dict(os.environ, PYTHONPATH=package_root + os.pathsep + os.environ.get("PYTHONPATH", ""))
        try:
            proc = subprocess.run([*NETNS, python, "-m", "fbaugur.daemon_replay", str(path)],
                                  capture_output=True, text=True, timeout=timeout, env=env)
        except subprocess.TimeoutExpired:
            return {"error": f"replay timed out after {timeout}s"}
        try:
            return json.loads(proc.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {"error": f"replay helper failed: {proc.stderr.strip()[-400:]}"}


def _daemon_replay_once(command: str, data: bytes, *, port: int, delivery: str, cwd: str | None,
                        host: str, timeout: int, python: str, trigger: bytes = b"") -> DaemonReplay:
    out = _run_replay_helper({"command": command, "cwd": cwd, "port": port, "host": host,
                              "delivery": delivery, "input_hex": data.hex(), "trigger_hex": trigger.hex(),
                              "env": {k: v for k, v in sanitizer_env().items()
                                      if k.endswith(("SAN_OPTIONS", "SYMBOLIZER_PATH"))}}, timeout, python)
    if "error" in out and "started" not in out:
        return DaemonReplay(False, None, 0, out["error"])
    if not out.get("started"):
        return DaemonReplay(False, None, 0, out.get("error", "did not start"))
    parsed = parse_report(out.get("stderr", ""), out.get("returncode"), False)
    note = "the program crashed" if out.get("crashed_on_its_own") else "the program kept running"
    return DaemonReplay(True, parsed, int(out.get("sent", 0)), note, str(out.get("closed_mid_input") or ""))
