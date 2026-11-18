"""Prepare a repository for a scan with nothing but its link.

A scan needs, for the program in WORK/source: a compile database, a coverage build, an
instrumented trace build, sanitizer and plain builds of the real program, and a way to start it
(arguments, configuration, port).  For tinyproxy a person wrote that once (targets/tinyproxy).
Here an agent with a shell works it out inside WORK and leaves the same two files a person would:

    WORK/profile/profile.json   what the pipeline is given (pipeline_args with {WORK})
    WORK/profile/prepare.sh     rebuilds everything from a clean WORK/source, printing "[prep] ..." lines

The agent's word is not taken: Occulta runs prepare.sh again itself and measures each requirement
(check_profile).  What fails goes back to the agent, which continues its session and fixes it.
A profile that passes is kept in OCCULTA_HOME/targets/<name>/ and reused without an agent.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import proctrack
from .config import CODEX_DAYBREAK, PROVIDER_MODELS

REFERENCE = Path(__file__).resolve().parents[2] / "targets" / "tinyproxy"

TASK = """You prepare an open-source C/C++ program for an automated fuzzing and vulnerability scan.
The source is checked out in {work}/source (repository {repo}). You work in {work} with a shell.
Do not modify files under {work}/source except through the project's own build steps.
You cannot use sudo; if a system package is missing, say exactly which in your final answer.

Deliver two files, written by you:

1. {work}/profile/prepare.sh -- a bash script that, run with `bash prepare.sh` from {work} with
   environment WORK={work}, PROFILE={work}/profile, HC=<HarnessCreator root>, PY=<python>,
   MSAN_LIBS=<shared MemorySanitizer library cache>, MSAN_CC=<clang for MSan>, builds
   everything below from the clean source and prints a line "[prep] <short Korean step name>" before
   each step (they become the progress bar). `set -eu`, idempotent (it may run again on the same WORK),
   build output into log files, not the terminal. It must produce:
   a. $WORK/analysis/compile_commands.json for the program's own sources (use `bear -- <build>`;
      keep the project's normal configure options; the analysis needs the real defines). Build
      only the server program's target, with -g, and KEEP the build: the harness is linked from the
      translation units that program's debug information names and from the static archives the
      build made (bundled libraries), so the executable and its build tree must stay in $WORK/analysis.
      Build every variant below in the same layout (a copy of the source tree, or an out-of-tree
      build directory) so the executable sits at the same path inside each build tree.
   b. $WORK/cov/: a build with `gcc --coverage -O0 -g` (or the project's build with
      CC=gcc CFLAGS="-O0 -g --coverage" LDFLAGS=--coverage). IMPORTANT: the source files must be
      INSIDE $WORK/cov (copy the source tree into $WORK/cov and build there), because coverage records
      are only read for sources under the coverage root. The program must write its .gcda files when
      it receives SIGTERM, i.e. it exits normally on SIGTERM (most servers do; if not, say so).
   c. $WORK/trace/: the same program built with `clang -O0 -g -finstrument-functions` and linked with
      the hook object made by: PYTHONPATH="$HC/src" "$PY" -m harnesscreator.cli thread-trace-hook $WORK/trace/hook.o
      (optional: skip it if the build system makes this impractical, and leave the argument out).
   d. $WORK/daemon-asan/: clang -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined, linked -no-pie.
   e. $WORK/daemon-msan/: the newest clang-NN >= 18 found (clang-20, ...) with -fsanitize=memory
      -fsanitize-memory-track-origins=2 (optional: skip if no such clang or the build cannot do it).
      MemorySanitizer only sees memory written by instrumented code: EVERY library the program links,
      other than the C runtime (libc, libm, libdl, libpthread, librt, ld-linux, libgcc_s), must also be
      built with -fsanitize=memory, or each value it returns is reported as uninitialised (a system
      libcrypto.so fails at startup). Bundled libraries: build them with the same flags. System
      libraries (OpenSSL, libyang, libxml2, zlib, ...): build each from its upstream source at the
      version installed on this machine, with $MSAN_CC -fsanitize=memory (and its no-assembly option,
      e.g. OpenSSL `no-asm enable-msan`; assembly is invisible to MemorySanitizer), installed into the
      shared cache $MSAN_LIBS/<library>-<version>/ (include/, lib/), static libraries preferred. Reuse a
      cache directory that already exists; other targets share it. Write a file
      $MSAN_LIBS/<library>-<version>/BUILT with the configure command when a build finished. Link the
      MSan daemon and build_harness.sh (when SANITIZER=memory) against the cached libraries, never the
      system ones. If a dependency cannot be built this way, skip the MSan variant and say which.
   f. $WORK/daemon-plain/: gcc -O2, no sanitizers.
   g. $WORK/run/: whatever the program needs to start as a server on the loopback: a minimal
      configuration file (listen on 127.0.0.1, a fixed TCP port that nothing else uses, foreground /
      no daemonizing, no privilege drop, logs and pid files under $WORK/run, no authentication
      unless the program cannot run without it). Generate it from a template in $PROFILE if needed.

   h. {work}/profile/build_harness.sh -- the recipe that builds a libFuzzer harness against the
      program, used for every harness build later (OSS-Fuzz's build.sh contract). It is called as
      `bash build_harness.sh SRC HARNESS OUT` with environment CC, CXX, CFLAGS, CXXFLAGS (sanitizer and
      -fsanitize=fuzzer-no-link already in them), LIB_FUZZING_ENGINE (the final link flags),
      MAIN_RENAME (`-Dmain=hc_native_original_main`), BUILD_DIR (an empty scratch directory) and
      SANITIZER (address+undefined or memory). SRC is a tree laid out like $WORK/analysis (possibly a
      copy with some .c files edited): treat it as read-only and build under $BUILD_DIR (copy SRC there
      first if the build system writes into its tree). It must:
        - build the server program from SRC exactly as the analysis build does (same configure options,
          same defines, same bundled libraries), but with $CC/$CXX and $CFLAGS for EVERY object,
          including bundled libraries (a MemorySanitizer binary with one uninstrumented library reports
          false errors), and with a fresh configure/build directory (never reuse objects of other builds);
        - compile the file that defines the program's main() with $MAIN_RENAME added;
        - compile HARNESS with $CC $CFLAGS and the program's include flags, and link it with all the
          program's objects and libraries (system libraries such as -lssl included) as
          `$CC $CFLAGS <objects> <libraries> $LIB_FUZZING_ENGINE -o OUT` ($CXX instead only for a
          C++ program; it adds libstdc++, which MemorySanitizer cannot see into);
        - write nothing outside $BUILD_DIR and OUT, and print the build output (errors must be visible).
      Occulta checks it with a harness that does nothing; the result must run.

2. {work}/profile/profile.json -- exactly this shape (paths written with {{WORK}}, replaced later):
{{
  "name": "{name}",
  "repos": ["{repo}"],
  "prepare": "prepare.sh",
  "port": <port>,
  "pipeline_args": [
    "--coverage-root", "{{WORK}}/cov",
    "--coverage-command", "{{WORK}}/cov/<path to binary> <args that start it in the foreground>",
    "--coverage-cwd", "{{WORK}}/cov",
    "--thread-trace-command", "{{WORK}}/trace/<binary> <same args>",          (omit both if no trace build)
    "--analysis-compile-database", "{{WORK}}/analysis/compile_commands.json",
    "--harness-link-binary", "{{WORK}}/analysis/<path to the server binary the analysis build made>",
    "--harness-build-script", "{{PROFILE}}/build_harness.sh",
    "--port", "<port>", "--channel", "tcp",
    "--daemon-command", "{{WORK}}/daemon-asan/<binary> <args>",
    "--daemon-msan-command", "{{WORK}}/daemon-msan/<binary> <args>",          (omit both if no msan build)
    "--daemon-plain-command", "{{WORK}}/daemon-plain/<binary> <args>",
    "--daemon-cwd", "{{WORK}}"
  ]
}}
The program's main network input is what will be fuzzed: choose the listener a remote client reaches
(for a program with several, the main protocol port). If the program is not a network server at all,
use "--channel", "stdin" or "file" (with {{input_file}} in the commands) and no --port/--daemon-* args.

Work method: read the build files and docs first, then write prepare.sh, run it (`cd {work} && WORK={work}
PROFILE={work}/profile HC={hc} PY={py} MSAN_LIBS={msan_libs} MSAN_CC={msan_cc} bash profile/prepare.sh`), fix what fails, and run it again until
it passes. Then start the coverage build with its command, check the port accepts a connection, stop it
with SIGTERM and check .gcda files appeared under $WORK/cov. When everything works, end with a short
summary: build system, binary, port, configuration, anything you skipped and why.

A working example written by hand for tinyproxy follows. Adapt the method, not the details.
--- profile.json ---
{ref_profile}
--- prepare.sh ---
{ref_prepare}
--- build.sh (called by prepare.sh) ---
{ref_build}
"""


def _read(path: Path, limit: int = 6000) -> str:
    try:
        return path.read_text(encoding="utf-8")[:limit]
    except OSError:
        return ""


# ------------------------------------------------------------------------------------------ checks
def _port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _start_and_stop(command: str, cwd: str, port: int | None, *, wait: float = 25.0,
                    key: str | None = None) -> dict[str, Any]:
    """Start a command, wait for its port, stop it with SIGTERM. What happened, for the report."""
    out = tempfile.NamedTemporaryFile(prefix="autoprep-", suffix=".log", delete=False)
    try:
        process = proctrack.spawn(key, shlex.split(command), cwd=cwd or None, stdout=out, stderr=subprocess.STDOUT,
                                  stdin=subprocess.DEVNULL)
    except OSError as exc:
        return {"started": False, "listening": False, "exit": None, "output": str(exc)}
    listening = False
    deadline = time.time() + wait
    while time.time() < deadline and process.poll() is None:
        if port and _port_open(port):
            listening = True
            break
        if not port:
            time.sleep(2)
            break
        time.sleep(0.2)
    early_exit = process.poll()
    if early_exit is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
    proctrack.forget(key, process)
    out.close()
    text = Path(out.name).read_text(encoding="utf-8", errors="replace")[-1500:]
    os.unlink(out.name)
    return {"started": early_exit is None, "listening": listening, "exit": process.returncode,
            "early_exit": early_exit, "output": text}


def check_profile(work: Path, env: dict[str, str], *, rebuild: bool = True,
                  emit: Callable[[str], None] = lambda m: None, key: str | None = None) -> list[str]:
    """Problems with WORK/profile, measured; an empty list means the profile is usable."""
    problems: list[str] = []
    profile_path = work / "profile" / "profile.json"
    try:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return [f"profile/profile.json is missing or not JSON: {exc}"]
    if not (work / "profile" / profile.get("prepare", "prepare.sh")).is_file():
        return ["profile/prepare.sh is missing"]
    if rebuild:
        emit("prepare.sh 다시 실행해서 확인")
        run = proctrack.run(key, ["bash", str(work / "profile" / profile.get("prepare", "prepare.sh"))], cwd=str(work),
                            env=env, text=True, timeout=7200)
        if run.returncode != 0:
            return [f"prepare.sh failed (exit {run.returncode}): {(run.stdout + run.stderr).strip()[-1500:]}"]
        if not re.search(r"^\[prep\] ", run.stdout, re.M):
            problems.append("prepare.sh printed no '[prep] ...' step lines")
    args = [a.replace("{WORK}", str(work)).replace("{PROFILE}", str(work / "profile"))
            for a in profile.get("pipeline_args", [])]
    opt = {args[i]: args[i + 1] for i in range(len(args) - 1) if args[i].startswith("--")}
    for key in ("--coverage-root", "--coverage-command", "--analysis-compile-database", "--channel",
                "--harness-link-binary", "--harness-build-script"):
        if key not in opt:
            problems.append(f"pipeline_args has no {key}")
    if problems:
        return problems
    link = Path(opt["--harness-link-binary"])
    if not link.is_file():
        problems.append(f"--harness-link-binary {link} does not exist; keep the analysis build")
    else:
        sections = subprocess.run(["readelf", "-S", str(link)], capture_output=True, text=True).stdout
        if ".debug_info" not in sections:
            problems.append(f"--harness-link-binary {link} has no debug information; build it with -g")
    if not problems:
        problems += check_harness_script(work, env, opt)
    try:
        entries = json.loads(Path(opt["--analysis-compile-database"]).read_text(encoding="utf-8"))
        if not entries:
            problems.append("compile_commands.json is empty")
        else:
            source = (work / "source").resolve()
            def under_source(entry: dict) -> bool:
                path = Path(str(entry.get("file", "")))
                path = path if path.is_absolute() else Path(str(entry.get("directory", ""))) / path
                return path.resolve() == source or source in path.resolve().parents or \
                    any((source / Path(*path.parts[i:])).is_file() for i in range(1, len(path.parts)))
            if not any(under_source(e) for e in entries[:400] if isinstance(e, dict)):
                problems.append(f"compile_commands.json names no file of {source}: build it in {source} itself "
                                "(or in a copy whose relative paths match), the analysis reads that tree")
    except (OSError, ValueError) as exc:
        problems.append(f"compile database unreadable: {exc}")
    channel = opt["--channel"]
    port = int(opt.get("--port", 0) or 0)
    if channel in ("tcp", "udp") and not port:
        problems.append("a network channel needs --port")
    cov_root = Path(opt["--coverage-root"])
    for gcda in cov_root.rglob("*.gcda"):
        gcda.unlink()
    binary = shlex.split(opt["--coverage-command"])[0]
    if not os.access(binary, os.X_OK):
        problems.append(f"coverage binary is not an executable file: {binary}")
        return problems
    if channel == "tcp":
        result = _start_and_stop(opt["--coverage-command"], opt.get("--coverage-cwd", str(cov_root)), port, key=key)
        if not result["listening"]:
            problems.append(f"the coverage build did not accept a TCP connection on 127.0.0.1:{port} within 25 s "
                            f"(exited early: {result['early_exit']}); its output: {result['output'][-800:]}")
        elif not any(cov_root.rglob("*.gcda")):
            problems.append("the coverage build left no .gcda file after SIGTERM: it must exit normally on SIGTERM "
                            f"and its sources must be under {cov_root}; exit status {result['exit']}")
        session_key = key
        for key in ("--daemon-command", "--daemon-plain-command", "--daemon-msan-command",
                    "--thread-trace-command"):
            if key in opt:
                if key == "--daemon-msan-command":
                    problems += _uninstrumented_libraries(Path(shlex.split(opt[key])[0]), "the MSan daemon")
                r = _start_and_stop(opt[key], opt.get("--daemon-cwd", str(work)), port, key=session_key)
                if not r["listening"]:
                    problems.append(f"{key} did not accept a connection on port {port}: {r['output'][-600:]}")
    return problems


_C_RUNTIME = re.compile(r"^(linux-vdso|libc|libm|libdl|libpthread|librt|libutil|libresolv|ld-linux[^ ]*|libgcc_s)"
                        r"\.so")


def msan_cc() -> str:
    """The newest clang-NN >= 18 on PATH (older ones cannot start MSan on this kernel)."""
    for n in range(30, 17, -1):
        if shutil.which(f"clang-{n}"):
            return f"clang-{n}"
    return "clang"


def msan_libs_dir() -> Path:
    """Shared cache of libraries built with MemorySanitizer, for every target."""
    return Path(os.environ.get("OCCULTA_HOME", Path.home() / ".occulta")) / "msan-libs"


def _uninstrumented_libraries(binary: Path, what: str, allow: tuple[str, ...] = ()) -> list[str]:
    """A MemorySanitizer binary must load no shared library built without it, other than the C
    runtime the sanitizer intercepts: values such a library writes look uninitialised (goahead: the
    system libcrypto.so.3 in BIO_new_file, before any input).  Libraries resolved from the shared
    MSan cache are instrumented by construction."""
    try:
        out = subprocess.run(["ldd", str(binary)], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [f"cannot list the shared libraries of {binary}: {exc}"]
    cache = str(msan_libs_dir().resolve())
    bad = []
    for line in out.splitlines():
        line = line.strip()
        name = line.split()[0] if line else ""
        if not name or _C_RUNTIME.match(Path(name).name) or Path(name).name.startswith(allow or ("\0",)):
            continue
        path = line.split("=>")[1].split("(")[0].strip() if "=>" in line else name
        if not str(Path(path).resolve()).startswith(cache + "/"):
            bad.append(f"{name} ({path})")
    if not bad:
        return []
    return [f"{what} loads shared libraries not built with MemorySanitizer: {', '.join(bad)}. Build them "
            f"with -fsanitize=memory into {cache}/<library>-<version>/ and link those (static preferred)"]


_EMPTY_HARNESS = (
    "#include <stddef.h>\n#include <stdint.h>\n"
    "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { (void)data; (void)size; return 0; }\n")


def check_harness_script(work: Path, env: dict[str, str], opt: dict[str, str]) -> list[str]:
    """Build a harness that does nothing through the profile's recipe, the way every later harness
    is built, once per sanitizer the scan uses, and run it once."""
    problems: list[str] = []
    sanitizers = ["address+undefined"] + (["memory"] if "--daemon-msan-command" in opt else [])
    scratch = work / "harness-check"
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)
    harness = scratch / "empty_harness.c"
    harness.write_text(_EMPTY_HARNESS, encoding="utf-8")
    for sanitizer in sanitizers:
        out = scratch / sanitizer.replace("+", "-")
        argv = [env.get("PY") or "python3", "-m", "harnesscreator.runtime.native_build",
                "--source-root", str(work / "source"), "--harness", str(harness), "--output", str(out),
                "--compile-database", opt["--analysis-compile-database"],
                "--target-binary", opt["--harness-link-binary"], "--build-script", opt["--harness-build-script"]]
        run = subprocess.run(argv, env=dict(env, PYTHONPATH=str(Path(env.get("HC", ".")) / "src"),
                                            HARNESSCREATOR_NATIVE_SANITIZER=sanitizer),
                             capture_output=True, text=True, timeout=7200)
        binary = out / "hc-native-fuzzer"
        if run.returncode != 0 or not binary.is_file():
            problems.append(f"build_harness.sh did not build a {sanitizer} harness: "
                            f"{(run.stdout + run.stderr).strip()[-2000:]}")
            continue
        if sanitizer == "memory":
            # libFuzzer's own runtime links libstdc++ into every harness (also of a C program); it
            # does not touch program data.  A C++ program's libstdc++ is caught on its MSan daemon.
            problems += _uninstrumented_libraries(binary, "the memory harness built by build_harness.sh",
                                                  allow=("libstdc++.so",))
        ran = subprocess.run([str(binary), "-runs=10"], capture_output=True, text=True, timeout=300,
                             stdin=subprocess.DEVNULL)
        if ran.returncode != 0:
            problems.append(f"the {sanitizer} harness built by build_harness.sh does not run "
                            f"(exit {ran.returncode}): {ran.stderr[-1500:]}")
    return problems


# ------------------------------------------------------------------------------------------ agent
class AutoPrep:
    def __init__(self, work: Path, *, repo: str, name: str, provider: str, model: str, python: str, hc: Path,
                 claude: str = "claude", codex: str = "codex", ollama_url: str = "http://localhost:11434",
                 rounds: int = 3, agent_timeout: float = 3600.0, emit: Callable[[str], None] = print,
                 progress: Callable[[str], None] = lambda label: None, key: str | None = None):
        self.key = key
        self.work, self.repo, self.name = Path(work), repo, name
        self.provider, self.model, self.python, self.hc = provider, model, python, Path(hc)
        self.claude, self.codex, self.ollama_url = claude, codex, ollama_url
        self.rounds, self.agent_timeout = rounds, agent_timeout
        self.emit, self.progress = emit, progress
        self.session_id = ""
        self.log = self.work / "autoprep-agent.jsonl"

    @property
    def env(self) -> dict[str, str]:
        return dict(os.environ, WORK=str(self.work), PROFILE=str(self.work / "profile"), HC=str(self.hc),
                    PY=self.python, MSAN_LIBS=str(msan_libs_dir()), MSAN_CC=msan_cc())

    def task(self) -> str:
        return TASK.format(work=self.work, repo=self.repo, name=self.name, hc=self.hc, py=self.python,
                           msan_libs=msan_libs_dir(), msan_cc=msan_cc(),
                           ref_profile=_read(REFERENCE / "profile.json"),
                           ref_prepare=_read(REFERENCE / "prepare.sh"), ref_build=_read(REFERENCE / "build.sh"))

    def _agent_ollama(self, prompt: str) -> str:
        """Ollama only: our own loop on /api/chat with shell and file tools in WORK."""
        from .ollama_agent import run_loop, workspace_tools
        tools = workspace_tools(self.work, on_command=lambda c: self.progress(str(c).splitlines()[0][:60]), key=self.key)
        result, self._history = run_loop(
            url=self.ollama_url, model=self.model,
            system="You are a build engineer with a shell. Use the bash, read_file and write_file tools.",
            message=prompt, local_tools=tools, max_turns=200, deadline_seconds=self.agent_timeout,
            history=getattr(self, "_history", None),
            should_stop=lambda: proctrack.cancelled(self.key or ""))
        if proctrack.cancelled(self.key or ""):
            raise proctrack.Cancelled("stopped by the user")
        with self.log.open("a", encoding="utf-8") as log:
            log.write(json.dumps({"turns": result.turns, "tool_calls": result.tool_calls, "status": result.status,
                                  "error": result.error, "text": result.text[-2000:]}, ensure_ascii=False) + "\n")
        self.agent_error = result.error if result.status == "error" else ""
        return result.text

    def _agent(self, prompt: str) -> str:
        """One agent session (continued when one exists); returns its final text."""
        (self.work / "profile").mkdir(parents=True, exist_ok=True)
        if self.provider == "ollama":
            return self._agent_ollama(prompt)
        if self.provider == "codex":
            argv = [self.codex, "exec", "--json", "--ignore-user-config", *CODEX_DAYBREAK, "--skip-git-repo-check",
                    "-m", self.model,
                    "-s", "workspace-write", "-C", str(self.work),
                    "-c", 'model_reasoning_effort="high"', "-c", "sandbox_workspace_write.network_access=true"]
            argv += (["resume", self.session_id, "-"] if self.session_id else ["-"])
            env = None
        else:
            argv = [self.claude, "-p", "--model", self.model, "--output-format", "stream-json", "--verbose",
                    "--allowedTools", "Bash", "Read", "Write", "Edit", "Glob", "Grep",
                    "--add-dir", str(self.work), "--setting-sources", "", "--strict-mcp-config", "--max-turns", "200"]
            argv += ["--resume", self.session_id] if self.session_id else []
            env = None
            if self.provider == "ollama":
                from types import SimpleNamespace
                from .agent import ollama_env
                env = ollama_env(SimpleNamespace(ollama_url=self.ollama_url), self.model)
        process = proctrack.spawn(self.key, argv, cwd=str(self.work), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, env=env)
        process.stdin.write(prompt)
        process.stdin.close()
        # The limit holds even when the agent prints nothing: a timer ends the whole process group.
        timed_out = threading.Event()

        def expire() -> None:
            timed_out.set()
            proctrack.kill_group(process.pid, grace=2.0)

        watchdog = threading.Timer(self.agent_timeout, expire)
        watchdog.daemon = True
        watchdog.start()
        final, started, self.agent_error, tail = "", time.time(), "", []
        with self.log.open("a", encoding="utf-8") as log:
            for line in process.stdout:
                log.write(line)
                tail = (tail + [line.strip()])[-20:]
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                self.session_id = (event.get("session_id") or event.get("thread_id") or self.session_id)
                final = self._watch(event) or final
                if event.get("type") == "result" and event.get("is_error"):
                    self.agent_error = str(event.get("result") or event.get("subtype") or "agent error")
                if event.get("type") in ("error", "turn.failed"):
                    self.agent_error = str(event.get("message") or (event.get("error") or {}).get("message") or event)
        code = process.wait()
        watchdog.cancel()
        proctrack.forget(self.key, process)
        if proctrack.cancelled(self.key or ""):
            raise proctrack.Cancelled("stopped by the user")
        if timed_out.is_set():
            self.agent_error = self.agent_error or f"the agent did not finish within {self.agent_timeout:.0f}s"
        if not final and not self.agent_error:
            # No answer at all: the agent did not run (not logged in, model unknown, CLI missing ...).
            plain = [t for t in tail if t and not t.startswith("{")]
            self.agent_error = (" | ".join(plain[-3:]) or (tail[-1] if tail else "")
                                or f"the agent exited with status {code} and wrote nothing")
        return final

    def _watch(self, event: dict[str, Any]) -> str:
        """Progress label from the agent's commands; the final text when the event carries it."""
        if event.get("type") == "assistant":
            for block in event.get("message", {}).get("content", []):
                if block.get("type") == "tool_use" and block.get("name") == "Bash":
                    what = block.get("input", {}).get("description") or block.get("input", {}).get("command", "")
                    self.progress(str(what).splitlines()[0][:60])
        item = event.get("item") or {}
        if item.get("type") == "command_execution" and event.get("type") == "item.started":
            self.progress(str(item.get("command", "")).splitlines()[0][:60])
        if event.get("type") == "result":
            return str(event.get("result") or "")
        if item.get("type") == "agent_message" and event.get("type") == "item.completed":
            return str(item.get("text") or "")
        return ""

    def run(self) -> tuple[bool, list[str], str]:
        """(usable, problems left, the agent's last summary)."""
        prompt, summary, problems = self.task(), "", ["not started"]
        if self.provider == "ollama":
            import urllib.request
            from .agent import missing_ollama_models
            try:
                tags = json.loads(urllib.request.urlopen(self.ollama_url.rstrip("/") + "/api/tags", timeout=5).read())
            except (OSError, ValueError) as exc:
                return False, [f"Ollama 가 응답하지 않음 ({self.ollama_url}): {exc}"], ""
            missing = missing_ollama_models(tags, {self.model})
            if missing:
                return False, [missing], ""
        for number in range(1, self.rounds + 1):
            self.emit(f"[autoprep] agent round {number}: {self.provider}/{self.model}")
            try:
                summary = self._agent(prompt)
            except FileNotFoundError as exc:
                return False, [f"준비 에이전트를 실행할 수 없음 ({exc.filename} 없음)"], ""
            self.emit("[autoprep] agent: " + summary.strip().replace("\n", " ")[:600])
            if self.agent_error and not (self.work / "profile" / "profile.json").is_file():
                # Retrying cannot help an agent that does not start; say why instead.
                return False, [f"준비 에이전트 실행 실패 ({self.provider}): {self.agent_error[:400]}"], summary
            self.progress("결과 확인 (prepare.sh 다시 실행)")
            problems = check_profile(self.work, self.env, emit=self.progress, key=self.key)
            if not problems:
                return True, [], summary
            self.emit("[autoprep] check failed: " + " | ".join(p[:300] for p in problems))
            prompt = ("Occulta ran profile/prepare.sh again itself and checked the result. These requirements "
                      "failed:\n- " + "\n- ".join(problems) + "\nFix prepare.sh and/or profile.json, run them "
                      "again, and end with a short summary.")
        return False, problems, summary


def default_model(provider: str, models: dict[str, str] | None = None) -> str:
    """Building and debugging a project is the main (coding) tier's work."""
    return (models or {}).get("2") or PROVIDER_MODELS[provider]["2"]


def save_profile(work: Path, targets_home: Path, name: str) -> Path:
    """Keep a passing profile for the next scan of the same repository."""
    dest = targets_home / re.sub(r"[^A-Za-z0-9._-]", "_", name)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(work / "profile", dest)
    return dest
