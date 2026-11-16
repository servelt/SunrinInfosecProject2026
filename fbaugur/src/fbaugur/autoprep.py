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
import time
from pathlib import Path
from typing import Any, Callable

from .config import CODEX_DAYBREAK, PROVIDER_MODELS

REFERENCE = Path(__file__).resolve().parents[2] / "targets" / "tinyproxy"

TASK = """You prepare an open-source C/C++ program for an automated fuzzing and vulnerability scan.
The source is checked out in {work}/source (repository {repo}). You work in {work} with a shell.
Do not modify files under {work}/source except through the project's own build steps.
You cannot use sudo; if a system package is missing, say exactly which in your final answer.

Deliver two files, written by you:

1. {work}/profile/prepare.sh -- a bash script that, run with `bash prepare.sh` from {work} with
   environment WORK={work}, PROFILE={work}/profile, HC=<HarnessCreator root>, PY=<python>, builds
   everything below from the clean source and prints a line "[prep] <short Korean step name>" before
   each step (they become the progress bar). `set -eu`, idempotent (it may run again on the same WORK),
   build output into log files, not the terminal. It must produce:
   a. $WORK/analysis/compile_commands.json for the program's own sources (use `bear -- <build>`;
      keep the project's normal configure options; the analysis needs the real defines).
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
   f. $WORK/daemon-plain/: gcc -O2, no sanitizers.
   g. $WORK/run/: whatever the program needs to start as a server on the loopback: a minimal
      configuration file (listen on 127.0.0.1, a fixed TCP port that nothing else uses, foreground /
      no daemonizing, no privilege drop, logs and pid files under $WORK/run, no authentication
      unless the program cannot run without it). Generate it from a template in $PROFILE if needed.

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
    "--port", "<port>", "--channel", "tcp",
    "--daemon-command", "{{WORK}}/daemon-asan/<binary> <args>",
    "--daemon-msan-command", "{{WORK}}/daemon-msan/<binary> <args>",          (omit both if no msan build)
    "--daemon-plain-command", "{{WORK}}/daemon-plain/<binary> <args>",
    "--daemon-cwd", "{{WORK}}",
    "--harness-max-minutes", "55"
  ]
}}
The program's main network input is what will be fuzzed: choose the listener a remote client reaches
(for a program with several, the main protocol port). If the program is not a network server at all,
use "--channel", "stdin" or "file" (with {{input_file}} in the commands) and no --port/--daemon-* args.

Work method: read the build files and docs first, then write prepare.sh, run it (`cd {work} && WORK={work}
PROFILE={work}/profile HC={hc} PY={py} bash profile/prepare.sh`), fix what fails, and run it again until
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


def _start_and_stop(command: str, cwd: str, port: int | None, *, wait: float = 25.0) -> dict[str, Any]:
    """Start a command, wait for its port, stop it with SIGTERM. What happened, for the report."""
    out = tempfile.NamedTemporaryFile(prefix="autoprep-", suffix=".log", delete=False)
    try:
        process = subprocess.Popen(shlex.split(command), cwd=cwd or None, stdout=out, stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL, start_new_session=True)
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
    out.close()
    text = Path(out.name).read_text(encoding="utf-8", errors="replace")[-1500:]
    os.unlink(out.name)
    return {"started": early_exit is None, "listening": listening, "exit": process.returncode,
            "early_exit": early_exit, "output": text}


def check_profile(work: Path, env: dict[str, str], *, rebuild: bool = True,
                  emit: Callable[[str], None] = lambda m: None) -> list[str]:
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
        run = subprocess.run(["bash", str(work / "profile" / profile.get("prepare", "prepare.sh"))], cwd=str(work),
                             env=env, capture_output=True, text=True, timeout=7200)
        if run.returncode != 0:
            return [f"prepare.sh failed (exit {run.returncode}): {(run.stdout + run.stderr).strip()[-1500:]}"]
        if not re.search(r"^\[prep\] ", run.stdout, re.M):
            problems.append("prepare.sh printed no '[prep] ...' step lines")
    args = [a.replace("{WORK}", str(work)) for a in profile.get("pipeline_args", [])]
    opt = {args[i]: args[i + 1] for i in range(len(args) - 1) if args[i].startswith("--")}
    for key in ("--coverage-root", "--coverage-command", "--analysis-compile-database", "--channel"):
        if key not in opt:
            problems.append(f"pipeline_args has no {key}")
    if problems:
        return problems
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
        result = _start_and_stop(opt["--coverage-command"], opt.get("--coverage-cwd", str(cov_root)), port)
        if not result["listening"]:
            problems.append(f"the coverage build did not accept a TCP connection on 127.0.0.1:{port} within 25 s "
                            f"(exited early: {result['early_exit']}); its output: {result['output'][-800:]}")
        elif not any(cov_root.rglob("*.gcda")):
            problems.append("the coverage build left no .gcda file after SIGTERM: it must exit normally on SIGTERM "
                            f"and its sources must be under {cov_root}; exit status {result['exit']}")
        for key in ("--daemon-command", "--daemon-plain-command", "--daemon-msan-command",
                    "--thread-trace-command"):
            if key in opt:
                r = _start_and_stop(opt[key], opt.get("--daemon-cwd", str(work)), port)
                if not r["listening"]:
                    problems.append(f"{key} did not accept a connection on port {port}: {r['output'][-600:]}")
    return problems


# ------------------------------------------------------------------------------------------ agent
class AutoPrep:
    def __init__(self, work: Path, *, repo: str, name: str, provider: str, model: str, python: str, hc: Path,
                 claude: str = "claude", codex: str = "codex", ollama_url: str = "http://localhost:11434",
                 rounds: int = 3, agent_timeout: float = 3600.0, emit: Callable[[str], None] = print,
                 progress: Callable[[str], None] = lambda label: None):
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
                    PY=self.python)

    def task(self) -> str:
        return TASK.format(work=self.work, repo=self.repo, name=self.name, hc=self.hc, py=self.python,
                           ref_profile=_read(REFERENCE / "profile.json"),
                           ref_prepare=_read(REFERENCE / "prepare.sh"), ref_build=_read(REFERENCE / "build.sh"))

    def _agent_ollama(self, prompt: str) -> str:
        """Ollama only: our own loop on /api/chat with shell and file tools in WORK."""
        from .ollama_agent import run_loop, workspace_tools
        tools = workspace_tools(self.work, on_command=lambda c: self.progress(str(c).splitlines()[0][:60]))
        result, self._history = run_loop(
            url=self.ollama_url, model=self.model,
            system="You are a build engineer with a shell. Use the bash, read_file and write_file tools.",
            message=prompt, local_tools=tools, max_turns=200, deadline_seconds=self.agent_timeout,
            history=getattr(self, "_history", None))
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
        process = subprocess.Popen(argv, cwd=str(self.work), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, env=env, start_new_session=True)
        process.stdin.write(prompt)
        process.stdin.close()
        final, started, self.agent_error, tail = "", time.time(), "", []
        with self.log.open("a", encoding="utf-8") as log:
            for line in process.stdout:
                log.write(line)
                tail = (tail + [line.strip()])[-20:]
                if time.time() - started > self.agent_timeout:
                    os.killpg(process.pid, signal.SIGKILL)
                    break
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
            problems = check_profile(self.work, self.env, emit=self.progress)
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
