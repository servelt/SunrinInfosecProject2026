"""Continue a run from verified Entries to built harnesses in one command.

``harnesscreator run --workflow context`` ends the orchestrator once the Entry
files exist and calls :func:`run_after_entries`, which executes the same three
stages a user can start by hand (``contexts`` -> ``seeds`` -> ``context-harness``)
for every selected channel.  Nothing here re-implements a stage; it only builds
the arguments each stage already accepts and records what happened.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import time
from pathlib import Path
from typing import Any

from . import cli as stages
from .coverage import CoverageUnavailable, GcovCoverage
from .execution import ProgramRunner, ProgramSpec

_CHANNEL_DELIVERY = stages._CHANNEL_DELIVERY
_DELIVERY_CHANNEL = {delivery: channel for channel, delivery in _CHANNEL_DELIVERY.items()}
_CHANNEL_RESOURCE = {"tcp": "network", "udp": "network", "tcp-peer": "network", "stdin": "stdin", "file": "file"}
_CHANNEL_ORDER = ("tcp", "tcp-peer", "udp", "stdin", "file")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group(
        "input-context workflow (--workflow context)",
        "after the Entry stage: group Entries into input contexts, create and verify normal inputs on a "
        "coverage build of the original program, then generate, build and check one harness per channel")
    group.add_argument("--coverage-root", type=Path,
                       help="build directory of the original program compiled with --coverage (holds .gcno files)")
    group.add_argument("--coverage-command",
                       help="command that starts the coverage build, split without a shell")
    group.add_argument("--coverage-cwd", type=Path, help="working directory for --coverage-command "
                                                         "(default: --coverage-root)")
    group.add_argument("--thread-trace-command",
                       help="command of a second build with the thread-trace hook (see `thread-trace-hook`); "
                            "records which functions the thread that reads the input runs, so the harness is "
                            "not required to reproduce background-thread work")
    group.add_argument("--channel", action="append", default=[], choices=sorted(_CHANNEL_DELIVERY),
                       help="channel to produce a harness for (repeatable; default: every delivery of the "
                            "highest-priority network context, e.g. tcp and udp)")
    group.add_argument("--contexts-per-channel", type=int, default=0, metavar="N",
                       help="at most N contexts per channel, highest priority first (default 0 = every one). "
                            "A channel can hold several distinct contexts -- on an FTP server the control "
                            "connection and the two data-connection readers are all tcp/stream -- and each "
                            "one is a separate input path, so by default each gets its own harness")
    group.add_argument("--host", default=None, help="address the program listens on (default: --scenario-host)")
    group.add_argument("--port", type=int, default=None, help="port the program listens on (default: --scenario-port)")
    group.add_argument("--include-unresolved-entries", action="store_true",
                       help="also group Entries the Entry Verifier left UNRESOLVED. Unresolved means it "
                            "could not establish every condition (selected build target, remote exposure, "
                            "indirect-call targets), not that the input is not external; without this a "
                            "whole channel can be dropped")
    group.add_argument("--explore-lines", action="store_true",
                       help="also ask for inputs reaching unexecuted lines inside executed functions")
    group.add_argument("--generator-turns", type=int, default=0,
                       help="turn limit of the seed generator session; 0 (default) = no limit")
    group.add_argument("--frontier-turns", type=int, default=6, help="turn limit per not-yet-executed function")
    group.add_argument("--max-frontier-targets", type=int, default=0, help="0 (default) = no limit")
    group.add_argument("--time-budget", type=float, default=0.0,
                       help="seconds for not-yet-executed exploration per channel; 0 (default) = no limit")
    group.add_argument("--harness-link-binary", type=Path, default=None, metavar="PATH",
                       help="the program as the project's own build linked it, compiled with -g.  Its debug "
                            "information names the translation units it was linked from; the harness is built "
                            "from exactly those (needed when the compile database holds several programs)")
    group.add_argument("--harness-build-script", type=Path, default=None, metavar="PATH",
                       help="the profile's harness build recipe; sets HARNESSCREATOR_HARNESS_BUILD_SCRIPT")
    group.add_argument("--harness-attempts", type=int, default=3,
                       help="harness generation attempts per context and channel (default: 3)")


def validate(args: argparse.Namespace) -> None:
    """Reject a run that could not reach the harness stage, before analysis and model work."""

    missing = [name for name, value in (("--coverage-root", args.coverage_root),
                                        ("--coverage-command", args.coverage_command)) if not value]
    if missing:
        raise ValueError(
            "--workflow context (the default) continues from Entries to harnesses and needs "
            + " and ".join(missing) + "; pass them, or select the earlier Action path with --workflow action")
    if not GcovCoverage(args.coverage_root).has_notes():
        raise ValueError(f"{args.coverage_root} holds no .gcno files; build the original program with --coverage first")
    command = shlex.split(args.coverage_command)
    if not command or not Path(command[0]).is_file():
        raise ValueError(f"--coverage-command does not start with an existing program: {args.coverage_command!r}")
    if args.thread_trace_command:
        trace = shlex.split(args.thread_trace_command)
        if not trace or not Path(trace[0]).is_file():
            raise ValueError(f"--thread-trace-command does not start with an existing program: "
                             f"{args.thread_trace_command!r}")
    network = [channel for channel in args.channel if _CHANNEL_RESOURCE[channel] == "network"]
    if (network or not args.channel) and not _port(args):
        raise ValueError("a network channel needs --port (or --scenario-port); "
                         "for a program read through stdin or a file pass --channel stdin / --channel file")


def _port(args: argparse.Namespace) -> int:
    return int(args.port or getattr(args, "scenario_port", None) or 0)


def _host(args: argparse.Namespace) -> str:
    return args.host or getattr(args, "scenario_host", None) or "127.0.0.1"


def _llm_fields(args: argparse.Namespace) -> dict[str, Any]:
    # The stage commands know five effort levels; `run` additionally accepts "ultra".
    return {"provider": args.provider, "model": args.model,
            "effort": "max" if args.effort == "ultra" else args.effort,
            "claude": args.claude, "codex": args.codex, "ollama_url": args.ollama_url}


async def probe_tcp_entries(args: argparse.Namespace, run_dir: Path,
                            contexts: list[dict[str, Any]]) -> dict[str, Any]:
    """Which network Entries the program really reads a TCP connection through, measured.

    The socket type of an Entry is often not in its source (a helper that receives a
    descriptor parameter), and naming it from the API -- recvfrom means datagram -- was wrong
    on 3proxy: it reads every TCP client through def_recvfrom, so its contexts were filed as
    datagram and skipped, and the selected def_recv contexts named a function that never runs
    on Linux (148 proxy requests answered 502 and all were rejected for missing it).  One
    connection to the coverage build settles it: an Entry function that ran is read over TCP,
    whatever it was classified as, and goes first; a network Entry that did not run goes last.
    """
    port = _port(args)
    if "tcp" not in args.channel or not port or not args.coverage_root or not args.coverage_command:
        return {}
    coverage = GcovCoverage(args.coverage_root)
    coverage.reset()
    spec = ProgramSpec(command=shlex.split(args.coverage_command),
                       cwd=Path(args.coverage_cwd or args.coverage_root), delivery="stream",
                       host=_host(args), port=port)
    observation = await ProgramRunner(spec).run([b"\r\n\r\n"])
    try:
        executed = {name for _, name in coverage.collect().functions}
    except CoverageUnavailable as exc:
        stages._log(f"[WORKFLOW] TCP probe: no coverage ({exc}); classification kept")
        return {"error": str(exc)}
    finally:
        coverage.reset()
    ran, idle = [], []
    for ctx in contexts:
        if ctx.get("resource_kind") not in ("network", "unknown"):
            continue
        names = {e.get("entry_function") for e in ctx.get("entries", []) if isinstance(e, dict)} - {None, ""}
        names |= {ctx.get("driver_function")} - {None, ""}
        if not names:
            continue
        if names & executed:
            ctx["tcp_probe"] = "executed"
            if "stream" not in ctx.get("deliveries", []):
                ctx.setdefault("notes", []).append(
                    f"filed as {ctx.get('deliveries')}; its Entry ran on a TCP connection to port {port}")
                ctx["deliveries"] = ["stream"] + [d for d in ctx.get("deliveries", []) if d not in ("datagram", "unknown")]
            ctx["resource_kind"] = "network"
            ran.append(ctx["context_id"])
        else:
            ctx["tcp_probe"] = "not_executed"
            idle.append(ctx["context_id"])
    order = {"executed": 0, None: 1, "not_executed": 2}
    contexts.sort(key=lambda ctx: order.get(ctx.get("tcp_probe"), 1))
    path = run_dir / "contexts" / "contexts.jsonl"
    path.write_text("".join(json.dumps(ctx, ensure_ascii=False) + "\n" for ctx in contexts), encoding="utf-8")
    stages._log(f"[WORKFLOW] TCP probe on port {port} ({observation.exit_status or 'ran'}): Entry ran in "
                f"{ran or 'none'}; did not run in {idle or 'none'}")
    return {"executed": ran, "not_executed": idle}


def select_units(contexts: list[dict[str, Any]], channels: list[str], *,
                 per_channel: int = 0) -> list[tuple[dict[str, Any], str]]:
    """Pick (context, channel) pairs, in priority order, every context of each channel.

    The stages run one at a time and each one starts and stops the program itself, so two
    contexts of the same channel do not have to share a running program and there is no
    reason to drop one.  Measured on LightFTP: three Entries were grouped into three
    distinct ``network``/``stream`` contexts -- the control connection (``ftp_client_thread``)
    and the two data-connection readers (``stor_thread``, ``append_thread``) -- and keeping
    only the first left the bytes an attacker uploads with STOR/APPE covered by no harness
    at all.  ``per_channel`` caps how many are taken (0 = every one), for a budget that
    cannot afford the whole surface.
    """

    if not channels:
        primary = next((ctx for ctx in contexts if ctx.get("resource_kind") == "network"), None)
        if primary is None:
            return []
        channels = [_DELIVERY_CHANNEL[delivery] for delivery in primary.get("deliveries", [])
                    if delivery in _DELIVERY_CHANNEL]
    if "tcp" in channels and "tcp-peer" not in channels:
        # Asking for TCP covers both directions: connections clients open to the program and
        # connections the program opens to servers whose replies it parses.
        channels = [*channels, "tcp-peer"]
    units = []
    for channel in sorted(set(channels), key=_CHANNEL_ORDER.index):
        delivery = _CHANNEL_DELIVERY[channel]
        matching = [ctx for ctx in contexts if delivery in ctx.get("deliveries", [])]
        if per_channel > 0:
            matching = matching[:per_channel]
        units.extend((context, channel) for context in matching)
    return units


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _seed_digest(run_dir: Path, context_id: str, delivery: str) -> dict[str, Any]:
    summary = _read_json(run_dir / "seeds" / f"summary-{context_id}-{delivery}.json") or {}
    keys = ("corpus_seeds", "target_functions", "target_functions_in_this_build", "executed_without_input",
            "executed_with_seeds", "executed_only_with_seeds", "frontier_remaining",
            "frontier_remaining_unattempted", "stopped", "model_infrastructure_error")
    return {key: summary[key] for key in keys if key in summary}


def _harness_digest(run_dir: Path, context_id: str, delivery: str) -> dict[str, Any]:
    summary = _read_json(run_dir / "context-harnesses" / "summary.json") or {}
    for row in summary.get("harnesses", []):
        if row.get("context_id") == context_id and row.get("delivery") == delivery:
            return {key: value for key, value in row.items() if not isinstance(value, (list, dict))}
    return {}


async def run_after_entries(args: argparse.Namespace, run_dir: Path, entry_counts: dict[str, Any]) -> int:
    run_dir = Path(run_dir).resolve()
    llm = _llm_fields(args)
    started = time.time()
    report: dict[str, Any] = {"run_dir": str(run_dir), "entries": entry_counts, "channels": []}

    def save() -> None:
        out = run_dir / "context-workflow"
        out.mkdir(parents=True, exist_ok=True)
        report["elapsed_seconds"] = round(time.time() - started, 1)
        (out / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    async def stage(label: str, call: Any) -> tuple[int | None, str]:
        begin = time.time()
        stages._log(f"[WORKFLOW] {label}: started")
        try:
            code, error = await call, ""
        except Exception as exc:  # a failed stage is reported; later channels still run
            code, error = None, f"{type(exc).__name__}: {exc}"
        stages._log(f"[WORKFLOW] {label}: finished in {time.time() - begin:.0f}s "
                    f"({'exit ' + str(code) if code is not None else error})")
        return code, error

    resources = sorted({_CHANNEL_RESOURCE[channel] for channel in args.channel}) or ["network"]
    code, error = await stage("1 input contexts (group Entries, locate interpreters)", stages._contexts(
        argparse.Namespace(run_dir=run_dir, include_unresolved=args.include_unresolved_entries,
                           classify=True, locate=True, locate_resource=resources, **llm)))
    report["contexts"] = {"exit": code, "error": error}
    if code != 0:
        save()
        return 3
    contexts = stages._load_contexts(run_dir)
    if args.include_unresolved_entries:
        stages._log("[WORKFLOW] unresolved Entries are grouped too (--include-unresolved-entries)")
    report["tcp_probe"] = await probe_tcp_entries(args, run_dir, contexts)
    units = select_units(contexts, list(args.channel), per_channel=args.contexts_per_channel)
    chosen = {context["context_id"] for context, _ in units}
    report["contexts"].update({
        "count": len(contexts),
        "not_run": [{"context_id": ctx["context_id"], "resource_kind": ctx.get("resource_kind"),
                     "deliveries": ctx.get("deliveries", []),
                     "reason": "needs its own program configuration; start it with the seeds command"}
                    for ctx in contexts if ctx["context_id"] not in chosen]})
    if not units:
        report["contexts"]["error"] = "no input context matches the requested channels"
        stages._log(f"[WORKFLOW] {report['contexts']['error']}; see {run_dir}/contexts/contexts.jsonl")
        save()
        return 3
    stages._log("[WORKFLOW] selected: " + ", ".join(f"{ctx['context_id']}/{channel}" for ctx, channel in units))

    for index, (context, channel) in enumerate(units, 1):
        context_id, delivery = context["context_id"], _CHANNEL_DELIVERY[channel]
        row: dict[str, Any] = {"context_id": context_id, "channel": channel, "delivery": delivery}
        report["channels"].append(row)
        code, error = await stage(f"2.{index} normal inputs for {context_id} over {channel} ({index}/{len(units)})",
                                  stages._seeds(argparse.Namespace(
            run_dir=run_dir, context=[context_id], include_unresolved=args.include_unresolved_entries,
            source=Path(args.source).expanduser().resolve(),
            coverage_root=args.coverage_root, program_command=args.coverage_command, cwd=args.coverage_cwd,
            channel=channel, host=_host(args), port=_port(args), env=list(getattr(args, "scenario_env", []) or []),
            startup_timeout=float(getattr(args, "scenario_startup_timeout", 10.0) or 10.0), step_timeout=1.0,
            stop_signal="TERM", skip_generator=False, thread_trace_command=args.thread_trace_command,
            thread_trace_cwd=None, measure_only=False, explore_lines=args.explore_lines,
            generator_turns=args.generator_turns, frontier_turns=args.frontier_turns,
            max_frontier_targets=args.max_frontier_targets, time_budget=args.time_budget, **llm)))
        row["seeds"] = {"exit": code, "error": error, **_seed_digest(run_dir, context_id, delivery)}
        save()
        if not row["seeds"].get("corpus_seeds"):
            row["harness"] = {"exit": None, "error": "skipped: no verified normal input for this channel"}
            stages._log(f"[WORKFLOW] 3.{index} harness for {context_id} over {channel}: skipped, no verified input")
            save()
            continue
        if getattr(args, "harness_build_script", None):
            os.environ["HARNESSCREATOR_HARNESS_BUILD_SCRIPT"] = str(Path(args.harness_build_script).resolve())
        code, error = await stage(f"3.{index} harness for {context_id} over {channel} ({index}/{len(units)})",
                                  stages._harness(argparse.Namespace(
            run_dir=run_dir, context=[context_id], delivery=delivery, source=None, compile_database=None,
            target_binary=getattr(args, "harness_link_binary", None), attempts=args.harness_attempts, no_build=False, legacy_generator=False,
            server_args=None, host=_host(args), port=_port(args), reading_turns=30, **llm)))
        row["harness"] = {"exit": code, "error": error, **_harness_digest(run_dir, context_id, delivery)}
        save()

    save()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if all(row.get("harness", {}).get("exit") == 0 for row in report["channels"]) else 3
