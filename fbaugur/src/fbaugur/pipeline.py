"""One command from source to findings: generate the harness, then scan it.

Stage 1 runs `harnesscreator run --workflow context`, which finds the input entries,
groups them into input contexts, creates and verifies normal inputs on a coverage build
and generates one measured harness per channel.  Stage 2 runs this package's scan on
that output.  The wall clock is one budget shared by both stages.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from .config import PROVIDER_MODELS

_ARTIFACTS = re.compile(r"artifacts=(\S+)")


def add_arguments(parser) -> None:
    parser.add_argument("source", type=Path, help="the program's source root")
    parser.add_argument("--name", help="program name (default: the source directory's name)")
    parser.add_argument("--output", type=Path, default=Path("fbaugur-runs"),
                        help="where both stages write their run directories")
    # -- stage 1: harness generation
    harness = parser.add_argument_group("harness generation (stage 1)")
    harness.add_argument("--coverage-root", type=Path, required=True,
                         help="build directory of the program compiled with --coverage (.gcno files)")
    harness.add_argument("--coverage-command", required=True,
                         help="command that starts the coverage build, split without a shell")
    harness.add_argument("--coverage-cwd", type=Path, help="working directory for --coverage-command")
    harness.add_argument("--thread-trace-command",
                         help="command of a second build linked with the thread-trace hook")
    harness.add_argument("--port", type=int, default=None,
                         help="port the program listens on (required for --channel tcp/udp; a program read "
                              "through --channel stdin/file has none)")
    harness.add_argument("--host", default="127.0.0.1")
    harness.add_argument("--channel", action="append", default=[], choices=["tcp", "udp", "stdin", "file"],
                         help="channel to produce a harness for (repeatable; default: every delivery "
                              "of the highest-priority network context)")
    harness.add_argument("--analysis-compile-database", type=Path,
                         help="compile_commands.json of the program's build")
    harness.add_argument("--harness-link-binary", type=Path,
                         help="the program as its own build linked it (with -g); the harness is built from "
                              "the translation units its debug information names")
    harness.add_argument("--harness-build-script", type=Path,
                         help="the profile's harness build recipe (SRC HARNESS OUT, OSS-Fuzz style CC/CFLAGS/"
                              "LIB_FUZZING_ENGINE); every harness, invariant and MSan build runs it instead of "
                              "reconstructing the program's link")
    harness.add_argument("--require-fuzz-introspector", action="store_true",
                         help="require Fuzz Introspector (default: allow source indexing, which is "
                              "enough for a small program)")
    harness.add_argument("--svf", action="store_true",
                         help="resolve function-pointer targets with SVF (default: off)")
    harness.add_argument("--harness-max-minutes", type=float, default=0.0,
                         help="cap for stage 1; 0 (default) = half the whole budget")
    from .cli import HC_SRC_DEFAULT
    harness.add_argument("--harnesscreator", type=Path, default=HC_SRC_DEFAULT.parent,
                         help=f"HarnessCreator checkout (default: {HC_SRC_DEFAULT.parent})")
    harness.add_argument("--skip-harness", type=Path, metavar="RUN",
                         help="reuse this HarnessCreator run instead of generating one")
    harness.add_argument("--only-verified-entries", action="store_true",
                         help="group only entries the Entry Verifier could fully prove. The default also "
                              "uses UNRESOLVED ones: unresolved means the verifier could not establish "
                              "every condition (build target, exposure, indirect-call targets), not that "
                              "the input is not external, and dropping them loses whole channels")


def harnesscreator_argv(args, run_root: Path) -> list[str]:
    argv = [args.python, "-m", "harnesscreator.cli", "run", str(args.source.resolve()),
            "--name", args.name or args.source.resolve().name,
            "--output", str(run_root),
            "--provider", args.provider, "--workers", str(max(1, args.concurrency)),
            "--coverage-root", str(args.coverage_root.resolve()),
            "--coverage-command", args.coverage_command,
            "--host", args.host]
    if args.port:
        argv += ["--port", str(args.port)]
    if args.coverage_cwd:
        argv += ["--coverage-cwd", str(args.coverage_cwd.resolve())]
    if args.thread_trace_command:
        argv += ["--thread-trace-command", args.thread_trace_command]
    for channel in args.channel:
        argv += ["--channel", channel]
    if args.analysis_compile_database:
        argv += ["--analysis-compile-database", str(args.analysis_compile_database.resolve())]
    if getattr(args, "harness_link_binary", None):
        argv += ["--harness-link-binary", str(args.harness_link_binary.resolve())]
    if not args.only_verified_entries:
        argv += ["--include-unresolved-entries"]
    if args.diff:                          # delta: Entries only where data reaches the change
        argv += ["--diff", str(args.diff.expanduser().resolve())]
    argv += [] if args.require_fuzz_introspector else ["--allow-source-analysis"]
    argv += ["--svf"] if args.svf else ["--no-svf"]
    if args.provider == "claude":
        if args.model_t3:                  # the Entry stage is the cheapest place to save
            argv += ["--model", args.model_t3]
    else:
        # Tier mapping of HarnessCreator's roles: candidates = fast, verifiers = reasoning,
        # harness generation = main coding model.
        tiers = dict(PROVIDER_MODELS[args.provider])
        tiers.update({k: v for k, v in (("1", args.model_t1), ("2", args.model_t2), ("3", args.model_t3)) if v})
        argv += ["--strong-model", tiers["1"], "--coding-model", tiers["2"], "--candidate-model", tiers["3"],
                 "--model", tiers["3"]]
        argv += ["--ollama-url", args.ollama_url] if args.provider == "ollama" else ["--codex", args.codex, "--daybreak"]
    return argv


async def generate_harness(args, run_root: Path, budget: float, emit, deadline_file: Path | None = None) -> Path | None:
    """Run stage 1, streaming its log; returns the HarnessCreator run directory."""
    argv = harnesscreator_argv(args, run_root)
    log_path = run_root / "harnesscreator.log"
    run_root.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PYTHONPATH=str((args.harnesscreator / "src").resolve()))
    # Entry answers this session already paid for in an earlier attempt (resumed after a cap, a usage
    # limit or a crash) are reused for byte-identical questions instead of asking the model again (llm/base.py).
    # Only this session's own earlier runs (its --output); a new session always asks afresh.
    logs = sorted(str(p) for p in args.output.expanduser().glob("*/harness/*/trajectories/llm.jsonl"))
    if logs:
        env["HARNESSCREATOR_LLM_REPLAY"] = ":".join(logs)
        emit(f"[stage 1] earlier Entry answers available for reuse from {len(logs)} run(s)")
    if args.native_extra_cflags:
        env["HARNESSCREATOR_NATIVE_EXTRA_CFLAGS"] = args.native_extra_cflags
    emit(f"[stage 1] harness generation, up to {budget / 60:.0f} min")
    emit("[stage 1] " + " ".join(argv[2:]))
    started = time.time()
    process = await asyncio.create_subprocess_exec(
        *argv, cwd=str(args.harnesscreator.resolve()), env=env,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, limit=16 * 1024 * 1024)
    artifacts: str | None = None
    last_line = time.time()
    with log_path.open("w", encoding="utf-8") as log:
        async def pump() -> None:
            nonlocal artifacts, last_line
            while True:
                line = await process.stdout.readline()
                if not line:
                    return
                text = line.decode("utf-8", errors="replace").rstrip()
                log.write(text + "\n")
                log.flush()
                last_line = time.time()
                match = _ARTIFACTS.search(text)
                if match:
                    artifacts = match.group(1)
                # Every line is shown: a stage of this length must never look stuck.
                if text.strip():
                    emit("  " + text[:220])

        async def heartbeat() -> None:
            """Say what is still running when HarnessCreator goes quiet for a while; and stop stage 1
            when the whole pipeline's end time, changed by the user, has come."""
            from . import deadline as live
            while True:
                await asyncio.sleep(30)
                if deadline_file is not None and time.time() >= live.read(deadline_file, float("inf")):
                    emit("[stage 1] the time limit was changed and has passed; stopping harness generation")
                    process.kill()
                    return
                quiet = time.time() - last_line
                if quiet >= 30:
                    emit(f"  ... still running, no output for {quiet:.0f}s "
                         f"({(time.time() - started) / 60:.0f} min into stage 1 of {budget / 60:.0f} min)")

        beat = asyncio.create_task(heartbeat())
        try:
            await asyncio.wait_for(pump(), timeout=budget)
            await process.wait()
        except asyncio.TimeoutError:
            emit(f"[stage 1] budget of {budget / 60:.0f} min reached; stopping harness generation")
            process.kill()
            await process.wait()
        finally:
            beat.cancel()
    emit(f"[stage 1] finished in {(time.time() - started) / 60:.1f} min (exit {process.returncode})")
    # The run directory is reported as `artifacts=...`; fall back to the newest one.
    run_dir = Path(artifacts) if artifacts else None
    if run_dir is None or not run_dir.is_dir():
        candidates = sorted((p for p in run_root.iterdir() if p.is_dir() and (p / "project.json").is_file()),
                            key=lambda p: p.stat().st_mtime)
        run_dir = candidates[-1] if candidates else None
    if run_dir is None:
        emit("[stage 1] produced no run directory; see " + str(log_path))
        return None
    emit(f"[stage 1] run directory: {run_dir}")
    return run_dir


def built_harnesses(run_dir: Path) -> list[tuple[str, str]]:
    """(context id, delivery) pairs that have a built harness."""
    base = run_dir / "context-harnesses"
    found = []
    if base.is_dir():
        for directory in sorted(base.iterdir()):
            if not directory.is_dir() or "-" not in directory.name:
                continue
            context, _, delivery = directory.name.rpartition("-")
            if delivery in ("stream", "datagram", "peer_stream") and any(directory.glob("attempt-*/build/hc-native-fuzzer")):
                found.append((context, delivery))
    # Priority order, as stage 1 ranked the contexts (contexts.jsonl), not directory order: when
    # the budget runs short the highest-priority context must be the one already analysed.  On
    # LightFTP directory order put the data-connection context ahead of the control connection.
    rank: dict[str, int] = {}
    path = run_dir / "contexts" / "contexts.jsonl"
    if path.is_file():
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
            if line.strip():
                rank.setdefault(json.loads(line).get("context_id", ""), index)
    found.sort(key=lambda pair: (rank.get(pair[0], len(rank)), pair[1]))
    return found


def report_stage1(run_dir: Path, emit) -> list[tuple[str, str]]:
    def rows(name: str) -> list[dict[str, Any]]:
        path = run_dir / name
        if not path.is_file():
            return []
        with path.open(encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    verified = rows("entries/verified.jsonl")
    contexts = rows("contexts/contexts.jsonl")
    emit(f"[stage 1] input entries verified: {len(verified)}; input contexts: {len(contexts)}")
    seeds = sorted((run_dir / "seeds").glob("summary-*.json"))
    for path in seeds:
        summary = json.loads(path.read_text(encoding="utf-8"))
        emit(f"  seeds {summary.get('context_id')}/{summary.get('delivery')}: "
             f"{summary.get('corpus_seeds')} verified normal inputs, "
             f"{summary.get('executed_with_seeds')} of {summary.get('target_functions_in_this_build')} "
             "target functions executed")
    harnesses = built_harnesses(run_dir)
    summary_path = run_dir / "context-harnesses" / "summary.json"
    if summary_path.is_file():
        for row in json.loads(summary_path.read_text(encoding="utf-8")).get("harnesses", []):
            emit(f"  harness {row.get('context_id')}/{row.get('delivery')}: {row.get('status')} "
                 f"({row.get('executions_per_second')} exec/s)")
    emit(f"[stage 1] built harnesses: {harnesses or 'none'}")
    return harnesses


FIRST_PASS_FUZZ_MINUTES = 60.0   # fuzzing after analysis for every context but the last


async def run(args, emit) -> int:
    if getattr(args, "harness_build_script", None):
        # Read by harnesscreator's native builder in stage 1 and in every stage-2 rebuild.
        os.environ["HARNESSCREATOR_HARNESS_BUILD_SCRIPT"] = str(args.harness_build_script.resolve())
    from .config import PROVIDER_MODELS, RunConfig
    from .orchestrator import Run

    total = args.max_hours * 3600
    deadline = time.time() + total
    run_root = args.output.expanduser().resolve() / f"{time.strftime('%Y%m%d-%H%M%S')}-pipeline"
    run_root.mkdir(parents=True, exist_ok=True)
    emit(f"pipeline directory: {run_root} | whole budget: {args.max_hours} h")
    from . import deadline as live
    deadline_file = run_root / "deadline"
    live.write(deadline_file, deadline)

    if args.skip_harness:
        hc_run = args.skip_harness.expanduser().resolve()
        emit(f"[stage 1] skipped; reusing {hc_run}")
    else:
        share = args.harness_max_minutes * 60 if args.harness_max_minutes else total / 2
        hc_run = await generate_harness(args, run_root / "harness", min(share, max(60.0, deadline - time.time())),
                                        emit, deadline_file=deadline_file)
        if hc_run is None:
            return 3
    harnesses = report_stage1(hc_run, emit)
    if not harnesses:
        emit("no built harness, so there is nothing to analyse; stage 1's log holds the reason")
        return 3

    from .agent import check_backend
    problem = check_backend(RunConfig(run_dir=".", hc_run=".", context_id="", deliveries=[],
                                      claude_executable=args.claude, provider=args.provider,
                                      codex_executable=args.codex, ollama_url=args.ollama_url))
    if problem:
        emit(problem)
        return 3
    # Every built context is analysed, not just the first.  A channel can hold several
    # distinct contexts -- on LightFTP the tcp/stream contexts were the control connection
    # and the two data-connection readers -- and each is a separate input path, so analysing
    # only the first would throw away harnesses stage 1 just spent its budget building.
    # One Run handles one context, so they go one after another, each with an equal share of
    # what is left.  A context that finishes early hands the rest to the ones still to come.
    grouped: list[tuple[str, list[str]]] = []
    for context, delivery in harnesses:
        for existing, deliveries in grouped:
            if existing == context:
                deliveries.append(delivery)
                break
        else:
            grouped.append((context, [delivery]))
    emit(f"[stage 2] {len(grouped)} context(s) to analyse: "
         + ", ".join(f"{ctx}{sorted(d)}" for ctx, d in grouped))
    summaries: list[dict[str, Any]] = []
    exit_code = 1
    analysed: list[str] = []         # scan dirs already done: findings there are not new
    for index, (context, deliveries) in enumerate(grouped):
        deadline = live.read(deadline_file, deadline)
        remaining = deadline - time.time()
        if remaining < 120:
            emit(f"the whole budget is spent; {len(grouped) - index} context(s) not analysed. "
                 f"The harnesses are in place -- run `fbaugur scan` on them when ready")
            break
        share = remaining / (len(grouped) - index)
        # Analysis (SPs, PoVs, invariants) of every context comes before long fuzzing of any one:
        # an equal share let the first context fuzz for days after its analysis ended while the
        # context that held the bug waited (LightFTP 954454b: 10 days on the STOR data
        # connection before the control connection, where writelogentry overflows, was analysed).
        drain = args.fuzz_after_drain_minutes
        if not drain and index < len(grouped) - 1:
            drain = min(FIRST_PASS_FUZZ_MINUTES, share / 60)
        emit(f"[stage 2] scan {index + 1}/{len(grouped)}: {context} {sorted(deliveries)}, "
             f"{share / 60:.0f} min of the {remaining / 60:.0f} min left"
             + (f"; fuzzing after analysis capped at {drain:.0f} min so the next context is analysed"
                if drain and not args.fuzz_after_drain_minutes else ""))
        scan_dir = run_root / ("scan" if len(grouped) == 1 else f"scan-{context}")
        scan_dir.mkdir(parents=True, exist_ok=True)
        cfg = RunConfig(
            run_dir=str(scan_dir), hc_run=str(hc_run), context_id=context, deliveries=sorted(deliveries),
            sanitizer=args.sanitizer, python=args.python, claude_executable=args.claude,
            max_hours=share / 3600, fuzz_after_drain_minutes=drain,
            claude_concurrency=args.concurrency, sp_generator_agents=args.sp_agents,
            verifier_agents=args.verify_agents, pov_agents=args.pov_agents,
            max_function_analyses=args.max_functions, sp_fuzz_seconds=args.sp_fuzz_seconds,
            rebuild_min_interval_seconds=args.rebuild_interval, skip_threat_model=args.skip_threat_model,
            native_extra_cflags=args.native_extra_cflags, msan=not args.no_msan,
            diff_path=str(args.diff.expanduser().resolve()) if args.diff else "",
            daemon_command=args.daemon_command or "", daemon_msan_command=args.daemon_msan_command or "",
            daemon_plain_command=args.daemon_plain_command or "",
            daemon_cwd=args.daemon_cwd, daemon_port=args.daemon_port, product_version=args.product_version,
            prior_scans=list(analysed))
        cfg.deadline_file, cfg.contexts_after = str(deadline_file), len(grouped) - index - 1
        cfg.provider, cfg.codex_executable, cfg.ollama_url = args.provider, args.codex, args.ollama_url
        cfg.models = dict(PROVIDER_MODELS[args.provider])
        for tier, value in (("1", args.model_t1), ("2", args.model_t2), ("3", args.model_t3)):
            if value:
                cfg.models[tier] = value
        for item in args.max_turns:
            role, _, number = item.partition("=")
            cfg.max_turns[role] = int(number)
        cfg.save()
        scan = Run(scan_dir, cfg, harnesscreator_src=(args.harnesscreator / "src").resolve(), emit=emit)
        summary = await scan.execute()
        summary["context_id"] = context
        summaries.append(summary)
        analysed.append(str(scan_dir))
        confirmed = sum(summary["crashes"].get(k, 0) for k in ("confirmed", "validated", "reported", "needs_review"))
        if summary["terminal_error"]:
            exit_code = 3
        elif confirmed or summary["suspicious_points"]:
            exit_code = min(exit_code, 0)
        emit(f"[stage 2] {context} done: {confirmed} reported crash(es), "
             f"{sum(summary['suspicious_points'].values())} suspicious point(s)")
    if not summaries:
        return 3
    report = {"harnesscreator_run": str(hc_run), "pipeline_dir": str(run_root), "scans": summaries}
    (run_root / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                                            encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return exit_code
