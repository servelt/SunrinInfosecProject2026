from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import shlex
import sys
import time
from pathlib import Path
from typing import Any

from ..analysis.graph import GraphStore
from ..models import AnalysisBundle, CallEdge, FunctionMetadata
from .agents import ROLES, ContextLocatorAgent, EntryChannelClassifier, EntryPeerAgent
from .builder import CallGraph, api_resource, build_contexts, render_table, write_contexts

_DEFAULT_MODELS = {"claude": "claude-haiku-5-5", "claude-api": "claude-haiku-5-5",
                   "codex": "gpt-5.6-sol", "ollama": "glm-5.3:cloud"}
# tcp-peer: a TCP connection the program opens itself; the harness plays the server it contacts.
_CHANNEL_DELIVERY = {"tcp": "stream", "udp": "datagram", "tcp-peer": "peer_stream", "stdin": "stdin", "file": "file"}


def _log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


def load_graph(run_dir: Path) -> GraphStore:
    names = {field.name for field in dataclasses.fields(FunctionMetadata)}
    edge_names = {field.name for field in dataclasses.fields(CallEdge)}
    functions, edges = {}, []
    with (run_dir / "analysis" / "functions.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                functions[row["function_id"]] = FunctionMetadata(**{k: v for k, v in row.items() if k in names})
    with (run_dir / "analysis" / "edges.jsonl").open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                row = json.loads(line)
                edges.append(CallEdge(**{k: v for k, v in row.items() if k in edge_names}))
    return GraphStore(AnalysisBundle(functions=functions, edges=edges))


def _add_llm_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--provider", choices=["claude", "claude-api", "codex", "ollama"], default="claude")
    parser.add_argument("--model", help="model for every role of this stage (default depends on the provider)")
    parser.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max"])
    parser.add_argument("--claude", default="claude", help="Claude Code executable for --provider claude")
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--ollama-url", default="http://127.0.0.1:11434")


async def make_llm(args: argparse.Namespace, run_dir: Path, extra_roles: tuple[str, ...] = ()) -> Any:
    from ..llm.base import RecordingLLM
    model = args.model or _DEFAULT_MODELS[args.provider]
    roles = {role: model for role in ROLES + extra_roles}
    efforts = {role: args.effort for role in roles}
    event = lambda message: _log(f"[LLM] {message}")
    if args.provider == "claude":
        from ..llm.claude_code import ClaudeCodeProvider
        base = ClaudeCodeProvider(role_models=roles, role_efforts=efforts, executable=args.claude, on_event=event)
        await base.preflight()
    elif args.provider == "claude-api":
        from ..llm.claude import ClaudeProvider
        base = ClaudeProvider(role_models=roles, role_efforts=efforts, on_event=event)
        await base.preflight()
    elif args.provider == "ollama":
        from ..llm.ollama import OllamaProvider
        base = OllamaProvider(role_models=roles, role_efforts=efforts, url=args.ollama_url)
    else:
        from ..llm.codex_app_server import CodexAppServer
        base = CodexAppServer(cwd=run_dir, model=model, role_models=roles, daybreak=True,
                              effort="high" if args.effort == "max" else args.effort,
                              executable=args.codex, on_event=event)
    trajectory = run_dir / "trajectories" / "contexts-llm.jsonl"
    trajectory.parent.mkdir(parents=True, exist_ok=True)

    def record(row: dict[str, Any]) -> None:
        with trajectory.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
    return RecordingLLM(base, on_record=record)


def add_subparsers(subparsers: Any) -> None:
    contexts = subparsers.add_parser(
        "contexts", help="group verified Entries of a run into input contexts (no model calls unless --locate)")
    contexts.add_argument("run_dir", type=Path)
    contexts.add_argument("--include-unresolved", action="store_true",
                          help="also group Entries the verifier left UNRESOLVED")
    contexts.add_argument("--classify", action="store_true",
                          help="have the model choose each Entry's resource kind and delivery from a fixed list "
                               "(recorded in contexts/classification.jsonl) instead of searching the Entry "
                               "description for keywords")
    contexts.add_argument("--locate", action="store_true",
                          help="ask the model for the interpreting function of Entries that have none on record")
    contexts.add_argument("--locate-resource", action="append", default=[],
                          help="with --locate, only ask for Entries of this resource kind (repeatable; default: all)")
    _add_llm_arguments(contexts)

    seeds = subparsers.add_parser(
        "seeds", help="generate seeds for an input context and verify them on the coverage-built original program")
    seeds.add_argument("run_dir", type=Path)
    seeds.add_argument("--context", action="append", default=[],
                       help="context id (repeatable); default: the highest-priority context with the chosen delivery")
    seeds.add_argument("--source", type=Path, required=True, help="original source root (for tests, clients, docs)")
    seeds.add_argument("--coverage-root", type=Path, required=True,
                       help="build tree of the original program compiled with --coverage (holds .gcno/.gcda)")
    # dest must not be "command": that name holds the selected subcommand.
    seeds.add_argument("--command", dest="program_command", required=True,
                       help="command that starts the coverage-built original program; {input_file} for file delivery")
    seeds.add_argument("--cwd", type=Path, help="working directory for the command (default: --coverage-root)")
    seeds.add_argument("--channel", choices=sorted(_CHANNEL_DELIVERY), required=True,
                       help="how seeds are delivered; selects the context's matching delivery")
    seeds.add_argument("--host", default="127.0.0.1")
    seeds.add_argument("--port", type=int, default=0)
    seeds.add_argument("--env", action="append", default=[], metavar="NAME=VALUE")
    seeds.add_argument("--startup-timeout", type=float, default=10.0)
    seeds.add_argument("--step-timeout", type=float, default=1.0)
    seeds.add_argument("--stop-signal", default="TERM", help="signal that makes the program exit normally (default TERM)")
    seeds.add_argument("--skip-generator", action="store_true",
                       help="do not ask for new seeds: measure the seeds already recorded again, then explore the frontier")
    seeds.add_argument("--thread-trace-command",
                       help="command starting a build of the original compiled with -finstrument-functions and the "
                            "thread-trace hook; records which thread ran which function for every accepted seed")
    seeds.add_argument("--thread-trace-cwd", type=Path, help="working directory for --thread-trace-command")
    seeds.add_argument("--measure-only", action="store_true",
                       help="no model calls: measure the recorded seeds again (paced and whole-input delivery)")
    seeds.add_argument("--explore-lines", action="store_true",
                       help="after the function frontier, also ask for inputs that execute the unexecuted lines of "
                            "functions already executed (state-dependent branches that call no new function)")
    seeds.add_argument("--generator-turns", type=int, default=40, help="resource limit for the generator session")
    seeds.add_argument("--frontier-turns", type=int, default=6, help="resource limit per not-yet-executed function")
    seeds.add_argument("--max-frontier-targets", type=int, default=0, help="0 = no limit")
    seeds.add_argument("--time-budget", type=float, default=0.0, help="seconds for frontier exploration; 0 = no limit")
    _add_llm_arguments(seeds)

    hook = subparsers.add_parser(
        "thread-trace-hook", help="compile the hook object that records which thread executed which function")
    hook.add_argument("output", type=Path)

    try:
        from .harness import add_harness_arguments
    except ImportError:
        return
    harness = subparsers.add_parser(
        "context-harness", help="generate and build a harness per input context from its verified seeds")
    harness.add_argument("run_dir", type=Path)
    add_harness_arguments(harness)
    from .measured_harness import add_measured_arguments
    add_measured_arguments(harness)
    _add_llm_arguments(harness)


def _load_contexts(run_dir: Path) -> list[dict[str, Any]]:
    path = run_dir / "contexts" / "contexts.jsonl"
    if not path.is_file():
        raise FileNotFoundError(f"{path} not found; run `harnesscreator contexts {run_dir}` first")
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def _entry_rows(run_dir: Path, include_unresolved: bool) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for name in ("verified", "unresolved") if include_unresolved else ("verified",):
        path = run_dir / "entries" / f"{name}.jsonl"
        if path.is_file():
            with path.open(encoding="utf-8") as handle:
                rows.extend(json.loads(line) for line in handle if line.strip())
    return rows


async def _classify(args: argparse.Namespace, run_dir: Path) -> None:
    """Record an enumerated resource kind and delivery for every Entry that lacks one."""

    out = run_dir / "contexts" / "classification.jsonl"
    done = set()
    if out.is_file():
        with out.open(encoding="utf-8") as handle:
            done = {json.loads(line)["entry_id"] for line in handle if line.strip()}
    graph = load_graph(run_dir)
    pending = [entry for entry in _entry_rows(run_dir, args.include_unresolved)
               if entry["entry_id"] not in done and not api_resource(entry.get("source_api", ""))
               and entry.get("entry_function_id") in graph.bundle.functions]
    if not pending:
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    llm = await make_llm(args, run_dir)
    try:
        agent = EntryChannelClassifier(llm, graph)
        for entry in pending:
            name = f"{graph.bundle.functions[entry['entry_function_id']].name}::{entry.get('source_api')}"
            try:
                row = await agent.classify(entry)
            except Exception as exc:  # the keyword table is used for this Entry and the output says so
                _log(f"[CLASSIFY] {name} failed: {type(exc).__name__}: {exc}")
                continue
            _log(f"[CLASSIFY] {name} -> {row['resource_kind']}/{row['delivery']}")
            with out.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    finally:
        await llm.close()


async def _peers(args: argparse.Namespace, run_dir: Path) -> None:
    """Record, for every socket stream Entry, which peers' bytes reach it (accepted / initiated)."""

    from .builder import resolve_channel
    out = run_dir / "contexts" / "peers.jsonl"
    done = set()
    if out.is_file():
        with out.open(encoding="utf-8") as handle:
            done = {json.loads(line)["entry_id"] for line in handle if line.strip()}
    chosen = {}
    path = run_dir / "contexts" / "classification.jsonl"
    if path.is_file():
        with path.open(encoding="utf-8") as handle:
            chosen = {row["entry_id"]: row for row in map(json.loads, filter(str.strip, handle))}
    graph = load_graph(run_dir)
    pending = []
    for entry in _entry_rows(run_dir, args.include_unresolved):
        if entry["entry_id"] in done or entry.get("entry_function_id") not in graph.bundle.functions:
            continue
        resource, delivery, _ = resolve_channel(entry, chosen.get(entry["entry_id"]))
        if resource in ("network", "local_ipc") and delivery == "stream":
            pending.append(entry)
    if not pending:
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    llm = await make_llm(args, run_dir)
    try:
        agent = EntryPeerAgent(llm, graph)
        for entry in pending:
            name = f"{graph.bundle.functions[entry['entry_function_id']].name}::{entry.get('source_api')}"
            try:
                row = await agent.find(entry)
            except Exception as exc:  # the Entry keeps the single peer the Entry Verifier traced
                _log(f"[PEERS] {name} failed: {type(exc).__name__}: {exc}")
                continue
            _log(f"[PEERS] {name} -> " + (", ".join(f"{p['role']} {p['descriptor']}" for p in row["peers"]) or "none"))
            with out.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    finally:
        await llm.close()


async def _contexts(args: argparse.Namespace) -> int:
    run_dir = args.run_dir.resolve()
    if getattr(args, "classify", False):
        await _classify(args, run_dir)
        await _peers(args, run_dir)
    result = build_contexts(run_dir, include_unresolved=args.include_unresolved)
    if args.locate:
        unknown = [member for ctx in result["contexts"] for member in ctx.entries
                   if member.interpreter_source == "entry_function"
                   and (not args.locate_resource or member.resource_kind in args.locate_resource)]
        if unknown:
            graph, callgraph = load_graph(run_dir), CallGraph.from_run(run_dir)
            llm = await make_llm(args, run_dir)
            try:
                agent = ContextLocatorAgent(llm, graph, callgraph)
                entries = {}
                for name in ("verified", "unresolved"):
                    path = run_dir / "entries" / f"{name}.jsonl"
                    if path.is_file():
                        with path.open(encoding="utf-8") as handle:
                            entries.update({row["entry_id"]: row for row in map(json.loads, filter(str.strip, handle))})
                out = run_dir / "contexts"
                out.mkdir(parents=True, exist_ok=True)
                for member in unknown:
                    try:
                        located = await agent.locate(entries[member.entry_id])
                    except Exception as exc:  # one failed model session must not end the stage
                        _log(f"[LOCATE] {member.entry_function}::{member.source_api} failed: "
                             f"{type(exc).__name__}: {exc}")
                        continue
                    _log(f"[LOCATE] {member.entry_function}::{member.source_api} -> "
                         f"{[graph.bundle.functions[f].name for f in located['interpreter_function_ids']] or located['ended']}")
                    with (out / "locator.jsonl").open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps(located, ensure_ascii=False, sort_keys=True) + "\n")
            finally:
                await llm.close()
            result = build_contexts(run_dir, include_unresolved=args.include_unresolved)
    out = write_contexts(run_dir, result)
    print(render_table(result))
    print(f"written: {out}")
    return 0


async def _seeds(args: argparse.Namespace) -> int:
    import signal

    from .coverage import GcovCoverage
    from .execution import ProgramRunner, ProgramSpec
    from .workflow import SeedWorkflow

    run_dir = args.run_dir.resolve()
    delivery = _CHANNEL_DELIVERY[args.channel]
    contexts = _load_contexts(run_dir)
    wanted = set(args.context)
    matching = [ctx for ctx in contexts if delivery in ctx.get("deliveries", [])]
    if wanted:
        selected = [ctx for ctx in matching if ctx["context_id"] in wanted]
    else:
        # One command starts one program configuration, so by default only the
        # highest-priority context with this delivery is run; name others with --context.
        selected = matching[:1]
    if not selected:
        raise ValueError(f"no selected context has the {delivery!r} delivery; see {run_dir}/contexts/contexts.jsonl")
    for ctx in selected:
        _log(f"[SEED] context {ctx['context_id']} ({ctx['resource_kind']}, driver={ctx.get('driver_function') or '-'}, "
             f"targets={len(ctx.get('target_function_ids', []))})")
    coverage = GcovCoverage(args.coverage_root)
    if not coverage.has_notes():
        raise ValueError(f"{args.coverage_root} holds no .gcno files; build the original program with --coverage first")
    environment = dict(item.split("=", 1) for item in args.env)
    spec = ProgramSpec(
        command=shlex.split(args.program_command), cwd=(args.cwd or args.coverage_root).resolve(), delivery=delivery,
        host=args.host, port=args.port, environment=environment, startup_timeout=args.startup_timeout,
        step_timeout=args.step_timeout, stop_signal=getattr(signal, "SIG" + args.stop_signal.upper().removeprefix("SIG")))
    artifacts_path = run_dir / "analysis" / "project-usage-artifacts.json"
    artifacts = []
    if artifacts_path.is_file():
        artifacts = sorted({item["path"] for item in json.loads(artifacts_path.read_text(encoding="utf-8")).get("artifacts", [])
                            if (args.source / item["path"]).is_file()})
    graph, callgraph = load_graph(run_dir), CallGraph.from_run(run_dir)
    thread_trace = None
    if args.thread_trace_command:
        import dataclasses as _dc
        import tempfile

        from .thread_trace import SymbolTable
        trace_argv = shlex.split(args.thread_trace_command)
        trace_cwd = (args.thread_trace_cwd or Path(trace_argv[0]).parent).resolve()
        trace_file = Path(tempfile.mkdtemp(prefix="hc-thread-trace-")) / "trace.txt"
        trace_spec = _dc.replace(spec, command=trace_argv, cwd=trace_cwd,
                                 environment={**environment, "HC_THREAD_TRACE": str(trace_file)})
        thread_trace = (ProgramRunner(trace_spec), trace_file, SymbolTable(Path(trace_argv[0])))
    llm = None if args.measure_only else await make_llm(args, run_dir)
    summaries = []
    try:
        for context in selected:
            # Recorded so the harness stage can start the program the same way.
            spec_dir = run_dir / "seeds"
            spec_dir.mkdir(parents=True, exist_ok=True)
            (spec_dir / f"run-spec-{context['context_id']}-{delivery}.json").write_text(json.dumps({
                "command": spec.command, "cwd": str(spec.cwd), "delivery": delivery, "host": spec.host,
                "port": spec.port, "environment": spec.environment}, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8")
            workflow = SeedWorkflow(
                run_dir=run_dir, context=context, delivery=delivery, graph=graph, callgraph=callgraph, llm=llm,
                runner=ProgramRunner(spec), coverage=coverage, source_root=args.source.resolve(),
                artifact_paths=artifacts, generator_turns=args.generator_turns, frontier_turns=args.frontier_turns,
                max_frontier_targets=args.max_frontier_targets, time_budget_seconds=args.time_budget,
                skip_generator=args.skip_generator or args.measure_only, skip_frontier=args.measure_only,
                explore_lines=args.explore_lines and not args.measure_only, thread_trace=thread_trace, emit=_log)
            summaries.append(await workflow.run())
    finally:
        if llm is not None:
            await llm.close()
    print(json.dumps(summaries, ensure_ascii=False, indent=2))
    return 0


async def _harness(args: argparse.Namespace) -> int:
    from .harness import run_context_harness
    from .measured_harness import run_measured_harness
    args.run_dir = args.run_dir.resolve()
    llm = await make_llm(args, args.run_dir, extra_roles=("harness_generator", "harness_verifier"))
    try:
        if not args.legacy_generator:
            return await run_measured_harness(args, llm)
        return await run_context_harness(args, llm)
    finally:
        await llm.close()


def dispatch(args: argparse.Namespace) -> int | None:
    """Run a contexts-stage command; returns None when the command is not ours."""

    if args.command == "thread-trace-hook":
        from .thread_trace import BUILD_HELP, build_hook_object
        print(build_hook_object(args.output))
        print(BUILD_HELP)
        return 0
    handlers = {"contexts": _contexts, "seeds": _seeds, "context-harness": _harness}
    handler = handlers.get(args.command)
    return None if handler is None else asyncio.run(handler(args))
