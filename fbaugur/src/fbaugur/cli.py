"""fbaugur command line.

    fbaugur scan   HC_RUN --context CTX [--delivery stream --delivery datagram]
    fbaugur report RUN_DIR
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import sys
import time
from pathlib import Path

from .config import PROVIDER_MODELS, DEFAULT_MAX_TURNS, RunConfig
from .store import Store

def _harnesscreator_default() -> Path:
    """Find the HarnessCreator checkout without a path baked into the source.

    This package sits next to it in the same tree (`<root>/fbaugur`, `<root>/harnesscreator`),
    so the sibling is tried first, then an installed copy on sys.path, then the development
    location.  `--harnesscreator-src` / `--harnesscreator` override it either way.
    """
    here = Path(__file__).resolve()
    candidates = [here.parents[3] / "harnesscreator",            # <root>/fbaugur/src/fbaugur/cli.py
                  here.parents[4] / "harnesscreator"]            # an extra level of nesting
    for base in candidates:
        if (base / "src" / "harnesscreator").is_dir():
            return base / "src"
        if (base / "harnesscreator").is_dir():
            return base
    try:
        import harnesscreator                                     # already importable
        return Path(harnesscreator.__file__).resolve().parent.parent
    except ImportError:
        pass
    raise SystemExit("HarnessCreator not found: put it next to fbaugur (<root>/harnesscreator) or install it")


HC_SRC_DEFAULT = _harnesscreator_default()


def _emit(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fbaugur", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--python", default=sys.executable, help="interpreter used to rebuild the harness")
        parser.add_argument("--claude", default="claude")
        parser.add_argument("--native-extra-cflags", default="",
                            help="extra compiler flags for the harness rebuild (e.g. -fcommon)")
        parser.add_argument("--max-hours", type=float, default=4.0, help="wall clock budget (default 4)")
        parser.add_argument("--fuzz-after-drain-minutes", type=float, default=0.0,
                            help="cap the fuzzing that follows the agents, in minutes; 0 (default) uses the "
                                 "rest of --max-hours")
        parser.add_argument("--sanitizer", default="address+undefined")
        parser.add_argument("--daemon-command",
                            help="the real program built with ASan (+UBSan), started as a server, e.g. "
                                 "'/t/daemon-asan/fftp /t/run/fftp.conf'. Each confirmed finding is sent to it "
                                 "over its own socket before it may be called a vulnerability")
        parser.add_argument("--daemon-msan-command", help="the same, built with MemorySanitizer, for MSan findings")
        parser.add_argument("--daemon-plain-command",
                            help="the same program built WITHOUT sanitizers. Each finding is sent to it repeatedly "
                                 "(and once under glibc's debugging allocator) to measure what it does in a normal "
                                 "build; impact that is neither measured there nor proven from the code is not scored")
        parser.add_argument("--daemon-cwd", default="", help="working directory for the daemon commands")
        parser.add_argument("--daemon-port", type=int, default=0, help="port the daemon listens on (default: the harness's)")
        parser.add_argument("--product-version", default="",
                            help="the tested version or revision, written as the advisory's affected version")
        parser.add_argument("--diff", type=Path,
                            help="delta scan (FBv2 delta mode): analyse the functions this unified diff changes "
                                 "instead of the whole program. Paths may be relative to the diff's own "
                                 "repository; they are matched to the source by file name")
        parser.add_argument("--no-msan", action="store_true",
                            help="do not add a MemorySanitizer fuzzing worker (default: add one per harness "
                                 "when a clang >= 18 is installed and the build starts)")
        parser.add_argument("--provider", choices=["claude", "codex", "ollama"], default="claude",
                            help="LLM back end for both stages (codex: codex exec; ollama: Claude Code on Ollama's "
                                 "Anthropic-compatible API)")
        parser.add_argument("--codex", default="codex", help="Codex CLI executable")
        parser.add_argument("--ollama-url", default="http://localhost:11434")
        parser.add_argument("--model-t1", help="reasoning tier (threat model, directions, verification, triage)")
        parser.add_argument("--model-t2", help="main tier (seeds, PoV, invariants, reports)")
        parser.add_argument("--model-t3", help="fast tier (candidate generation)")
        parser.add_argument("--concurrency", type=int, default=5, help="concurrent Claude agents")
        parser.add_argument("--sp-agents", type=int, default=3)
        parser.add_argument("--verify-agents", type=int, default=2)
        parser.add_argument("--pov-agents", type=int, default=2)
        parser.add_argument("--max-functions", type=int, default=0, help="0 = every function in the pools")
        parser.add_argument("--max-turns", action="append", default=[], metavar="ROLE=N",
                            help=f"override a role's turn limit; roles: {', '.join(sorted(DEFAULT_MAX_TURNS))}")
        parser.add_argument("--sp-fuzz-seconds", type=int, default=120)
        parser.add_argument("--rebuild-interval", type=float, default=120.0,
                            help="minimum seconds between two instrumented builds")
        parser.add_argument("--skip-threat-model", action="store_true")

    scan = sub.add_parser("scan", help="analyse a HarnessCreator run's harnesses")
    scan.add_argument("hc_run", type=Path, help="HarnessCreator run directory (holds project.json)")
    scan.add_argument("--context", required=True, help="input context id, e.g. ctx-803ca65377ec")
    scan.add_argument("--delivery", action="append", default=[], choices=["stream", "datagram", "peer_stream"],
                      help="channel to analyse (repeatable; default: every built delivery of the context)")
    scan.add_argument("--output", type=Path, default=Path("fbaugur-runs"))
    scan.add_argument("--harnesscreator-src", type=Path, default=HC_SRC_DEFAULT)
    add_common(scan)
    scan.add_argument("--resume", type=Path, help="continue an existing fbaugur run directory")

    line = sub.add_parser("pipeline", help="generate the harness from source, then scan it (one command)")
    from .pipeline import add_arguments as add_pipeline_arguments
    add_pipeline_arguments(line)
    add_common(line)

    report = sub.add_parser("report", help="print the state of a run")
    report.add_argument("run_dir", type=Path)
    report.add_argument("--json", action="store_true")
    return parser


def _built_deliveries(hc_run: Path, context: str) -> list[str]:
    base = hc_run / "context-harnesses"
    found = []
    for delivery in ("stream", "datagram", "peer_stream"):
        directory = base / f"{context}-{delivery}"
        if directory.is_dir() and any(directory.glob("attempt-*/build/hc-native-fuzzer")):
            found.append(delivery)
    return found


async def _scan(args: argparse.Namespace) -> int:
    from .orchestrator import Run

    hc_run = args.hc_run.expanduser().resolve()
    if not (hc_run / "project.json").is_file():
        raise SystemExit(f"{hc_run} is not a HarnessCreator run (no project.json)")
    deliveries = args.delivery or _built_deliveries(hc_run, args.context)
    if not deliveries:
        raise SystemExit(f"no built harness for context {args.context} under {hc_run}/context-harnesses")
    if args.resume:
        run_dir = args.resume.expanduser().resolve()
        cfg = RunConfig.load(run_dir)
        _emit(f"resuming {run_dir}")
    else:
        run_dir = (args.output.expanduser().resolve() /
                   f"{time.strftime('%Y%m%d-%H%M%S')}-{args.context}")
        run_dir.mkdir(parents=True, exist_ok=True)
        cfg = RunConfig(run_dir=str(run_dir), hc_run=str(hc_run), context_id=args.context,
                        deliveries=deliveries, sanitizer=args.sanitizer, python=args.python,
                        claude_executable=args.claude, max_hours=args.max_hours,
                        fuzz_after_drain_minutes=args.fuzz_after_drain_minutes,
                        claude_concurrency=args.concurrency, sp_generator_agents=args.sp_agents,
                        verifier_agents=args.verify_agents, pov_agents=args.pov_agents,
                        max_function_analyses=args.max_functions, sp_fuzz_seconds=args.sp_fuzz_seconds,
                        rebuild_min_interval_seconds=args.rebuild_interval,
                        skip_threat_model=args.skip_threat_model,
                        native_extra_cflags=args.native_extra_cflags, msan=not args.no_msan,
                        diff_path=str(args.diff.expanduser().resolve()) if args.diff else "",
                        daemon_command=args.daemon_command or "", daemon_msan_command=args.daemon_msan_command or "",
                        daemon_plain_command=args.daemon_plain_command or "",
                        daemon_cwd=args.daemon_cwd, daemon_port=args.daemon_port,
                        product_version=args.product_version)
        cfg.provider, cfg.codex_executable, cfg.ollama_url = args.provider, args.codex, args.ollama_url
        cfg.models = dict(PROVIDER_MODELS[args.provider])
        for tier, value in (("1", args.model_t1), ("2", args.model_t2), ("3", args.model_t3)):
            if value:
                cfg.models[tier] = value
        for item in args.max_turns:
            if "=" not in item:
                raise SystemExit(f"--max-turns wants ROLE=N, got {item!r}")
            role, number = item.split("=", 1)
            if role not in DEFAULT_MAX_TURNS:
                raise SystemExit(f"unknown role {role!r}; roles: {', '.join(sorted(DEFAULT_MAX_TURNS))}")
            cfg.max_turns[role] = int(number)
        cfg.save()
    from .agent import check_backend
    problem = check_backend(cfg)
    if problem:
        raise SystemExit(problem)
    _emit(f"run directory: {run_dir}")
    _emit(f"deliveries: {deliveries} | models: {cfg.models} | wall clock: {cfg.max_hours} h")
    run = Run(run_dir, cfg, harnesscreator_src=args.harnesscreator_src.resolve(), emit=_emit)
    summary = await run.execute()
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    confirmed = sum(summary["crashes"].get(k, 0) for k in ("confirmed", "validated", "reported", "needs_review"))
    if summary["terminal_error"]:
        return 3
    return 0 if confirmed or summary["suspicious_points"] else 1


def _report(args: argparse.Namespace) -> int:
    run_dir = args.run_dir.expanduser().resolve()
    store = Store(run_dir / "state.db")
    counts = lambda sql: {row["k"]: row["n"] for row in store.rows(sql)}
    data = {
        "run_dir": str(run_dir),
        "functions": counts("SELECT status AS k, COUNT(*) AS n FROM pool GROUP BY status"),
        "suspicious_points": counts("SELECT status AS k, COUNT(*) AS n FROM sps GROUP BY status"),
        "invariants": counts("SELECT status AS k, COUNT(*) AS n FROM invariants GROUP BY status"),
        "violations": counts("SELECT COALESCE(verdict,status) AS k, COUNT(*) AS n FROM violations GROUP BY k"),
        "crashes": counts("SELECT status AS k, COUNT(*) AS n FROM crashes GROUP BY status"),
        "agent_runs": counts("SELECT status AS k, COUNT(*) AS n FROM agent_runs GROUP BY status"),
    }
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0
    for key, value in data.items():
        print(f"{key}: {value}")
    print("\nconfirmed crashes:")
    for row in store.rows("SELECT crash_id, crash_type, signature, source, report_path, status FROM crashes "
                          "WHERE status IN ('confirmed','validated','reported','not_vulnerability','needs_review')"):
        print(f"  {row['crash_id']} {row['status']:17} {row['crash_type']} [{row['source']}] {row['signature']}")
        if row["report_path"]:
            print(f"    report: {row['report_path']}")
    print("\ninvariants:")
    for row in store.rows("SELECT phi_num, file, line, expression, status, refinements, reached "
                          "FROM invariants ORDER BY phi_num"):
        print(f"  phi {row['phi_num']:3d} {row['status']:16} "
              f"{'reached' if row['reached'] else '  -    '} {row['file']}:{row['line']}  "
              f"{row['expression']}" + (f"  (refined {row['refinements']}x)" if row["refinements"] else ""))
    leads = store.rows("SELECT sp_id, function_name, status, origin_ref FROM sps WHERE origin='invariant_violation'")
    if leads:
        print("\nleads from falsified invariants:")
        for row in leads:
            print(f"  {row['sp_id']} {row['function_name']} ({row['status']}) from phi {row['origin_ref']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return asyncio.run(_scan(args))
    if args.command == "pipeline":
        from .pipeline import run as run_pipeline
        return asyncio.run(run_pipeline(args, _emit))
    return _report(args)


if __name__ == "__main__":
    sys.exit(main())
