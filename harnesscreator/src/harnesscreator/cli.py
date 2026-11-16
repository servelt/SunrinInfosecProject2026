from __future__ import annotations

import argparse
import asyncio
import dataclasses
import getpass
import hashlib
import json
import re
import shlex
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .analysis import (
    GraphStore,
    FuzzIntrospectorError,
    FuzzIntrospectorRunner,
    SVFError,
    StaticAnalyzer,
    UpstreamProcessResult,
    UpstreamToolError,
    UsageEvidenceBundle,
    fuzzgen_reports_to_rubick_a2dg,
    load_upstream_revisions,
    load_usage_evidence,
    mark_svf_unavailable,
    prepare_svf_analysis,
    run_rubick_a2dg,
)
from .analysis.binary_sources import linked_source_priority
from .analysis.fuzz_introspector import default_fi_cache_root
from .analysis.svf import default_svf_cache_root
from .llm import (
    CachingLLM,
    CodexAppServer,
    CodexAppServerError,
    CodexAppServerPool,
    LLMProvider,
)
from .llm.claude import DEFAULT_CLAUDE_MODEL, ClaudeProvider
from .llm.claude_code import ClaudeCodeProvider
from .llm.ollama import OllamaProvider
from .models import AnalysisBundle, ProjectSpec, as_json
from .orchestrator import EntryStageCompleted, HarnessCreator, validate_active_output_schemas
from .runtime import (
    OssFuzzBackendError,
    NativeOssFuzzVerifierAgent,
    preflight_oss_fuzz_backend,
)


DEFAULT_ROLE_MODELS: dict[str, str] = {
    # Temporary lower-cost default; explicit role overrides still take precedence.
    "entry_generator": "gpt-5.6-sol",
    "entry_verifier": "gpt-5.6-sol",
    "entry_action_screen": "gpt-5.6-sol",
    "input_surface": "gpt-5.6-sol",
    "input_action": "gpt-5.6-sol",
    "scenario_refiner": "gpt-5.6-sol",
    "state_dependency": "gpt-5.6-sol",
    "harness_generator": "gpt-5.6-sol",
    "harness_verifier": "gpt-5.6-sol",
}


# Preserve the original workload split: broad candidates first, verification later.
# The former Small/Large Feature reasoning budget moves to the current
# Input Action / State Dependency / Scenario Refiner roles.
DEFAULT_OLLAMA_ROLE_EFFORTS: dict[str, str | None] = {
    "entry_generator": "high",
    "entry_verifier": "low",
    "entry_action_screen": "high",
    "input_surface": "high",
    "input_action": "high",
    "state_dependency": "high",
    "scenario_refiner": "high",
    "harness_generator": None,
    "harness_verifier": "max",
    # Historical roles are kept for backwards-compatible direct calls.
    "small_feature": "high",
    "large_feature": "high",
}

_ACTION_ROLES = frozenset({
    "entry_generator", "entry_verifier", "entry_action_screen", "input_surface", "input_action",
    "state_dependency", "scenario_refiner", "harness_generator",
    "harness_verifier",
})


def _for_workflow(args: argparse.Namespace, models: dict[str, str]) -> dict[str, str]:
    return {role: model for role, model in models.items() if role in _ACTION_ROLES}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harnesscreator",
        description="Evidence-driven fuzz harness generation through Codex app-server",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="check the local Codex app-server connection")
    doctor.add_argument("--source", type=Path, default=Path.cwd())
    doctor.add_argument("--codex", default="codex")
    doctor.add_argument("--daybreak", action="store_true", help="request Daybreak on eligible Codex models")
    doctor.add_argument("--workers", type=int, default=1)
    doctor.add_argument(
        "--turn",
        action="store_true",
        help="also execute one tiny structured-output model turn",
    )

    report = subparsers.add_parser("report", help="inspect an existing or interrupted run without LLM calls")
    report.add_argument("run_dir", type=Path)
    report.add_argument("--json", action="store_true", help="machine-readable candidate attrition and blockers")

    network_fuzz = subparsers.add_parser(
        "network-fuzz",
        help="run an explicitly configured StateAFL campaign from original-run network seeds",
    )
    instrument_server = subparsers.add_parser(
        "instrument-server",
        help="build a copied C/C++ server tree with StateAFL's compiler",
    )
    instrument_server.add_argument("source_root", type=Path)
    instrument_server.add_argument("--output", type=Path, required=True)
    instrument_server.add_argument("--stateafl-cc", type=Path, required=True)
    instrument_server.add_argument("--stateafl-cxx", type=Path)
    instrument_server.add_argument(
        "--build-command", required=True,
        help="trusted project build argv as one quoted string; never run through a shell",
    )
    instrument_server.add_argument(
        "--build-step", action="append", default=[],
        help="additional trusted build argv, executed in order; repeat for configure/clean/make",
    )
    instrument_server.add_argument(
        "--server-relative-path", type=Path, required=True,
        help="expected executable path relative to the copied source root",
    )
    instrument_server.add_argument("--timeout-seconds", type=int)
    instrument_server.add_argument(
        "--container-image",
        help="explicit Docker image with a Clang/LLVM version matching the StateAFL pass",
    )
    instrument_server.add_argument(
        "--linker-flag", action="append", default=[],
        help="extra final-link argument for build systems that invoke gcc/g++ directly; repeat as needed",
    )
    network_fuzz.add_argument("run_dir", type=Path)
    network_fuzz.add_argument("--output", type=Path, required=True)
    network_fuzz.add_argument("--stateafl-fuzz", type=Path, required=True)
    network_fuzz.add_argument(
        "--server-build-manifest", type=Path,
        help="instrument-server build.json; verifies coverage object and binary digest",
    )
    network_fuzz.add_argument(
        "--server-command", required=True,
        help="instrumented server argv as one quoted string; never run through a shell",
    )
    network_fuzz.add_argument("--transport", choices=["tcp", "udp"], required=True)
    network_fuzz.add_argument("--host", required=True)
    network_fuzz.add_argument("--port", type=int, required=True)
    network_fuzz.add_argument("--seconds", type=int, required=True)
    network_fuzz.add_argument(
        "--seed-tier", choices=["proven", "exploratory", "diagnostic"],
        default="proven",
    )
    network_fuzz.add_argument(
        "--research-only", action="store_true",
        help="required for unproven seeds; results cannot qualify a harness",
    )
    network_fuzz.add_argument(
        "--state-aware", action="store_true",
        help="opt in to StateAFL -E; the seed must actually initialize a protocol state",
    )
    network_fuzz.add_argument("--startup-delay-us", type=int)
    network_fuzz.add_argument("--execution-timeout-ms", type=int)
    network_fuzz.add_argument("--memory-limit-mb", type=int)
    network_fuzz.add_argument(
        "--no-memory-limit", action="store_true",
        help="explicitly pass StateAFL -m none for servers needing more than its default",
    )
    network_fuzz.add_argument("--graceful-sigterm", action="store_true")
    network_fuzz.add_argument(
        "--replay-server-command",
        help="separate original server argv for crash replay; quoted as one string",
    )
    network_fuzz.add_argument(
        "--replay-timeout-ms", type=int,
        help="required with --replay-server-command; bounds each original replay",
    )
    network_fuzz.add_argument("--prepare-only", action="store_true")

    analyze = subparsers.add_parser("analyze", help="run static indexing without an LLM")
    analyze.add_argument("source", type=Path)
    analyze.add_argument(
        "--analysis-binary", type=Path,
        help=("prioritize DWARF-matched sources, or unique ELF file-symbol "
              "hints when no DWARF units exist; never exclude other files"),
    )
    analyze.add_argument(
        "--fuzz-introspector",
        type=Path,
        help="use an existing FI report instead of running Fuzz Introspector automatically",
    )
    analyze.add_argument(
        "--analysis-compile-database", type=Path,
        help="existing compile_commands.json from the configured build for Clang AST analysis",
    )
    analyze.add_argument(
        "--analysis-build-command",
        help=("trusted real build argv to record with Bear, for example "
              "'make -B -j4'; may write normal build artifacts in the source tree"),
    )
    analyze.add_argument("--analysis-build-timeout", type=float)
    analyze.add_argument(
        "--require-fuzz-introspector",
        action="store_true",
        help="fail instead of using the bootstrap source indexer",
    )
    analyze.add_argument(
        "--svf",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=("augment indirect calls with locked SVF evidence; accepts a "
              "compilation database, bitcode, or an existing SVF report"),
    )
    analyze.add_argument("--require-svf", action="store_true")
    analyze.add_argument("--svf-bitcode", type=Path, action="append", default=[])
    analyze.add_argument("--svf-callgraph", type=Path)
    analyze.add_argument("--research-repos-root", type=Path)
    analyze.add_argument("--json", action="store_true", help="print complete function metadata")

    run = subparsers.add_parser("run", help="run the complete harness creation workflow")
    run.add_argument(
        "--workflow", choices=["context", "action", "legacy_scenario"], default="context",
        help=("context (default): after the Entry stage continue with input contexts, verified normal "
              "inputs and one harness per channel; action: the earlier Action-based stages "
              "(legacy_scenario is an alias for saved commands)"),
    )
    run.add_argument("source", type=Path)
    run.add_argument("--output", type=Path, default=Path("harnesscreator-runs"))
    run.add_argument(
        "--entry-artifacts-from", type=Path,
        help=("reuse verified/unresolved Entry records from a previous run "
              "after checking the indexed product source; skip Entry LLM calls"),
    )
    run.add_argument(
        "--action-artifacts-from", type=Path,
        help=("reuse completed semantic Actions and their Entry records from a previous "
              "run after checking the indexed product source; start at Action grouping"),
    )
    run.add_argument("--name")
    run.add_argument("--diff", type=Path, help="delta scan: search Entries only among changed functions and their callers")
    run.add_argument("--diff-depth", type=int, default=6, help="with --diff: how many calls above the change to search (0 = no limit)")
    run.add_argument(
        "--analysis-binary", type=Path,
        help=("optional ELF: prioritize byte-identical DWARF sources or "
              "unique file-symbol hints; all other source remains eligible"),
    )
    run.add_argument(
        "--analysis-compile-database", type=Path,
        help=("existing compile_commands.json from the configured build; "
              "supplies Clang include paths and macros, not link or runtime proof"),
    )
    run.add_argument(
        "--analysis-build-command",
        help=("trusted real build argv to record with Bear, for example "
              "'make -B -j4'; may write normal build artifacts in the source tree"),
    )
    run.add_argument("--analysis-build-timeout", type=float)
    run.add_argument(
        "--fuzz-introspector",
        type=Path,
        help="use an existing FI report instead of running Fuzz Introspector automatically",
    )
    analysis_policy = run.add_mutually_exclusive_group()
    analysis_policy.add_argument(
        "--require-fuzz-introspector",
        dest="require_fuzz_introspector",
        action="store_true",
        default=True,
        help="require a Fuzz Introspector report (default); graph completeness remains unproven",
    )
    analysis_policy.add_argument(
        "--allow-source-analysis",
        dest="require_fuzz_introspector",
        action="store_false",
        help="run FI first, but allow bootstrap source indexing if automatic FI analysis fails",
    )
    run.add_argument(
        "--svf",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "resolve possible function-pointer targets with the locked official SVF "
            "engine (default: enabled)"
        ),
    )
    indirect_policy = run.add_mutually_exclusive_group()
    indirect_policy.add_argument(
        "--require-svf",
        dest="require_svf",
        action="store_true",
        default=None,
        help="stop before LLM work if SVF evidence cannot be produced",
    )
    indirect_policy.add_argument(
        "--allow-partial-indirect-calls",
        dest="require_svf",
        action="store_false",
        help="continue with an explicitly partial function-pointer call graph",
    )
    run.add_argument(
        "--svf-bitcode",
        type=Path,
        action="append",
        default=[],
        help="prebuilt LLVM .bc module for SVF (repeatable)",
    )
    run.add_argument(
        "--svf-callgraph",
        type=Path,
        help="existing official SVF DOT or HarnessCreator SVF evidence JSON",
    )
    run.add_argument(
        "--model",
        help="override every LLM role; omitted uses HarnessCreator's fixed per-agent defaults",
    )
    run.add_argument(
        "--candidate-model",
        help=f"override Entry Generator (fixed default: {DEFAULT_ROLE_MODELS['entry_generator']})",
    )
    run.add_argument(
        "--strong-model",
        help=f"override verifier and normal-flow reconstruction agents (fixed default: {DEFAULT_ROLE_MODELS['entry_verifier']})",
    )
    run.add_argument(
        "--coding-model",
        help=f"override Harness Generator (fixed default: {DEFAULT_ROLE_MODELS['harness_generator']})",
    )
    run.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max", "ultra"])
    run.add_argument(
        "--provider", choices=["codex", "ollama", "claude", "claude-api"], default="codex",
        help="claude: local Claude Code CLI on the Claude subscription; "
             "claude-api: Claude API with ANTHROPIC_API_KEY (billed per token)",
    )
    run.add_argument("--claude", default="claude", help="Claude Code executable for --provider claude")
    run.add_argument("--ollama-url", default="http://127.0.0.1:11434")
    run.add_argument("--codex", default="codex")
    run.add_argument(
        "--daybreak",
        action="store_true",
        help="opt into Daybreak Blue for eligible Codex turns (requires approved account)",
    )
    run.add_argument(
        "--workers",
        type=int,
        default=1,
        help="parallel Codex app-server processes (default: 1; total across simultaneous runs matters)",
    )
    run.add_argument(
        "--worker-recycle-turns",
        type=int,
        default=16,
        help=(
            "restart each app-server after this many turns, deferred until its active "
            "agent sessions finish (default: 16)"
        ),
    )
    run.add_argument(
        "--resume-from",
        type=Path,
        help=(
            "reuse exact LLM calls from an earlier run directory or trajectory JSONL; "
            "a run directory also continues one source-linked Action lead per Entry; "
            "ordered stateful sessions replay as a whole, sessions changed at their first turn rerun "
            "live, and late divergence stops instead of losing thread history"
        ),
    )
    run.add_argument("--fuzz-seconds", type=int, default=300)
    run.add_argument(
        "--network-harness-config", type=Path,
        help=("trusted JSON configuration for a separately instrumented "
              "StateAFL network harness; its result never qualifies a libFuzzer harness"),
    )
    run.add_argument("--context-depth", type=int, default=3)
    run.add_argument(
        "--context-functions", type=int, default=0,
        help=("maximum functions opened per Entry Verifier, Input Surface, and Input Action walk; "
              "0 (default) has no arbitrary function-count cutoff beyond indexed-function cycle guards; "
              "a positive value is a work budget, never a completeness claim"),
    )
    run.add_argument(
        "--entry-batch-size",
        type=int,
        default=32,
        help="maximum source excerpts per Entry Generator model call (prompt-size cap also applies)",
    )
    run.add_argument(
        "--max-attempts",
        type=int,
        default=0,
        help=(
            "optional maximum generate/audit/build repair attempts per scenario; "
            "0 (default) has no attempt-count cutoff, while repeated or "
            "non-repairable failures still stop"
        ),
    )
    from .contexts.pipeline import add_arguments as add_context_workflow_arguments
    add_context_workflow_arguments(run)
    scenario = run.add_argument_group(
        "original-program scenario verification",
        "trusted command/channel used to prove a normal external request sequence before harness generation",
    )
    scenario.add_argument(
        "--scenario-command",
        help=(
            "trusted original-program command, split without a shell; "
            "supports {source_root}"
        ),
    )
    scenario.add_argument(
        "--scenario-channel",
        choices=["auto", "stdin", "tcp", "udp", "unix_stream", "file", "argv", "env"],
        default="auto",
        help="optional original runtime adapter (default: auto per Action); never restricts Entry discovery",
    )
    scenario.add_argument(
        "--scenario-exploratory-drafts",
        action="store_true",
        help=(
            "try bounded source-derived requests when strict state planning stalls; "
            "build and replay the observed request when dynamic checks are enabled "
            "after response + ordered GDB observation, but NEVER "
            "mark unattributed traces as PROVEN_RUNTIME or QUALIFIED"
        ),
    )
    scenario.add_argument(
        "--max-initial-input-trials", "--max-exploratory-entries",
        dest="max_exploratory_entries", type=int, default=0,
        help=("maximum early raw-input runtime trials across all Entries; "
              "0 (default) tries every materialized case; omitted cases are recorded"),
    )
    scenario.add_argument(
        "--max-input-trial-bytes", type=int, default=0,
        help=("operator-selected maximum bytes in an original input trial; "
              "0 (default) does not infer a protocol size limit"),
    )
    scenario.add_argument("--scenario-host", default="127.0.0.1")
    scenario.add_argument(
        "--scenario-input-env", default="", metavar="NAME",
        help="trusted environment variable to receive generated bytes when using the env executor",
    )
    scenario.add_argument("--scenario-port", type=int)
    scenario.add_argument(
        "--scenario-socket-path", default="", metavar="ABS_PATH",
        help=("original AF_UNIX stream socket pathname; when omitted, "
              "{scenario_socket_path} in the trusted command receives a fresh temporary pathname"),
    )
    scenario.add_argument("--scenario-startup-timeout", type=float, default=10.0)
    scenario.add_argument("--scenario-step-timeout", type=float, default=2.0)
    scenario.add_argument("--scenario-response-limit", type=int, default=65_536)
    scenario.add_argument(
        "--scenario-attribution", choices=["gdb", "trace"], default="gdb",
        help="GDB temporal observation or source-instrumented request-correlated JSONL trace",
    )
    scenario.add_argument(
        "--require-differential-validation", dest="require_differential_validation",
        action="store_true",
        help="fail preflight unless original/harness source-instrumented traces can be compared; compatible command/trace runs compare automatically",
    )
    scenario.add_argument("--scenario-response-protocol", choices=["markers", "memcached_ascii"], default="markers")
    scenario.add_argument(
        "--scenario-env",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="trusted environment entry for the original program (repeatable)",
    )
    scenario.add_argument(
        "--scenario-evidence",
        action="append",
        type=Path,
        default=[],
        metavar="PATH",
        help=(
            "trusted project client/test/trace/corpus/spec evidence path "
            "(repeatable; mined separately from product Entries)"
        ),
    )
    scenario.add_argument(
        "--source-only-drafts", action=argparse.BooleanOptionalAction, default=None,
        help=("generate clearly unqualified source-derived C drafts when no "
              "trusted original-program execution proof is available; opt in "
              "explicitly because these drafts cannot be QUALIFIED"),
    )
    scenario.add_argument(
        "--max-source-drafts", type=int, default=32,
        help="maximum source-only C drafts per run (default: 32)",
    )
    scenario.add_argument(
        "--scenario-post-fuzz", action="store_true",
        help="also build bounded source-backed Setup→Fuzz→Post producer/consumer scenarios",
    )
    scenario.add_argument(
        "--max-scenario-steps", type=int, default=0,
        help="explicit request-sequence work limit; 0 (default) adds no depth cutoff",
    )
    scenario.add_argument(
        "--max-scenario-candidates", type=int, default=256,
        help=(
            "work budget for alternate request sequences (default: 256); "
            "every source-backed Action still receives at least one planning "
            "outcome, and a blocked target remains explicit"
        ),
    )
    scenario.add_argument(
        "--max-scenario-variants-per-action",
        type=int,
        default=0,
        help=(
            "optional maximum alternatives per target Action; 0 (default) "
            "adds no separate per-Action cutoff beyond the run-wide work budget"
        ),
    )
    scenario.add_argument(
        "--max-scenario-search-states",
        type=int,
        default=4096,
        help="maximum producer/consumer search states explored per target action",
    )
    run.add_argument(
        "--verification-backend",
        choices=["auto", "oss-fuzz", "command"],
        default="auto",
        help=(
            "auto tries a standalone Clang/libFuzzer build of each generated harness "
            "using the original source (or uses --build-command/--binary). "
            "OSS-Fuzz project recipes are only used if explicitly selected"
        ),
    )
    run.add_argument(
        "--build-command",
        help=(
            "trusted build command, split without a shell; placeholders: {harness}, {source_root}, {output}"
        ),
    )
    run.add_argument(
        "--binary",
        help="trusted path to the built fuzz target; supports {source_root} and {output}",
    )
    run.add_argument(
        "--oss-fuzz-dir",
        type=Path,
        help="required OSS-Fuzz checkout containing infra/helper.py and projects/",
    )
    run.add_argument(
        "--oss-fuzz-project",
        help="OSS-Fuzz project name (default: --name or source directory basename)",
    )
    run.add_argument(
        "--oss-fuzz-fuzzer",
        help="canonical OSS-Fuzz fuzzer binary/source stem; required when it cannot be inferred",
    )
    run.add_argument(
        "--harness-source-filename",
        help="canonical generated source basename including .c/.cc; inferred for known targets",
    )
    run.add_argument(
        "--oss-fuzz-source-path",
        help=(
            "absolute application checkout path inside the OSS-Fuzz builder image; "
            "the local source tree is overlaid here (inferred for known targets)"
        ),
    )
    run.add_argument(
        "--dynamic-verification",
        action=argparse.BooleanOptionalAction,
        default=True,
        help=(
            "build the generated target with sanitizers; the command backend also "
            "checks target reachability, while the native OSS-Fuzz backend performs "
            "smoke tests without claiming qualification; disabling it skips runtime "
            "tests and produces a build-only draft"
        ),
    )
    run.add_argument(
        "--agent-debug",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="also print structured agent decisions and graph traversal summaries live",
    )
    upstream = run.add_argument_group(
        "upstream research evidence",
        "consume outputs from the original research implementations without reimplementing their algorithms",
    )
    upstream.add_argument(
        "--fuzzgen-evidence",
        type=Path,
        action="append",
        default=[],
        help="FuzzGen AADG/dependency JSON exported with schema harnesscreator.fuzzgen.aadg.v1 (repeatable)",
    )
    upstream.add_argument(
        "--hopper-constraints",
        type=Path,
        action="append",
        default=[],
        help="Hopper constraint.config/custom rule file containing original ctx rules (repeatable)",
    )
    upstream.add_argument(
        "--winnie-evidence",
        type=Path,
        action="append",
        default=[],
        help="WINNIE trace sequence adapter JSON (repeatable)",
    )
    upstream.add_argument(
        "--rubick-a2dg",
        type=Path,
        action="append",
        default=[],
        help="A2DG JSON passed to the locked original RUBICK implementation (repeatable)",
    )
    upstream.add_argument(
        "--rubick-nfa",
        type=Path,
        action="append",
        default=[],
        help="NFA JSON emitted by the original RUBICK A2DG implementation (repeatable)",
    )
    upstream.add_argument(
        "--netlifter-bnf",
        type=Path,
        action="append",
        default=[],
        help="original NetLifter/Popeye <BNF> output (repeatable)",
    )
    upstream.add_argument(
        "--research-repos-root",
        type=Path,
        help="locked upstream checkout directory used to audit provider revisions",
    )
    from .contexts.cli import add_subparsers as add_context_subparsers
    add_context_subparsers(subparsers)
    return parser


async def _doctor(args: argparse.Namespace) -> int:
    source = args.source.expanduser().resolve()
    if not source.is_dir():
        raise ValueError(f"source root is not a directory: {source}")
    client = (
        CodexAppServer(
            cwd=source, model=DEFAULT_ROLE_MODELS["entry_generator"], executable=args.codex, daybreak=args.daybreak
        )
        if args.workers == 1
        else CodexAppServerPool(
            cwd=source, model=DEFAULT_ROLE_MODELS["entry_generator"], executable=args.codex,
            workers=args.workers, daybreak=args.daybreak,
        )
    )
    try:
        response = await client.start()
        payload: dict[str, object] = {
            "ok": True,
            "workers": args.workers,
            "initialize": response or {"pool": "initialized"},
        }
        if args.turn:
            payload["turn"] = await client.complete_json(
                role="doctor",
                instructions="Echo the supplied probe string and set ok to true.",
                payload={"probe": "harnesscreator-app-server"},
                output_schema={
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["ok", "probe"],
                    "properties": {
                        "ok": {"type": "boolean"},
                        "probe": {"type": "string"},
                    },
                },
            )
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0
    finally:
        await client.close()


def _analysis_compile_database(
    args: argparse.Namespace, source: Path, artifact_root: Path,
) -> Path | None:
    if args.analysis_build_command and args.analysis_compile_database:
        raise ValueError(
            "choose either --analysis-build-command or --analysis-compile-database"
        )
    if not args.analysis_build_command:
        return args.analysis_compile_database
    from .runtime.compile_database_capture import capture_compile_database

    output = artifact_root / "compile_commands.json"
    print(
        f"[{time.strftime('%H:%M:%S')}] Bear build-context capture started: {source}",
        file=sys.stderr, flush=True,
    )
    captured = capture_compile_database(
        source, output, shlex.split(args.analysis_build_command),
        timeout_seconds=args.analysis_build_timeout,
    )
    print(
        f"[{time.strftime('%H:%M:%S')}] Bear build-context capture completed: {captured}",
        file=sys.stderr, flush=True,
    )
    return captured


def _analyze(args: argparse.Namespace) -> int:
    source = args.source.expanduser().resolve()
    cache_key = hashlib.sha256(str(source).encode()).hexdigest()[:16]
    compile_database = _analysis_compile_database(
        args, source,
        Path(tempfile.gettempdir()) / "harnesscreator-build-context" / cache_key,
    )
    report = _prepare_fuzz_introspector(
        source,
        args.fuzz_introspector,
        default_fi_cache_root(source),
        require=args.require_fuzz_introspector,
        excluded_paths=(),
        progress=lambda message: print(
            f"[{time.strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True
        ),
        compile_database=compile_database,
    )
    bundle = StaticAnalyzer(
        source,
        report,
        require_fuzz_introspector=args.require_fuzz_introspector,
        compile_database=compile_database,
        target_binary=args.analysis_binary,
    ).index()
    research_root = (
        args.research_repos_root.expanduser().resolve()
        if args.research_repos_root
        else Path(__file__).resolve().parents[3] / "research-repos"
    )
    try:
        bundle = prepare_svf_analysis(
            bundle,
            source_root=source,
            cache_root=default_svf_cache_root(source),
            research_repos_root=research_root if research_root.is_dir() else None,
            enabled=args.svf,
            required=args.require_svf,
            evidence_path=args.svf_callgraph,
            bitcode=args.svf_bitcode,
            compile_database=compile_database,
            progress=lambda message: print(
                f"[{time.strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True
            ),
        )
    except SVFError as exc:
        raise ValueError(f"SVF indirect-call analysis failed: {exc}") from exc
    binary_source_priority = (
        linked_source_priority(
            args.analysis_binary,
            source,
            (function.file for function in bundle.functions.values()),
        ) if args.analysis_binary else None
    )
    if args.json:
        payload: dict[str, Any] = {
            "functions": [as_json(function) for function in bundle.function_list()],
            "edges": [as_json(edge) for edge in bundle.edges],
            "completeness": bundle.completeness,
        }
    else:
        payload = {
            "source": str(source),
            "functions": len(bundle.functions),
            "edges": len(bundle.edges),
            "completeness": bundle.completeness,
        }
    if binary_source_priority is not None:
        payload["binary_source_priority"] = binary_source_priority
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


async def _run(args: argparse.Namespace) -> int:
    if args.daybreak and args.provider != "codex":
        raise ValueError("--daybreak requires --provider codex")
    # Structured-output schema defects are local programming/configuration
    # errors.  Check them before cloning/building OSS-Fuzz, running FI/SVF, or
    # starting a model worker; the orchestrator repeats this assertion for
    # direct library callers that bypass the CLI.
    # The context workflow shares the Entry stage with the Action workflow and
    # leaves it once the Entry files exist, so the orchestrator is configured
    # exactly as for an Action run up to that point.
    context_workflow = args.workflow == "context"
    orchestrator_workflow = "action" if context_workflow else args.workflow
    validate_active_output_schemas(orchestrator_workflow)
    source = args.source.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if not source.is_dir():
        raise ValueError(f"source root is not a directory: {source}")
    if output == source:
        raise ValueError("output root must not be the project source root")
    if context_workflow:
        # Missing coverage build or port: fail before analysis and model work.
        from .contexts import pipeline as context_pipeline
        context_pipeline.validate(args)
    binary: str | Path | None = args.binary
    if binary and not any(token in str(binary) for token in ("{source_root}", "{output}")):
        binary = Path(binary).expanduser().resolve()
    build_command = shlex.split(args.build_command) if args.build_command else []
    native_default_build = False
    scenario_command = (
        shlex.split(args.scenario_command) if args.scenario_command else []
    )
    if (scenario_command and args.scenario_attribution == "gdb"
        and not args.scenario_exploratory_drafts
        and args.source_only_drafts is not True):
        raise ValueError(
            "this run cannot QUALIFY a harness: GDB breakpoints do not bind "
            "a handler to the submitted request. Configure an original build "
            "that emits request-correlated trace events with "
            "--scenario-attribution trace, or explicitly request unqualified "
            "work with --source-only-drafts or --scenario-exploratory-drafts"
        )
    # Input transport is inferred from an Action during runtime verification,
    # never required before scanning all product Entries.
    scenario_environment: dict[str, str] = {}
    for item in args.scenario_env:
        if "=" not in item or not item.split("=", 1)[0]:
            raise ValueError("--scenario-env must use NAME=VALUE")
        name, value = item.split("=", 1)
        scenario_environment[name] = value
    backend = args.verification_backend
    if backend == "auto":
        # Never implicitly select a pre-existing OSS-Fuzz project's fuzzer.
        # Its recipe is unrelated to a newly discovered source-level Entry.
        backend = "command"
        if not build_command and not args.binary:
            native_default_build = True
            build_command = [
                sys.executable, "-m", "harnesscreator.runtime.native_build",
                "--source-root", "{source_root}",
                "--harness", "{harness}",
                "--output", "{output}",
            ]
            binary = "{output}/hc-native-fuzzer"
        if args.oss_fuzz_dir:
            print(
                f"[{time.strftime('%H:%M:%S')}] OSS-Fuzz checkout ignored in auto mode; "
                "use --verification-backend oss-fuzz only for an explicit legacy recipe",
                file=sys.stderr, flush=True,
            )
    if backend == "command" and bool(build_command) != bool(binary):
        raise ValueError(
            "--build-command and --binary must be provided together; both may be "
            "omitted for a discovery-only run with deferred build verification"
        )
    if backend == "oss-fuzz" and (build_command or args.binary):
        raise ValueError(
            "do not combine the OSS-Fuzz backend with --build-command/--binary; select "
            "--verification-backend command for a custom build"
        )
    if (backend == "oss-fuzz" and args.source_only_drafts is not True
        and not args.scenario_exploratory_drafts):
        raise ValueError(
            "this run cannot QUALIFY a harness: the native OSS-Fuzz adapter "
            "currently verifies build and smoke execution only. Use "
            "--verification-backend command with request-correlated original "
            "instrumentation for qualification, or explicitly request "
            "unqualified work with --source-only-drafts or "
            "--scenario-exploratory-drafts"
        )

    oss_fuzz_project: str | None = None
    oss_fuzz_fuzzer: str | None = None
    oss_fuzz_source_path: str | None = None
    oss_fuzz_revision: str | None = None
    resolved_oss_fuzz_dir: Path | None = None
    harness_source_filename = args.harness_source_filename
    svf_capture_failure: Path | None = None
    if backend == "oss-fuzz":
        # Never import the QuartetFuzz project. It supplied research ideas,
        # not a runtime component of HarnessCreator.
        oss_fuzz_project = args.oss_fuzz_project or args.name or source.name
        if not args.oss_fuzz_dir:
            raise ValueError(
                "native OSS-Fuzz integration needs --oss-fuzz-dir pointing to an existing checkout"
            )
        resolved_oss_fuzz_dir = args.oss_fuzz_dir.expanduser().resolve()
        if not (resolved_oss_fuzz_dir / "infra" / "helper.py").is_file():
            raise ValueError(
                f"--oss-fuzz-dir is not a usable OSS-Fuzz checkout: {resolved_oss_fuzz_dir}"
            )
        oss_fuzz_fuzzer, inferred_source, inferred_checkout = _resolve_oss_fuzz_recipe(
            oss_fuzz_project, args.oss_fuzz_fuzzer,
            oss_fuzz_dir=resolved_oss_fuzz_dir,
        )
        harness_source_filename = harness_source_filename or inferred_source
        oss_fuzz_source_path = args.oss_fuzz_source_path or inferred_checkout
        if not oss_fuzz_fuzzer or not harness_source_filename:
            raise ValueError(
                f"cannot infer the canonical OSS-Fuzz target for {oss_fuzz_project!r}; "
                "pass --oss-fuzz-fuzzer and --harness-source-filename"
            )
        if not oss_fuzz_source_path:
            raise ValueError(
                f"cannot infer the application checkout directory for {oss_fuzz_project!r}; "
                "pass --oss-fuzz-source-path (for example /src/project) so the local source "
                "can be verified instead of the Dockerfile's remote checkout"
            )
        # The executable checkout, not an imagined revision, is the source
        # of truth. Git metadata may be unavailable for an unpacked checkout.
        import subprocess
        try:
            git_revision = subprocess.run(
                ['git', '-C', str(resolved_oss_fuzz_dir), 'rev-parse', '--verify', 'HEAD'],
                capture_output=True, text=True, check=False, timeout=10,
            )
            if git_revision.returncode == 0:
                value = git_revision.stdout.strip()
                if re.fullmatch(r'[0-9a-f]{40,64}', value):
                    oss_fuzz_revision = value
        except (OSError, subprocess.SubprocessError):
            pass
        print(
            f"[{time.strftime('%H:%M:%S')}] OSS-Fuzz recipe selected: "
            f"{resolved_oss_fuzz_dir} @ {(oss_fuzz_revision or 'unversioned')[:12]}",
            file=sys.stderr,
            flush=True,
        )
    else:
        harness_source_filename = harness_source_filename or "fuzz_target.cc"

    # GDB breakpoint order does not identify which request executed a
    # handler. Report the qualification limit before a potentially long
    # source inventory, even when GDB itself is installed.
    if scenario_command and args.scenario_attribution == "gdb":
        print(
            f"[{time.strftime('%H:%M:%S')}] ORIGINAL PROOF BLOCKER: "
            "GDB breakpoint order cannot establish request-to-handler "
            "attribution; strict runtime qualification needs a "
            "request-correlated trace. Source analysis and unqualified "
            "drafts may continue, but this configuration cannot QUALIFY "
            "a harness.",
            file=sys.stderr, flush=True,
        )
        if not shutil.which("gdb"):
            print(
                f"[{time.strftime('%H:%M:%S')}] GDB unavailable; exploratory "
                "replay may produce only unqualified drafts",
                file=sys.stderr, flush=True,
            )
    analysis_compile_database = _analysis_compile_database(
        args, source, output / ".analysis-build-context",
    )
    if native_default_build and analysis_compile_database is not None:
        build_command.extend([
            "--compile-database", str(analysis_compile_database.expanduser().resolve()),
        ])
    project = ProjectSpec(
        source_root=source,
        output_root=output,
        entry_artifacts_from=args.entry_artifacts_from,
        action_artifacts_from=args.action_artifacts_from,
        workflow_mode=orchestrator_workflow,
        name=args.name or source.name,
        analysis_binary=args.analysis_binary,
        analysis_compile_database=analysis_compile_database,
        fuzz_introspector=args.fuzz_introspector,
        require_fuzz_introspector=args.require_fuzz_introspector,
        svf_enabled=args.svf,
        require_svf=(args.require_svf if args.require_svf is not None else False),
        svf_bitcode=args.svf_bitcode,
        svf_callgraph=args.svf_callgraph,
        verification_backend=backend,
        build_command=build_command,
        native_default_build=native_default_build,
        harness_binary=binary,
        harness_source_filename=harness_source_filename,
        oss_fuzz_project=oss_fuzz_project,
        oss_fuzz_fuzzer=oss_fuzz_fuzzer,
        oss_fuzz_source_path=oss_fuzz_source_path,
        oss_fuzz_dir=(resolved_oss_fuzz_dir if backend == "oss-fuzz" else None),
        oss_fuzz_revision=oss_fuzz_revision,
        fuzz_seconds=args.fuzz_seconds,
        network_harness_config=args.network_harness_config,
        context_depth=args.context_depth,
        max_context_functions=args.context_functions,
        entry_batch_size=args.entry_batch_size,
        entry_diff=getattr(args, 'diff', None),
        entry_diff_depth=getattr(args, 'diff_depth', 6),
        fuzzgen_evidence=args.fuzzgen_evidence,
        hopper_constraints=args.hopper_constraints,
        winnie_evidence=args.winnie_evidence,
        rubick_a2dg=args.rubick_a2dg,
        rubick_nfa=args.rubick_nfa,
        netlifter_bnf=args.netlifter_bnf,
        research_repos_root=(
            args.research_repos_root
            or (
                Path(__file__).resolve().parents[3] / "research-repos"
                if (Path(__file__).resolve().parents[3] / "research-repos").is_dir()
                else None
            )
        ),
        scenario_command=scenario_command,
        scenario_channel=args.scenario_channel or "auto",
        scenario_input_env=args.scenario_input_env,
        scenario_host=args.scenario_host,
        scenario_port=args.scenario_port,
        scenario_socket_path=args.scenario_socket_path,
        scenario_startup_timeout=args.scenario_startup_timeout,
        scenario_step_timeout=args.scenario_step_timeout,
        scenario_response_limit=args.scenario_response_limit,
        scenario_response_protocol=args.scenario_response_protocol,
        scenario_attribution=args.scenario_attribution,
        require_differential_validation=args.require_differential_validation,
        scenario_environment=scenario_environment,
        scenario_evidence_paths=args.scenario_evidence,
        scenario_exploratory_drafts=args.scenario_exploratory_drafts,
        scenario_post_fuzz=args.scenario_post_fuzz,
        scenario_source_drafts=(
            args.source_only_drafts if args.source_only_drafts is not None
            else False
        ),
        max_source_drafts=args.max_source_drafts,
        max_exploratory_entries=args.max_exploratory_entries,
        max_input_trial_bytes=args.max_input_trial_bytes,
        max_scenario_steps=args.max_scenario_steps,
        max_scenario_candidates=args.max_scenario_candidates,
        max_scenario_variants_per_action=args.max_scenario_variants_per_action,
        max_scenario_search_states=args.max_scenario_search_states,
    ).normalized()
    if backend == "oss-fuzz":
        print(
            f"[{time.strftime('%H:%M:%S')}] OSS-Fuzz backend configured for later harness verification: "
            f"{oss_fuzz_project}/{oss_fuzz_fuzzer}; no canonical build prerequisite",
            file=sys.stderr, flush=True,
        )
    elif not build_command:
        print(
            f"[{time.strftime('%H:%M:%S')}] source discovery enabled without a build backend; "
            "generated artifacts cannot become QUALIFIED until a trusted build is configured",
            file=sys.stderr, flush=True,
        )
    elif args.verification_backend == "auto" and not args.build_command:
        print(
            f"[{time.strftime('%H:%M:%S')}] standalone Clang/libFuzzer build enabled "
            "for generated harnesses; no OSS-Fuzz project registration required",
            file=sys.stderr, flush=True,
        )
    # Verification blockers are known before costly indexing/model work.
    from .runtime.preflight import inspect_capabilities, source_analysis_binary
    for blocker in inspect_capabilities(project)["verification_blockers"]:
        print(f"[{time.strftime('%H:%M:%S')}] WARNING: {blocker}",
              file=sys.stderr, flush=True)
    excluded_paths = (
        [project.output_root]
        if project.source_root in project.output_root.parents
        else []
    )
    report = _prepare_fuzz_introspector(
        project.source_root,
        project.fuzz_introspector,
        default_fi_cache_root(project.source_root),
        require=project.require_fuzz_introspector,
        excluded_paths=excluded_paths,
        progress=lambda message: print(
            f"[{time.strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True
        ),
        compile_database=project.analysis_compile_database,
    )
    project = dataclasses.replace(project, fuzz_introspector=report)
    # Do this before starting app-server processes. A strict run with no FI
    # report must fail immediately rather than spend memory/time on model setup.
    analysis_preflight = StaticAnalyzer(
        project.source_root,
        project.fuzz_introspector,
        require_fuzz_introspector=project.require_fuzz_introspector,
        excluded_paths=excluded_paths,
        compile_database=project.analysis_compile_database,
        target_binary=source_analysis_binary(project),
    )
    print(
        f"[{time.strftime('%H:%M:%S')}] static analysis preflight started",
        file=sys.stderr,
        flush=True,
    )
    precomputed_analysis = analysis_preflight.index()
    print(
        f"[{time.strftime('%H:%M:%S')}] static analysis preflight completed: "
        f"{len(precomputed_analysis.functions)} functions, {len(precomputed_analysis.edges)} edges; "
        f"provider={precomputed_analysis.completeness.get('provider', 'unknown')}; "
        f"fuzz_introspector_authoritative={precomputed_analysis.completeness.get('authoritative', False)}",
        file=sys.stderr,
        flush=True,
    )
    for language, label in (("c", "C"), ("cpp", "C++")):
        completeness = precomputed_analysis.completeness
        failed = int(completeness.get(f"clang_{language}_ast_failed_files", 0))
        exhausted = bool(completeness.get(f"clang_{language}_ast_budget_exhausted"))
        if not (failed or exhausted):
            continue
        diagnostics = completeness.get(f"clang_{language}_ast_failure_diagnostics") or []
        first_error = (
            f"; first={diagnostics[0].get('file')}: {diagnostics[0].get('reason')}"
            if diagnostics else ""
        )
        print(
            f"[{time.strftime('%H:%M:%S')}] WARNING: {label} AST input-path "
            f"analysis incomplete: parsed={completeness.get(f'clang_{language}_ast_parsed_files', 0)}, "
            f"failed={failed}, budget_exhausted={exhausted}{first_error}; "
            "unparsed functions remain source-only navigation candidates",
            file=sys.stderr,
            flush=True,
        )
    # Do not compile the canonical upstream OSS-Fuzz fuzzer here. Its recipe
    # may target a different source revision or feature than the user's local
    # program. Build the GENERATED harness on demand in the verification phase.
    # Build errors remain explicit and can never produce QUALIFIED status.
    try:
        if svf_capture_failure is not None:
            reason = svf_capture_failure.read_text(
                encoding="utf-8", errors="replace"
            ).strip()
            precomputed_analysis = mark_svf_unavailable(
                precomputed_analysis,
                reason + f"; details={svf_capture_failure}",
            )
        else:
            precomputed_analysis = prepare_svf_analysis(
                precomputed_analysis,
                source_root=project.source_root,
                cache_root=default_svf_cache_root(project.source_root),
                research_repos_root=project.research_repos_root,
                enabled=project.svf_enabled,
                required=project.require_svf,
                evidence_path=project.svf_callgraph,
                bitcode=project.svf_bitcode,
                compile_database=project.analysis_compile_database,
                progress=lambda message: print(
                    f"[{time.strftime('%H:%M:%S')}] {message}",
                    file=sys.stderr,
                    flush=True,
                ),
            )
    except SVFError as exc:
        raise ValueError(f"SVF indirect-call preflight failed: {exc}") from exc
    print(
        f"[{time.strftime('%H:%M:%S')}] indirect-call preflight completed: "
        f"status={precomputed_analysis.completeness.get('svf_status', 'UNKNOWN')}, "
        f"mapped={precomputed_analysis.completeness.get('svf_indirect_edges_mapped', 0)}",
        file=sys.stderr,
        flush=True,
    )
    precomputed_usage_evidence, precomputed_upstream_runs = (
        _prepare_upstream_evidence(project, precomputed_analysis)
    )
    used_upstream = list(dict.fromkeys(
        status.provider
        for status in precomputed_usage_evidence.providers
        if status.state == "USED"
    ))
    print(
        f"[{time.strftime('%H:%M:%S')}] upstream evidence preflight completed: "
        + (
            f"used={','.join(used_upstream)}, "
            f"constraints={len(precomputed_usage_evidence.constraints)}, "
            f"sequences={len(precomputed_usage_evidence.sequences)}"
            if used_upstream
            else "no project-specific upstream output configured"
        ),
        file=sys.stderr,
        flush=True,
    )
    role_models = _resolve_role_models(args)
    if args.provider == "ollama":
        role_models = _resolve_ollama_models(args)
    elif args.provider in ("claude", "claude-api"):
        role_models = _resolve_claude_models(args)
    print(
        f"[{time.strftime('%H:%M:%S')}] model routing: "
        + ", ".join(f"{role}={model}" for role, model in role_models.items()),
        file=sys.stderr,
        flush=True,
    )
    if args.provider == "ollama":
        role_efforts = dict(DEFAULT_OLLAMA_ROLE_EFFORTS)
        base_llm = OllamaProvider(role_models=role_models, role_efforts=role_efforts,
                                  url=args.ollama_url, workers=args.workers)
    elif args.provider in ("claude", "claude-api"):
        # Codex's "ultra" has no Claude equivalent; "max" is Claude's highest level.
        claude_effort = "max" if args.effort == "ultra" else args.effort
        claude_options: dict[str, Any] = {
            "role_models": role_models,
            "role_efforts": {role: claude_effort for role in role_models},
            "workers": args.workers,
            "on_event": lambda message: print(
                f"[{time.strftime('%H:%M:%S')}] [CLAUDE] {message}",
                file=sys.stderr,
                flush=True,
            ),
        }
        base_llm = (
            ClaudeCodeProvider(executable=args.claude, **claude_options)
            if args.provider == "claude"
            else ClaudeProvider(**claude_options)
        )
        await base_llm.preflight()
    else:
        provider_options = {
            "cwd": source,
            "model": args.model,
            "role_models": role_models,
            "effort": args.effort,
            "executable": args.codex,
            "daybreak": args.daybreak,
            "max_turns_per_process": args.worker_recycle_turns,
            "on_event": lambda message: print(
                f"[{time.strftime('%H:%M:%S')}] [CONTEXT] {message}",
                file=sys.stderr,
                flush=True,
            ),
        }
        base_llm = (
            CodexAppServer(**provider_options)
            if args.workers == 1
            else CodexAppServerPool(workers=args.workers, **provider_options)
        )
        available_models = await base_llm.available_models()
        missing_models = sorted(set(role_models.values()) - available_models)
        if missing_models:
            available_text = ", ".join(sorted(available_models)) or "<none reported>"
            await base_llm.close()
            raise CodexAppServerError(
                "fixed role model(s) unavailable: "
                + ", ".join(missing_models)
                + f"; app-server reported: {available_text}. "
                "Use an explicit role override only if changing the fixed design is intended."
            )
    llm: LLMProvider = base_llm
    action_resume_continuations: list[dict[str, Any]] = []
    surface_resume_continuations: list[dict[str, Any]] = []
    request_resume_root: Path | None = None
    if args.resume_from:
        resume_path = args.resume_from.expanduser().resolve()
        trajectory = (
            resume_path / "trajectories" / "llm.jsonl"
            if resume_path.is_dir()
            else resume_path
        )
        if not trajectory.is_file():
            raise ValueError(f"resume trajectory does not exist: {trajectory}")
        action_resume_continuations = _load_action_resume_continuations(resume_path)
        surface_resume_continuations = _load_surface_resume_continuations(resume_path)
        if resume_path.is_dir():
            request_resume_root = resume_path
        cached = CachingLLM(
            base_llm,
            trajectory,
            on_event=lambda message: print(
                f"[{time.strftime('%H:%M:%S')}] [RESUME] {message}",
                file=sys.stderr,
                flush=True,
            ),
        )
        print(
            f"[{time.strftime('%H:%M:%S')}] loaded {cached.cached_calls} cached LLM calls from {trajectory}",
            file=sys.stderr,
            flush=True,
        )
        llm = cached
    try:
        summary = await HarnessCreator(
            project,
            llm,
            max_generation_attempts=args.max_attempts,
            dynamic_verification=args.dynamic_verification,
            agent_debug_console=args.agent_debug,
            precomputed_analysis=precomputed_analysis,
            precomputed_usage_evidence=precomputed_usage_evidence,
            precomputed_upstream_runs=precomputed_upstream_runs,
            action_resume_continuations=action_resume_continuations,
            surface_resume_continuations=surface_resume_continuations,
            request_resume_root=request_resume_root,
            stop_after_entries=context_workflow,
            progress=lambda message: print(
                f"[{time.strftime('%H:%M:%S')}] {message}",
                file=sys.stderr,
                flush=True,
            ),
        ).run()
        print(json.dumps(as_json(summary), ensure_ascii=False, indent=2))
        return 0 if summary.status == "COMPLETED" else 3
    except EntryStageCompleted as completed:
        entry_stage = completed
    finally:
        await llm.close()
    # The Entry model sessions are closed before the next stages open their own.
    return await context_pipeline.run_after_entries(args, entry_stage.run_dir, entry_stage.as_dict())


def _load_action_resume_continuations(resume_path: Path) -> list[dict[str, Any]]:
    if not resume_path.is_dir():
        return []
    artifact_dir = resume_path / "actions"
    continuation_path = artifact_dir / "continuations.json"
    # A VM failure can interrupt the orchestration after one Entry finished
    # but before the final Action artifact is written. Per-Entry progress is
    # atomically persisted by the agent and carries the same continuations.
    if not continuation_path.is_file():
        continuation_path = artifact_dir / "progress.json"
    if not continuation_path.is_file():
        return []
    continuation_data = json.loads(
        continuation_path.read_text(encoding="utf-8")
    )
    entries = (
        continuation_data.get(
            "entries" if continuation_path.name == "continuations.json"
            else "continuations"
        ) if isinstance(continuation_data, dict) else None
    )
    if not isinstance(entries, list) or not all(
        isinstance(item, dict) for item in entries
    ):
        raise ValueError(
            f"invalid Action continuation artifact: {continuation_path}"
        )
    return entries


def _load_surface_resume_continuations(resume_path: Path) -> list[dict[str, Any]]:
    if not resume_path.is_dir():
        return []
    continuation_path = resume_path / "input-surfaces" / "continuations.json"
    if not continuation_path.is_file():
        return []
    entries = json.loads(continuation_path.read_text(encoding="utf-8"))
    if not isinstance(entries, list) or not all(
        isinstance(item, dict) for item in entries
    ):
        raise ValueError(
            f"invalid Input Surface continuation artifact: {continuation_path}"
        )
    return entries


def _prepare_upstream_evidence(
    project: ProjectSpec,
    analysis: AnalysisBundle,
) -> tuple[UsageEvidenceBundle, list[UpstreamProcessResult]]:
    """Fail-fast and cache original-provider outputs before costly work."""

    configured_paths = [
        *project.fuzzgen_evidence,
        *project.hopper_constraints,
        *project.winnie_evidence,
        *project.rubick_a2dg,
        *project.rubick_nfa,
    ]
    rubick_nfas = list(project.rubick_nfa)
    upstream_runs: list[UpstreamProcessResult] = []
    if project.fuzzgen_evidence or project.rubick_a2dg:
        if project.research_repos_root is None:
            raise ValueError(
                "FuzzGen/RUBICK graph evidence requires --research-repos-root"
            )
        digest = hashlib.sha256()
        digest.update(b"harnesscreator-upstream-evidence-v1\0")
        for path in configured_paths:
            digest.update(str(path).encode("utf-8"))
            digest.update(b"\0")
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        for adapter_path in (
            project.research_repos_root / "LOCK.json",
            project.research_repos_root / "Rubick" / "rubick" / "source"
            / "automata" / "a2dg.py",
            project.research_repos_root / "Rubick" / "rubick" / "source"
            / "automata" / "harnesscreator_bridge.py",
        ):
            if adapter_path.is_file():
                digest.update(adapter_path.read_bytes())
        cache_root = (
            project.output_root
            / ".upstream-evidence"
            / digest.hexdigest()[:24]
        )
        rubick_inputs = list(project.rubick_a2dg)
        if project.fuzzgen_evidence:
            rubick_inputs.extend(fuzzgen_reports_to_rubick_a2dg(
                project.fuzzgen_evidence,
                cache_root / "rubick-input",
            ))
        rubick_output = cache_root / "rubick-nfa.json"
        cached_output = False
        if rubick_output.is_file():
            try:
                cached_payload = json.loads(rubick_output.read_text(encoding="utf-8"))
                cached_output = (
                    cached_payload.get("schema")
                    == "harnesscreator.rubick.nfa-set.v1"
                )
            except (OSError, json.JSONDecodeError):
                cached_output = False
        if cached_output:
            bridge = (
                project.research_repos_root
                / "Rubick"
                / "rubick"
                / "source"
                / "automata"
                / "harnesscreator_bridge.py"
            )
            upstream_runs.append(UpstreamProcessResult(
                provider="RUBICK",
                command=[str(bridge), "<digest-keyed-cache>"],
                cwd=str(bridge.parent),
                returncode=0,
                duration_seconds=0.0,
                stdout="reused validated digest-keyed RUBICK output",
                stderr="",
                output=rubick_output,
                cached=True,
            ))
        else:
            try:
                upstream_runs.append(run_rubick_a2dg(
                    project.research_repos_root,
                    rubick_inputs,
                    rubick_output,
                ))
            except UpstreamToolError as exc:
                raise ValueError(f"upstream evidence preflight failed: {exc}") from exc
        rubick_nfas.append(rubick_output)

    usage_evidence = load_usage_evidence(
        analysis,
        fuzzgen_reports=project.fuzzgen_evidence,
        hopper_constraints=project.hopper_constraints,
        winnie_reports=project.winnie_evidence,
        rubick_nfas=rubick_nfas,
        upstream_revisions=load_upstream_revisions(project.research_repos_root),
    )
    errors = [status for status in usage_evidence.providers if status.state == "ERROR"]
    if errors:
        raise ValueError(
            "configured upstream evidence failed validation: "
            + "; ".join(
                f"{status.provider} {status.source}: {status.reason}"
                for status in errors
            )
        )
    return usage_evidence, upstream_runs


def _resolve_ollama_models(args: argparse.Namespace) -> dict[str, str]:
    roles = {
        "entry_generator": "glm-5.3-flash:cloud",
        "entry_verifier": "glm-5.3:cloud", "input_surface": "glm-5.3:cloud",
        "entry_action_screen": "glm-5.3:cloud",
        "input_action": "glm-5.3:cloud",
        "state_dependency": "glm-5.3:cloud", "scenario_refiner": "glm-5.3:cloud",
        "harness_generator": "kimi-k2.7-code:cloud",
        "harness_verifier": "glm-5.3:cloud", "small_feature": "glm-5.3:cloud",
        "large_feature": "glm-5.3:cloud",
    }
    if args.model:
        roles = {role: args.model for role in roles}
    if args.candidate_model:
        roles["entry_generator"] = args.candidate_model
    if args.strong_model:
        for role in ("entry_verifier", "entry_action_screen", "input_surface", "input_action", "state_dependency", "scenario_refiner", "harness_verifier"):
            roles[role] = args.strong_model
    if args.coding_model:
        roles["harness_generator"] = args.coding_model
    return _for_workflow(args, roles)


def _resolve_claude_models(args: argparse.Namespace) -> dict[str, str]:
    roles = {role: DEFAULT_CLAUDE_MODEL for role in DEFAULT_ROLE_MODELS}
    if args.model:
        roles = {role: args.model for role in roles}
    if args.candidate_model:
        roles["entry_generator"] = args.candidate_model
    if args.strong_model:
        for role in ("entry_verifier", "entry_action_screen", "input_surface", "input_action", "state_dependency", "scenario_refiner", "harness_verifier"):
            roles[role] = args.strong_model
    if args.coding_model:
        roles["harness_generator"] = args.coding_model
    return _for_workflow(args, roles)


def _resolve_role_models(args: argparse.Namespace) -> dict[str, str]:
    role_models = dict(DEFAULT_ROLE_MODELS)
    if args.model:
        role_models = {role: args.model for role in role_models}
    if args.candidate_model:
        role_models["entry_generator"] = args.candidate_model
    if args.strong_model:
        for role in (
            "entry_verifier",
            "entry_action_screen",
            "input_surface",
            "input_action",
            "state_dependency",
            "harness_verifier",
        ):
            role_models[role] = args.strong_model
    if args.coding_model:
        role_models["harness_generator"] = args.coding_model
    return _for_workflow(args, role_models)


def _resolve_oss_fuzz_recipe(
    project: str,
    requested_fuzzer: str | None,
    *,
    oss_fuzz_dir: Path | None = None,
) -> tuple[str | None, str | None, str | None]:
    project_dir = (oss_fuzz_dir / "projects" / project) if oss_fuzz_dir else None
    if project_dir is None or not project_dir.is_dir():
        return requested_fuzzer, None, None
    fuzzer, source = _infer_fuzzer_from_oss_fuzz_project(
        project_dir, requested_fuzzer=requested_fuzzer, requested_source=None,
    )
    return fuzzer, source, _infer_oss_fuzz_checkout_path(project_dir)


_FUZZ_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}


def _infer_fuzzer_from_oss_fuzz_project(
    project_dir: Path,
    *,
    requested_fuzzer: str | None,
    requested_source: str | None,
) -> tuple[str | None, str | None]:
    """Infer a canonical target from the checked-in OSS-Fuzz recipe.

    This deliberately reads project metadata rather than maintaining a table
    of special projects.  Ambiguity is returned to the CLI so the user must
    select a target explicitly instead of silently choosing one.
    """

    sources = sorted(
        path for path in project_dir.iterdir()
        if path.is_file() and path.suffix.casefold() in _FUZZ_SOURCE_SUFFIXES
        and "LLVMFuzzerTestOneInput" in _read_optional_text(path)
    )
    source_by_name = {path.name: path for path in sources}
    source_by_stem: dict[str, list[Path]] = {}
    for path in sources:
        source_by_stem.setdefault(path.stem, []).append(path)

    source: Path | None = (
        source_by_name.get(Path(requested_source).name)
        if requested_source else None
    )
    if source is None and requested_fuzzer:
        matches = source_by_stem.get(requested_fuzzer, [])
        if len(matches) == 1:
            source = matches[0]
    if source is None and len(sources) == 1:
        source = sources[0]

    fuzzer = requested_fuzzer
    if fuzzer is None:
        option_targets = sorted({
            path.stem for path in project_dir.glob("*.options") if path.is_file()
        })
        if len(option_targets) == 1:
            fuzzer = option_targets[0]
        elif source is not None and len(sources) == 1:
            fuzzer = source.stem

    return fuzzer, source.name if source is not None else requested_source


def _infer_oss_fuzz_checkout_path(project_dir: Path) -> str | None:
    """Infer the application checkout location from its OSS-Fuzz recipe."""

    build_text = _read_optional_text(project_dir / "build.sh")
    docker_text = _read_optional_text(project_dir / "Dockerfile")

    # An explicit $SRC-relative cd in build.sh is the strongest evidence: it
    # is the directory in which the canonical recipe actually compiles/links.
    build_paths = re.findall(
        r"(?:^|[;&|]\s*|\n)\s*cd\s+[\"']?\$\{?SRC\}?/([A-Za-z0-9_.\-/]+)",
        build_text,
    )
    if build_paths:
        return "/src/" + build_paths[-1].strip("/")

    workdirs = re.findall(r"(?im)^\s*WORKDIR\s+([^\s#]+)", docker_text)
    if workdirs:
        workdir = workdirs[-1].strip("\"'")
        normalized = _normalize_oss_fuzz_container_path(workdir)
        if normalized:
            return normalized

    # If WORKDIR is absent, use the destination explicitly supplied to the
    # source clone.  Do not derive it from the project name.
    clone_destinations = re.findall(
        r"(?im)^\s*RUN\s+.*?\bgit\s+clone\b[^\n&;]*\s+([A-Za-z0-9_.\-/]+)\s*$",
        docker_text,
    )
    if clone_destinations:
        return _normalize_oss_fuzz_container_path(clone_destinations[-1])
    return None


def _normalize_oss_fuzz_container_path(value: str) -> str | None:
    value = value.strip().strip("\"'")
    value = re.sub(r"^\$\{?SRC\}?/?", "", value)
    if not value or value in {".", "/src"}:
        return None
    if value.startswith("/src/"):
        return "/src/" + value[len("/src/"):].strip("/")
    if value.startswith("/") or "$" in value:
        return None
    return "/src/" + value.strip("/")


def _read_optional_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""



def _prepare_fuzz_introspector(
    source: Path,
    explicit_report: Path | None,
    cache_root: Path,
    *,
    require: bool,
    excluded_paths: tuple[Path, ...] | list[Path],
    progress,
    compile_database: Path | None = None,
) -> Path | None:
    if explicit_report is not None:
        report = explicit_report.expanduser().resolve()
        progress(f"Fuzz Introspector explicit report selected: {report}")
        return report
    try:
        result = FuzzIntrospectorRunner(
            source,
            cache_root,
            excluded_paths=excluded_paths,
            progress=progress,
            compile_database=compile_database,
        ).run()
        return result.report
    except FuzzIntrospectorError as exc:
        if require:
            raise ValueError(
                "automatic Fuzz Introspector analysis is required but failed: " + str(exc)
            ) from exc
        progress(
            "WARNING: automatic Fuzz Introspector analysis failed; "
            f"bootstrap source analysis was explicitly allowed: {exc}"
        )
        return None


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        from .contexts.cli import dispatch as dispatch_context_command
        handled = dispatch_context_command(args)
        if handled is not None:
            return handled
        if args.command == "report":
            from .runtime.run_report import summarize_run, format_run_report
            data = summarize_run(args.run_dir)
            print(json.dumps(data, ensure_ascii=False, indent=2) if args.json else format_run_report(data))
            return 0
        if args.command == "instrument-server":
            from .runtime.stateafl_build import StateAFLBuildSpec, build_stateafl_server
            result = build_stateafl_server(StateAFLBuildSpec(
                source_root=args.source_root,
                output_dir=args.output,
                compiler=args.stateafl_cc,
                cxx_compiler=args.stateafl_cxx,
                build_command=tuple(shlex.split(args.build_command)),
                build_steps=tuple(tuple(shlex.split(step)) for step in args.build_step),
                server_relative_path=args.server_relative_path,
                timeout_seconds=args.timeout_seconds,
                linker_flags=tuple(args.linker_flag),
                container_image=args.container_image,
            ))
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result["instrumentation_evidence"] is True else 2
        if args.command == "network-fuzz":
            from .runtime.stateafl_campaign import (
                StateAFLCampaignSpec, prepare_stateafl_campaign,
                run_stateafl_campaign,
            )
            spec = StateAFLCampaignSpec(
                run_dir=args.run_dir, output_dir=args.output,
                afl_fuzz=args.stateafl_fuzz,
                server_command=tuple(shlex.split(args.server_command)),
                transport=args.transport, host=args.host, port=args.port,
                seconds=args.seconds, seed_tier=args.seed_tier,
                research_only=args.research_only,
                state_aware=args.state_aware,
                startup_delay_us=args.startup_delay_us,
                execution_timeout_ms=args.execution_timeout_ms,
                memory_limit_mb=args.memory_limit_mb,
                memory_limit_unlimited=args.no_memory_limit,
                graceful_sigterm=args.graceful_sigterm,
                replay_server_command=(
                    tuple(shlex.split(args.replay_server_command))
                    if args.replay_server_command else ()
                ),
                replay_timeout_ms=args.replay_timeout_ms,
                server_build_manifest=args.server_build_manifest,
            )
            result = (
                prepare_stateafl_campaign(spec)
                if args.prepare_only else run_stateafl_campaign(spec)
            )
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result["status"] in {
                "PREPARED_UNQUALIFIED", "FUZZING_OBSERVED_UNQUALIFIED",
            } else 3
        if args.command == "analyze":
            return _analyze(args)
        if args.command == "doctor":
            return asyncio.run(_doctor(args))
        if args.command == "run":
            return asyncio.run(_run(args))
    except (ValueError, FileNotFoundError, CodexAppServerError) as exc:
        print(f"harnesscreator: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("harnesscreator: interrupted", file=sys.stderr)
        return 130
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
