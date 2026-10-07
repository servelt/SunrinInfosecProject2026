from __future__ import annotations

import argparse
import asyncio
import dataclasses
import getpass
import hashlib
import json
import shlex
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .analysis import GraphStore, FuzzIntrospectorError, FuzzIntrospectorRunner, StaticAnalyzer
from .llm import (
    CachingLLM,
    CodexAppServer,
    CodexAppServerError,
    CodexAppServerPool,
    LLMProvider,
)
from .models import ProjectSpec, as_json
from .orchestrator import HarnessCreator
from .runtime import (
    OssFuzzBackendError,
    QuartetOssFuzzVerifierAgent,
    preflight_oss_fuzz_backend,
)


DEFAULT_ROLE_MODELS: dict[str, str] = {
    # Luna is the available low-cost/high-throughput tier used for recall-first
    # candidate collection.  Evidence decisions and code generation stay on
    # the stronger fixed model below.
    "entry_generator": "gpt-5.6-luna",
    "entry_verifier": "gpt-5.5",
    "small_feature": "gpt-5.5",
    "large_feature": "gpt-5.5",
    "harness_generator": "gpt-5.5",
    "harness_verifier": "gpt-5.5",
}


# Canonical source/binary pair from the OSS-Fuzz project recipe. Projects in
# QuartetFuzz's gold_source_paths.json are resolved dynamically; memcached is
# special because build.sh moves this source into the checkout before linking.
OSS_FUZZ_KNOWN_TARGETS: dict[str, tuple[str, str, str]] = {
    "memcached": ("fuzzer_proxy", "fuzzer_proxy.c", "/src/memcached"),
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="harnesscreator",
        description="Evidence-driven fuzz harness generation through Codex app-server",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="check the local Codex app-server connection")
    doctor.add_argument("--source", type=Path, default=Path.cwd())
    doctor.add_argument("--codex", default="codex")
    doctor.add_argument("--workers", type=int, default=1)
    doctor.add_argument(
        "--turn",
        action="store_true",
        help="also execute one tiny structured-output model turn",
    )

    analyze = subparsers.add_parser("analyze", help="run static indexing without an LLM")
    analyze.add_argument("source", type=Path)
    analyze.add_argument(
        "--fuzz-introspector",
        type=Path,
        help="use an existing FI report instead of running Fuzz Introspector automatically",
    )
    analyze.add_argument(
        "--require-fuzz-introspector",
        action="store_true",
        help="fail instead of using the bootstrap source indexer",
    )
    analyze.add_argument("--json", action="store_true", help="print complete function metadata")

    run = subparsers.add_parser("run", help="run the complete harness creation workflow")
    run.add_argument("source", type=Path)
    run.add_argument("--output", type=Path, default=Path("harnesscreator-runs"))
    run.add_argument("--name")
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
        help="require authoritative FI metadata (default)",
    )
    analysis_policy.add_argument(
        "--allow-source-analysis",
        dest="require_fuzz_introspector",
        action="store_false",
        help="run FI first, but allow bootstrap source indexing if automatic FI analysis fails",
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
        help=f"override verifier and feature agents (fixed default: {DEFAULT_ROLE_MODELS['entry_verifier']})",
    )
    run.add_argument(
        "--coding-model",
        help=f"override Harness Generator (fixed default: {DEFAULT_ROLE_MODELS['harness_generator']})",
    )
    run.add_argument("--effort", default="high", choices=["low", "medium", "high", "xhigh", "max", "ultra"])
    run.add_argument("--codex", default="codex")
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
            "ordered stateful sessions replay as a whole, sessions changed at their first turn rerun "
            "live, and late divergence stops instead of losing thread history"
        ),
    )
    run.add_argument("--fuzz-seconds", type=int, default=300)
    run.add_argument("--context-depth", type=int, default=3)
    run.add_argument("--context-functions", type=int, default=16)
    run.add_argument(
        "--entry-batch-size",
        type=int,
        default=32,
        help="maximum source excerpts per Entry Generator model call (prompt-size cap also applies)",
    )
    run.add_argument(
        "--max-attempts",
        type=int,
        default=8,
        help=(
            "maximum generate/audit/build repair attempts per Large Feature "
            "(default: 8; a safety limit, not a normal stopping target)"
        ),
    )
    run.add_argument(
        "--verification-backend",
        choices=["auto", "oss-fuzz", "command"],
        default="auto",
        help=(
            "auto selects command when --build-command/--binary are supplied; "
            "otherwise use the QuartetFuzz OSS-Fuzz backend"
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
        "--quartet-root",
        type=Path,
        help="path to the checked-out QuartetFuzz implementation used by the OSS-Fuzz backend",
    )
    run.add_argument(
        "--oss-fuzz-dir",
        type=Path,
        help="existing OSS-Fuzz checkout; omitted lets QuartetFuzz prepare its pinned checkout",
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
            "always build and require sanitizer instrumentation; when enabled, also replay seeds, verify "
            "five-seed anchor and per-variant GDB reachability, attribute crashes, and fuzz"
            "; disabling it skips runtime probes only and produces a build-verified DRAFT, never a qualified run"
        ),
    )
    run.add_argument(
        "--agent-debug",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="also print structured agent decisions and graph traversal summaries live",
    )
    return parser


async def _doctor(args: argparse.Namespace) -> int:
    source = args.source.expanduser().resolve()
    if not source.is_dir():
        raise ValueError(f"source root is not a directory: {source}")
    client = (
        CodexAppServer(cwd=source, executable=args.codex)
        if args.workers == 1
        else CodexAppServerPool(cwd=source, executable=args.codex, workers=args.workers)
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


def _analyze(args: argparse.Namespace) -> int:
    source = args.source.expanduser().resolve()
    cache_key = hashlib.sha256(str(source).encode()).hexdigest()[:16]
    report = _prepare_fuzz_introspector(
        source,
        args.fuzz_introspector,
        Path(tempfile.gettempdir()) / "harnesscreator-fi-cache" / cache_key,
        require=args.require_fuzz_introspector,
        excluded_paths=(),
        progress=lambda message: print(
            f"[{time.strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True
        ),
    )
    bundle = StaticAnalyzer(
        source,
        report,
        require_fuzz_introspector=args.require_fuzz_introspector,
    ).index()
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
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


async def _run(args: argparse.Namespace) -> int:
    source = args.source.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if not source.is_dir():
        raise ValueError(f"source root is not a directory: {source}")
    binary: str | Path | None = args.binary
    if binary and not any(token in str(binary) for token in ("{source_root}", "{output}")):
        binary = Path(binary).expanduser().resolve()
    build_command = shlex.split(args.build_command) if args.build_command else []
    backend = args.verification_backend
    if backend == "auto":
        backend = "command" if build_command or args.binary else "oss-fuzz"
    if backend == "command" and (not build_command or not args.binary):
        raise ValueError(
            "the command verification backend requires both --build-command and --binary so every "
            "accepted draft is linked against the real project"
        )
    if backend == "oss-fuzz" and (build_command or args.binary):
        raise ValueError(
            "do not combine the OSS-Fuzz backend with --build-command/--binary; select "
            "--verification-backend command for a custom build"
        )

    quartet_root: Path | None = None
    oss_fuzz_project: str | None = None
    oss_fuzz_fuzzer: str | None = None
    oss_fuzz_source_path: str | None = None
    oss_fuzz_revision: str | None = None
    resolved_oss_fuzz_dir: Path | None = None
    harness_source_filename = args.harness_source_filename
    if backend == "oss-fuzz":
        quartet_root = (
            args.quartet_root.expanduser().resolve()
            if args.quartet_root
            else Path(__file__).resolve().parents[3] / "QuartetFuzz" / "QuartetFuzz"
        )
        if not (quartet_root / "harness" / "checker" / "dynamic.py").is_file():
            raise ValueError(
                f"QuartetFuzz checkout not found at {quartet_root}; pass --quartet-root"
            )
        oss_fuzz_project = args.oss_fuzz_project or args.name or source.name
        oss_fuzz_fuzzer, inferred_source, inferred_checkout = _resolve_oss_fuzz_recipe(
            quartet_root, oss_fuzz_project, args.oss_fuzz_fuzzer
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
        if args.oss_fuzz_dir:
            explicit_oss_fuzz = args.oss_fuzz_dir.expanduser().resolve()
            if not (explicit_oss_fuzz / "infra" / "helper.py").is_file():
                raise ValueError(
                    f"--oss-fuzz-dir is not a usable OSS-Fuzz checkout: {explicit_oss_fuzz}"
                )
        resolved_oss_fuzz_dir, oss_fuzz_revision = _prepare_oss_fuzz_checkout(
            quartet_root,
            args.oss_fuzz_dir,
        )
        print(
            f"[{time.strftime('%H:%M:%S')}] OSS-Fuzz reference ready: "
            f"{resolved_oss_fuzz_dir} @ {oss_fuzz_revision[:12]}",
            file=sys.stderr,
            flush=True,
        )
    else:
        harness_source_filename = harness_source_filename or "fuzz_target.cc"

    if backend == "command" and args.dynamic_verification and not shutil.which("gdb"):
        raise ValueError(
            "dynamic verification requires gdb for crash attribution, five-seed anchor reachability, "
            "and per-variant target reachability"
        )
    project = ProjectSpec(
        source_root=source,
        output_root=output,
        name=args.name or source.name,
        fuzz_introspector=args.fuzz_introspector,
        require_fuzz_introspector=args.require_fuzz_introspector,
        verification_backend=backend,
        build_command=build_command,
        harness_binary=binary,
        harness_source_filename=harness_source_filename,
        oss_fuzz_project=oss_fuzz_project,
        oss_fuzz_fuzzer=oss_fuzz_fuzzer,
        oss_fuzz_source_path=oss_fuzz_source_path,
        oss_fuzz_dir=(resolved_oss_fuzz_dir if backend == "oss-fuzz" else None),
        oss_fuzz_revision=oss_fuzz_revision,
        quartet_root=quartet_root,
        fuzz_seconds=args.fuzz_seconds,
        context_depth=args.context_depth,
        max_context_functions=args.context_functions,
        entry_batch_size=args.entry_batch_size,
    ).normalized()
    if backend == "oss-fuzz":
        try:
            backend_preflight = preflight_oss_fuzz_backend(project)
        except OssFuzzBackendError as exc:
            raise ValueError(f"OSS-Fuzz verification preflight failed: {exc}") from exc
        print(
            f"[{time.strftime('%H:%M:%S')}] OSS-Fuzz verification preflight passed: "
            f"project={oss_fuzz_project}/{oss_fuzz_fuzzer}, "
            f"docker={backend_preflight['docker_server_version']}",
            file=sys.stderr,
            flush=True,
        )
    excluded_paths = (
        [project.output_root]
        if project.source_root in project.output_root.parents
        else []
    )
    report = _prepare_fuzz_introspector(
        project.source_root,
        project.fuzz_introspector,
        project.output_root / ".fuzz-introspector",
        require=project.require_fuzz_introspector,
        excluded_paths=excluded_paths,
        progress=lambda message: print(
            f"[{time.strftime('%H:%M:%S')}] {message}", file=sys.stderr, flush=True
        ),
    )
    project = dataclasses.replace(project, fuzz_introspector=report)
    # Do this before starting app-server processes. A strict run with no FI
    # report must fail immediately rather than spend memory/time on model setup.
    analysis_preflight = StaticAnalyzer(
        project.source_root,
        project.fuzz_introspector,
        require_fuzz_introspector=project.require_fuzz_introspector,
        excluded_paths=excluded_paths,
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
        f"authoritative={precomputed_analysis.completeness.get('authoritative', False)}",
        file=sys.stderr,
        flush=True,
    )
    if backend == "oss-fuzz":
        build_probe = QuartetOssFuzzVerifierAgent(
            project,
            GraphStore(precomputed_analysis),
            progress=lambda message: print(
                f"[{time.strftime('%H:%M:%S')}] {message}",
                file=sys.stderr,
                flush=True,
            ),
        )
        try:
            await build_probe.probe_canonical_build()
        except OssFuzzBackendError as exc:
            raise ValueError(
                f"OSS-Fuzz canonical build/runtime preflight failed: {exc}"
            ) from exc
        finally:
            await build_probe.close()
        project = dataclasses.replace(
            project,
            canonical_oss_fuzz_preflight_passed=True,
        )
    role_models = _resolve_role_models(args)
    print(
        f"[{time.strftime('%H:%M:%S')}] model routing: "
        + ", ".join(f"{role}={model}" for role, model in role_models.items()),
        file=sys.stderr,
        flush=True,
    )
    provider_options = {
        "cwd": source,
        "model": args.model,
        "role_models": role_models,
        "effort": args.effort,
        "executable": args.codex,
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
    if args.resume_from:
        resume_path = args.resume_from.expanduser().resolve()
        trajectory = (
            resume_path / "trajectories" / "llm.jsonl"
            if resume_path.is_dir()
            else resume_path
        )
        if not trajectory.is_file():
            raise ValueError(f"resume trajectory does not exist: {trajectory}")
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
            progress=lambda message: print(
                f"[{time.strftime('%H:%M:%S')}] {message}",
                file=sys.stderr,
                flush=True,
            ),
        ).run()
        print(json.dumps(as_json(summary), ensure_ascii=False, indent=2))
        return 0 if summary.status == "COMPLETED" else 3
    finally:
        await llm.close()


def _resolve_role_models(args: argparse.Namespace) -> dict[str, str]:
    role_models = dict(DEFAULT_ROLE_MODELS)
    if args.model:
        role_models = {role: args.model for role in role_models}
    if args.candidate_model:
        role_models["entry_generator"] = args.candidate_model
    if args.strong_model:
        for role in (
            "entry_verifier",
            "small_feature",
            "large_feature",
            "harness_verifier",
        ):
            role_models[role] = args.strong_model
    if args.coding_model:
        role_models["harness_generator"] = args.coding_model
    return role_models


def _resolve_oss_fuzz_recipe(
    quartet_root: Path,
    project: str,
    requested_fuzzer: str | None,
) -> tuple[str | None, str | None, str | None]:
    known = OSS_FUZZ_KNOWN_TARGETS.get(project)
    if known and (requested_fuzzer is None or requested_fuzzer == known[0]):
        return requested_fuzzer or known[0], known[1], known[2]

    mapping_path = quartet_root / "dataset" / "gold_source_paths.json"
    mappings: dict[str, str] = {}
    if mapping_path.is_file():
        try:
            raw = json.loads(mapping_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                mappings = {
                    str(key): str(value)
                    for key, value in raw.items()
                    if str(key).startswith(project + "/")
                }
        except (OSError, json.JSONDecodeError):
            mappings = {}
    if requested_fuzzer:
        path = mappings.get(f"{project}/{requested_fuzzer}")
        return requested_fuzzer, Path(path).name if path else None, None
    if len(mappings) == 1:
        key, path = next(iter(mappings.items()))
        return key.split("/", 1)[1], Path(path).name, None
    return None, None, None


def _prepare_oss_fuzz_checkout(
    quartet_root: Path,
    requested: Path | None,
) -> tuple[Path, str]:
    """Prepare the same pinned OSS-Fuzz source used by Quartet before LLM work."""

    root_text = str(quartet_root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    try:
        from harness.builder import ensure_oss_fuzz  # type: ignore[import-not-found]
        from infra.ossfuzz.workspace import (  # type: ignore[import-not-found]
            PINNED_OSS_FUZZ_COMMIT,
        )
    except Exception as exc:
        raise ValueError(
            f"failed to load QuartetFuzz OSS-Fuzz workspace helpers: {exc}"
        ) from exc
    checkout = (
        requested.expanduser().resolve()
        if requested
        else Path(f"/tmp/agf-{getpass.getuser()}/oss-fuzz-pinned")
    )
    try:
        prepared = ensure_oss_fuzz(checkout)
    except Exception as exc:
        raise ValueError(f"failed to prepare pinned OSS-Fuzz checkout: {exc}") from exc
    return Path(prepared).resolve(), str(PINNED_OSS_FUZZ_COMMIT)


def _prepare_fuzz_introspector(
    source: Path,
    explicit_report: Path | None,
    cache_root: Path,
    *,
    require: bool,
    excluded_paths: tuple[Path, ...] | list[Path],
    progress,
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
