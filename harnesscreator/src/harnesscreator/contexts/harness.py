"""Harness stage of the input-context workflow.

One harness is produced per (input context, delivery).  The fuzz input is the
whole byte stream delivered to the context's Entry of that delivery: libFuzzer
``Data/Size`` replaces an entire verified seed and there are no fixed setup
requests.

This module does not contain a generator of its own.  It converts a context
and its verified seeds into the objects the existing scenario generator
consumes (one synthetic ``ExternalActionSchema``, a single-step
``ScenarioCandidate``/``ScenarioWitness`` and the ``HarnessPlan`` derived from
them) and then repeats the orchestrator's post-witness sequence:

    plan -> generate -> static HC audit -> independent review -> build -> replay

A seed is a whole-stream replay accepted by the original program.  It is not a
per-request attribution proof, so the witness is ``REPLAYED_RUNTIME`` and no
result of this stage is ever QUALIFIED.  Coverage equivalence against the
original program is a separate stage.
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..agents.scenario_harness import (
    ScenarioHarnessGeneratorAgent,
    ScenarioStaticHarnessGate,
    action_harness_function_ids,
    build_harness_plan,
)
from ..analysis.graph import GraphStore
from ..llm.base import LLMProvider, close_llm_session
from ..models import (
    ActionActor,
    ActionExample,
    AnalysisBundle,
    AnalysisDisposition,
    CallEdge,
    CheckStatus,
    EntryRecord,
    EntrySiteKind,
    Evidence,
    ExternalActionSchema,
    FunctionMetadata,
    GateCheck,
    GateReport,
    HarnessPlan,
    ProjectSpec,
    RuntimeStepObservation,
    ScenarioCandidate,
    ScenarioStatus,
    ScenarioStep,
    ScenarioWitness,
    Verdict,
    stable_id,
)
from ..orchestrator import _build_failure_excerpt, _gate_feedback, _gate_report_signature
from ..runtime.contracts import ContractAudit, audit_harness_plan
from ..runtime.native_build import NativeBuildUnresolved, build_native
from ..runtime.runner import SANITIZER_MARKERS, CommandRunner
from ..storage import ArtifactStore

OUTPUT_DIR = "context-harnesses"

STATUS_BUILT_REPLAYED = "BUILT_REPLAYED_NOT_QUALIFIED"
STATUS_SEED_EQUIVALENT = "BUILT_SEED_EQUIVALENT_NOT_QUALIFIED"
STATUS_SEED_MISMATCH = "BUILT_SEED_MISMATCH"
STATUS_BUILT_REPLAY_FAILED = "BUILT_REPLAY_FAILED"
STATUS_BUILD_FAILED = "BUILD_FAILED"
STATUS_GENERATED_NOT_BUILT = "GENERATED_NOT_BUILT"
STATUS_REVIEW_FAILED = "REVIEW_FAILED"
STATUS_STATIC_FAILED = "STATIC_FAILED"
STATUS_GENERATION_BLOCKED = "GENERATION_BLOCKED"

# How far an attempt got.  The summary row of a context+delivery describes its
# furthest attempt; every attempt stays listed under ``attempts``.
_PROGRESS = {
    STATUS_GENERATION_BLOCKED: 0,
    STATUS_STATIC_FAILED: 1,
    STATUS_REVIEW_FAILED: 2,
    STATUS_BUILD_FAILED: 3,
    STATUS_GENERATED_NOT_BUILT: 3,
    STATUS_BUILT_REPLAY_FAILED: 4,
    STATUS_SEED_MISMATCH: 5,
    STATUS_BUILT_REPLAYED: 6,
    STATUS_SEED_EQUIVALENT: 7,
}

# The static gate ties HC11 and HC16 to ``witness.status is PROVEN_RUNTIME``.
# A whole-stream seed can never satisfy that, so these two stay recorded as
# not proven instead of blocking the draft.  This is the same carve-out the
# orchestrator applies to OBSERVED/REPLAYED witnesses; every other check
# still blocks.
NOT_PROVEN_CHECK_IDS = frozenset({"HC11", "HC16"})

# HC08 and HC10 ask for a static call path from the Entry function to the
# target.  In an input context the acquisition and its interpretation are
# joined by a common driver function instead (e.g. tcp_read and the command
# parser are both called from drive_machine), so that path does not exist.
# When the built harness can be measured, the two checks are decided by seed
# equivalence instead: every function the original program executed for a
# verified seed (beyond a run with no input) must also execute in the harness.
SEED_EQUIVALENCE_CHECK_IDS = frozenset({"HC08", "HC10"})

DELIVERY_CHOICES = ("stream", "datagram", "file", "argv", "env", "stdin")
_CPP_SUFFIXES = {".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"}
_REPLAY_TIMEOUT_SECONDS = 60.0
_QUALIFICATION_NOTE = (
    "No harness of this stage is QUALIFIED: seeds are whole-stream replays without "
    "request-level attribution, and coverage equivalence against the original program "
    "is not checked here."
)


def add_harness_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--context", action="append", default=None, metavar="ID",
        help="input context to build a harness for (repeatable; default: all network contexts)")
    parser.add_argument(
        "--delivery", choices=DELIVERY_CHOICES, default=None,
        help="only this delivery (default: every delivery of each selected context)")
    parser.add_argument(
        "--source", type=Path, default=None, metavar="PATH",
        help="original source root (default: source_root recorded in RUN/project.json)")
    parser.add_argument(
        "--compile-database", type=Path, default=None, metavar="PATH",
        help="compile_commands.json of the original build "
             "(default: analysis_compile_database recorded in RUN/project.json)")
    parser.add_argument(
        "--target-binary", type=Path, default=None, metavar="PATH",
        help="original executable whose link closure the harness build must reuse")
    parser.add_argument(
        "--attempts", type=int, default=2, metavar="N",
        help="generation attempts per context and delivery (default: 2)")
    parser.add_argument(
        "--no-build", action="store_true",
        help="stop after the static audit and independent review")


# --------------------------------------------------------------------------
# Run artifacts


def _rows(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        raise ValueError(f"required run artifact is missing: {path}")
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise ValueError(f"{path}:{number}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{number}: row is not an object")
            rows.append(row)
    return rows


def _known(cls: type, row: dict[str, Any]) -> dict[str, Any]:
    names = {item.name for item in dataclasses.fields(cls)}
    return {key: value for key, value in row.items() if key in names}


def load_graph(run_dir: Path) -> GraphStore:
    """Rebuild the call graph of a finished analysis run."""

    analysis = Path(run_dir) / "analysis"
    functions: dict[str, FunctionMetadata] = {}
    for row in _rows(analysis / "functions.jsonl"):
        try:
            function = FunctionMetadata(**_known(FunctionMetadata, row))
        except TypeError as exc:
            raise ValueError(f"functions.jsonl row lacks a required field: {exc}") from exc
        functions[function.function_id] = function
    edges: list[CallEdge] = []
    for row in _rows(analysis / "edges.jsonl"):
        fields = _known(CallEdge, row)
        if "caller_id" not in fields or "callee_id" not in fields:
            raise ValueError("edges.jsonl row lacks caller_id or callee_id")
        fields.setdefault("edge_id", stable_id(
            "edge", fields["caller_id"], fields["callee_id"],
            fields.get("line"), fields.get("kind", "direct")))
        edges.append(CallEdge(**fields))
    completeness: dict[str, Any] = {}
    completeness_file = analysis / "completeness.json"
    if completeness_file.is_file():
        loaded = json.loads(completeness_file.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            completeness = loaded
    return GraphStore(AnalysisBundle(functions=functions, edges=edges, completeness=completeness))


def load_verified_entries(run_dir: Path) -> dict[str, EntryRecord]:
    """Reload ``entries/verified.jsonl`` with the orchestrator's enum coercion."""

    records: dict[str, EntryRecord] = {}
    for raw in _rows(Path(run_dir) / "entries" / "verified.jsonl"):
        row = _known(EntryRecord, raw)
        try:
            row["status"] = Verdict(row["status"])
            row["site_kind"] = EntrySiteKind(row.get("site_kind", "DIRECT_ACQUISITION"))
            row["analysis_disposition"] = AnalysisDisposition(
                row.get("analysis_disposition", "COMPLETE"))
            row["evidence"] = [
                Evidence(**_known(Evidence, item)) for item in row.get("evidence", [])]
            record = EntryRecord(**row)
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"entries/verified.jsonl row cannot be loaded: {exc}") from exc
        records[record.entry_id] = record
    return records


def load_contexts(run_dir: Path) -> list[dict[str, Any]]:
    contexts = _rows(Path(run_dir) / "contexts" / "contexts.jsonl")
    for context in contexts:
        if not context.get("context_id"):
            raise ValueError("contexts.jsonl row has no context_id")
    return contexts


@dataclass(frozen=True)
class ContextSeed:
    seed_id: str
    messages: tuple[bytes, ...]
    responses: tuple[bytes, ...]
    covered_target_function_ids: tuple[str, ...]
    origin: str
    rationale: str
    functions_beyond_baseline: tuple[str, ...] = ()

    @property
    def data(self) -> bytes:
        """The bytes the harness receives: every message of the seed, in order."""
        return b"".join(self.messages)


def _expected_functions(raw: dict[str, Any]) -> tuple[str, ...]:
    """Functions the harness must execute for this seed.

    Whole-input delivery is how a harness delivers a seed, so that measurement
    is preferred.  When the executing thread was measured too, only functions
    run by the thread that ran the Entry function count: other threads do
    periodic or shutdown work that a harness need not reproduce.
    """

    functions = [str(item) for item in (
        raw["target_functions_beyond_baseline_whole_input"]
        if "target_functions_beyond_baseline_whole_input" in raw
        else raw.get("target_functions_beyond_baseline") or [])]
    if raw.get("request_thread_trace") == "measured":
        request = set(raw.get("request_thread_functions") or [])
        functions = [name for name in functions if name in request]
    return tuple(functions)


def load_seeds(run_dir: Path, context_id: str, delivery: str) -> tuple[list[ContextSeed], list[str]]:
    """Verified seeds of one context and delivery, plus the files that were not usable."""

    directory = Path(run_dir) / "seeds" / "corpus" / context_id
    seeds: list[ContextSeed] = []
    skipped: list[str] = []
    if not directory.is_dir():
        return seeds, skipped
    for path in sorted(directory.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if raw.get("context_id", context_id) != context_id or raw.get("delivery") != delivery:
                continue
            seed = ContextSeed(
                seed_id=str(raw.get("seed_id") or path.stem),
                messages=tuple(bytes.fromhex(item) for item in raw["messages_hex"]),
                responses=tuple(bytes.fromhex(item) for item in raw.get("responses_hex") or []),
                covered_target_function_ids=tuple(
                    str(item) for item in raw.get("covered_target_function_ids") or []),
                origin=str(raw.get("origin", "")),
                rationale=str(raw.get("rationale", "")),
                # Prefer the measurement taken with whole-input delivery: that is
                # how the harness delivers the seed.
                functions_beyond_baseline=_expected_functions(raw),
            )
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            skipped.append(f"{path.name}: {type(exc).__name__}: {exc}")
            continue
        if not seed.data:
            skipped.append(f"{path.name}: seed has no bytes")
            continue
        seeds.append(seed)
    seeds.sort(key=lambda item: item.seed_id)
    return seeds, skipped


# --------------------------------------------------------------------------
# Context + seeds -> the generator's inputs


def _channel(resource_kind: str, delivery: str) -> str:
    """Transport name understood by ``build_harness_plan``; empty when there is none."""

    if delivery in {"stdin", "file", "argv", "env"}:
        return delivery
    if delivery == "stream":
        return {"network": "tcp", "local_ipc": "unix_stream"}.get(resource_kind, "")
    if delivery == "datagram" and resource_kind == "network":
        return "udp"
    return ""


@dataclass
class HarnessUnit:
    """Everything the existing generator needs for one context and delivery."""

    context_id: str
    delivery: str
    channel: str
    entry: dict[str, Any]
    interpreter_function_id: str
    action: ExternalActionSchema
    candidate: ScenarioCandidate
    witness: ScenarioWitness
    plan: HarnessPlan
    plan_audit: ContractAudit
    seeds: list[ContextSeed]
    notes: list[str]


def build_unit(
    context: dict[str, Any],
    delivery: str,
    graph: GraphStore,
    entries: dict[str, EntryRecord],
    seeds: list[ContextSeed],
) -> HarnessUnit:
    """Build the synthetic Action, single-step witness and plan.

    Raises ``ValueError`` with the blocking reason when the context cannot be
    turned into a plan.
    """

    if not seeds:
        raise ValueError("no verified seed exists for this context and delivery")
    functions = graph.bundle.functions
    context_id = str(context["context_id"])
    notes: list[str] = []

    def usable(item: dict[str, Any]) -> bool:
        record = entries.get(str(item.get("entry_id", "")))
        if record is None or record.status is not Verdict.VERIFIED:
            return False
        try:
            record.validate()
        except ValueError:
            return False
        return record.entry_function_id in functions

    of_delivery = [item for item in context.get("entries") or [] if item.get("delivery") == delivery]
    if not of_delivery:
        raise ValueError(f"context has no Entry with delivery {delivery}")
    candidates = [item for item in of_delivery if usable(item)]
    if not candidates:
        raise ValueError(
            "no Entry of this delivery is a VERIFIED record whose function is in the analysis graph")
    entry = candidates[0]
    if len(of_delivery) > 1:
        notes.append(
            f"{len(of_delivery)} Entries share delivery {delivery}; used {entry.get('entry_id')} "
            f"({entry.get('entry_function') or functions[entries[entry['entry_id']].entry_function_id].name})")
    record = entries[str(entry["entry_id"])]
    entry_function_id = record.entry_function_id
    entry_function = functions[entry_function_id]

    resource_kind = str(entry.get("resource_kind") or context.get("resource_kind") or "unknown")
    channel = _channel(resource_kind, delivery)
    if not channel:
        raise ValueError(
            f"no transport model for resource kind {resource_kind} with delivery {delivery}")

    first = seeds[0]
    interpreter_ids = [
        item for item in (entry.get("interpreter_function_ids")
                          or context.get("interpreter_function_ids") or [])
        if item in functions
    ] or [item for item in context.get("interpreter_function_ids") or [] if item in functions]
    if not interpreter_ids:
        raise ValueError("no interpreting function of the context is in the analysis graph")
    # Several functions may interpret one context.  The handler anchor is the
    # one the witness seed executed in the original program when its coverage
    # is recorded; the name only breaks ties so the choice is reproducible.
    covered = set(first.covered_target_function_ids)
    interpreter_id = min(
        interpreter_ids, key=lambda item: (item not in covered, functions[item].name, item))
    others = [functions[item].name for item in interpreter_ids if item != interpreter_id]
    if others:
        notes.append("other interpreting functions of this context: " + ", ".join(sorted(others)))

    entry_line = entry.get("entry_line") or record.entry_line
    unproven = (
        "seeds were accepted as whole streams by the original program; "
        "no request-to-handler attribution exists")
    action = ExternalActionSchema(
        action_id=stable_id("ctx-action", context_id, delivery),
        entry_id=record.entry_id,
        name=f"{context_id} {delivery} input stream",
        description=(
            f"Whole {delivery} byte stream delivered to Entry {entry_function.name} "
            f"({record.source_api}) and interpreted by {functions[interpreter_id].name}."
            + (f" Other interpreting functions: {', '.join(sorted(others))}." if others else "")),
        dispatcher_function_id=interpreter_id,
        handler_function_id=interpreter_id,
        discriminator="",
        channel_kind=record.channel_kind,
        fields=[],
        examples=[
            ActionExample(
                data_hex=seed.data.hex(), rationale=seed.rationale,
                origin=f"verified_seed:{seed.origin or 'unknown'}")
            for seed in seeds
        ],
        success_markers_hex=[],
        failure_markers_hex=[],
        evidence=[Evidence(
            "input_context", entry_function_id, entry_function.file,
            int(entry_line) if entry_line else None,
            f"verified Entry acquisition of input context {context_id} ({delivery})")],
        inspected_function_ids=[],
        unknowns=[unproven],
        source_api=record.source_api,
        actor=(ActionActor.INBOUND_CLIENT if channel in {"tcp", "udp", "unix_stream"}
               else ActionActor.LOCAL_PROCESS_INPUT),
        direction="inbound",
        entry_function_id=entry_function_id,
        entry_probe_evidence=list(record.evidence),
    )

    request_hex = first.data.hex()
    step = ScenarioStep(
        index=0, action_id=action.action_id, entry_id=record.entry_id,
        request_hex=request_hex, bindings={}, expected_success_markers_hex=[])
    candidate = ScenarioCandidate(
        scenario_id=stable_id("ctx-scenario", context_id, delivery),
        target_action_id=action.action_id,
        steps=[step],
        required_entries=[record.entry_id],
        satisfied_resources=[],
        planning_evidence=[
            f"input context {context_id}, delivery {delivery}",
            f"verified seed {first.seed_id} is the whole fuzz input; no setup request exists",
        ],
        fuzz_step_index=0,
    )
    lengths = [len(item) for item in first.messages]
    response = b"".join(first.responses)
    witness = ScenarioWitness(
        witness_id=stable_id("ctx-witness", context_id, delivery, first.seed_id, request_hex),
        scenario_id=candidate.scenario_id,
        target_action_id=action.action_id,
        steps=[step],
        observations=[RuntimeStepObservation(
            index=0, action_id=action.action_id, request_hex=request_hex,
            response_hex=response.hex(),
            # Acceptance is the verdict of the seed verification stage for the
            # whole stream.  It is not a marker match and not a handler trace.
            success=True,
            detail=(
                f"verified seed {first.seed_id} (origin {first.origin or 'unknown'}): "
                f"{len(first.messages)} message(s), {len(response)} response byte(s) recorded "
                "by the seed verification stage; no Entry or handler probe"),
            duration_seconds=0.0,
            request_write_completed=True,
            response_success=True,
            entry_function_id=entry_function_id,
        )],
        command=[],
        channel=channel,
        process_returncode=None,
        status=ScenarioStatus.REPLAYED_RUNTIME,
        rationale=(
            f"Input-context harness for {context_id} ({delivery}). The fuzz input is the WHOLE "
            f"byte stream delivered to Entry {entry_function.name} ({record.source_api}); it may "
            "contain several protocol messages and there are no fixed setup requests. The step "
            f"bytes are verified seed {first.seed_id}: {len(lengths)} message(s) of lengths "
            f"{lengths}, "
            + ("each sent as one datagram and concatenated here. " if delivery == "datagram"
               else "concatenated in the order they were delivered. ")
            + "The original program accepted this seed as a whole; no request was attributed "
              "to a handler, so this is not a per-request proof and cannot qualify the harness. "
            + ("MEASURED ON THE ORIGINAL PROGRAM (coverage of this exact seed, excluding what a run "
               "with no input executes): these functions executed: "
               + ", ".join(first.functions_beyond_baseline[:120])
               + ". Calls through function pointers on this path therefore resolved to these "
                 "functions for this input; treat that as established by execution. After the "
                 "harness is built, the same seeds are replayed in it and the functions it executes "
                 "are compared with this list."
               if first.functions_beyond_baseline else "")),
        fuzz_step_index=0,
    )

    function_ids = list(action_harness_function_ids(action, entry_function_id))
    # The driver joins the acquisition and its interpretation, so the
    # generator and the reviewer must read it before the handler anchor.
    driver_id = str(context.get("driver_function_id") or "")
    if driver_id in functions and driver_id not in function_ids:
        function_ids.insert(len(function_ids) - 1, driver_id)
    plan = build_harness_plan(
        witness,
        action_function_ids={action.action_id: tuple(function_ids)},
        action_schemas={action.action_id: action},
        function_sources={key: value.file for key, value in functions.items()},
        build_target="UNRESOLVED",
        allow_observed=True,
    )
    plan.max_size = max(plan.max_size, *(len(seed.data) for seed in seeds))
    return HarnessUnit(
        context_id=context_id, delivery=delivery, channel=channel, entry=entry,
        interpreter_function_id=interpreter_id, action=action, candidate=candidate,
        witness=witness, plan=plan, plan_audit=audit_harness_plan(witness, plan),
        seeds=seeds, notes=notes)


# --------------------------------------------------------------------------
# Build and replay


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.") or "item"


async def _build(
    settings: "_Settings", store: ArtifactStore, attempt: Path, harness: Path,
) -> tuple[Path | None, str, bool]:
    """Return (binary, diagnostics, whether regenerating the harness can help)."""

    output = store.directory(attempt / "build")
    result: dict[str, Any] = {
        "builder": "harnesscreator.runtime.native_build.build_native",
        "source_root": str(settings.source_root),
        "harness": str(harness),
        "output": str(output),
        "compile_database": str(settings.compile_database) if settings.compile_database else None,
        "target_binary": str(settings.target_binary) if settings.target_binary else None,
    }
    started = time.monotonic()
    try:
        binary = await asyncio.to_thread(
            build_native, settings.source_root, harness, output,
            compile_database=settings.compile_database, target_binary=settings.target_binary)
    except (OSError, NativeBuildUnresolved) as exc:
        message = str(exc)
        # Only a compiler error in the generated file or a link error can be
        # repaired by another draft; an unresolved project closure cannot.
        repairable = (
            message.startswith(f"compilation failed for {harness}")
            or message.startswith("link failed"))
        store.write_text(attempt / "build.log", f"NATIVE_BUILD_UNRESOLVED: {message}\n")
        store.write_json(attempt / "build.json", {
            **result, "ok": False, "binary": None, "error": message,
            "harness_repairable": repairable,
            "duration_seconds": time.monotonic() - started})
        return None, message, repairable
    build_plan = output / ".native-build" / "build-plan.json"
    store.write_text(attempt / "build.log", f"NATIVE_BUILD_OK: {binary}\n")
    store.write_json(attempt / "build.json", {
        **result, "ok": True, "binary": str(binary), "error": None,
        "build_plan": str(build_plan) if build_plan.is_file() else None,
        "duration_seconds": time.monotonic() - started})
    return binary, "", False


async def _replay(
    store: ArtifactStore, attempt: Path, binary: Path, seeds: list[ContextSeed],
) -> list[dict[str, Any]]:
    """Run ``<binary> <seedfile> -runs=1`` for every seed."""

    runner = CommandRunner()
    cwd = store.directory(attempt / "replay")
    results: list[dict[str, Any]] = []
    for index, seed in enumerate(seeds):
        name = f"{index:04d}-{_safe_name(seed.seed_id)}"
        seed_file = store.write_bytes(attempt / "replay" / "seeds" / name, seed.data)
        try:
            report = await runner.run(
                [str(binary), str(seed_file), "-runs=1"], cwd=cwd,
                timeout_seconds=_REPLAY_TIMEOUT_SECONDS)
        except OSError as exc:
            results.append({
                "seed_id": seed.seed_id, "file": str(seed_file), "bytes": len(seed.data),
                "returncode": None, "timed_out": False, "sanitizer_report": False, "ok": False,
                "duration_seconds": 0.0,
                "output_tail": f"could not start the binary: {type(exc).__name__}: {exc}"})
            continue
        output = report.stdout + report.stderr
        store.write_text(attempt / "replay" / f"{name}.log", output)
        sanitizer = any(marker in output for marker in SANITIZER_MARKERS)
        results.append({
            "seed_id": seed.seed_id, "file": str(seed_file), "bytes": len(seed.data),
            "returncode": report.returncode, "timed_out": report.timed_out,
            "sanitizer_report": sanitizer,
            "ok": report.returncode == 0 and not report.timed_out and not sanitizer,
            "duration_seconds": report.duration_seconds,
            "output_tail": output[-4000:]})
    store.write_json(attempt / "replay.json", {
        "command_form": "<binary> <seedfile> -runs=1",
        "binary": str(binary),
        "replayed": len(results),
        "ok": sum(item["ok"] for item in results),
        "seeds": results,
    })
    return results


# --------------------------------------------------------------------------
# One context + delivery


@dataclass(frozen=True)
class _Settings:
    run_dir: Path
    source_root: Path
    compile_database: Path | None
    target_binary: Path | None
    attempts: int
    build: bool
    name: str
    origins: dict[str, str]

    def project(self, harness_source_filename: str) -> ProjectSpec:
        # Same build description the CLI records when it selects the bundled
        # native builder; the generator and the static gate key the
        # ``hc_native_original_main`` contract off it.
        command = [
            sys.executable, "-m", "harnesscreator.runtime.native_build",
            "--source-root", "{source_root}", "--harness", "{harness}", "--output", "{output}",
        ]
        if self.compile_database is not None:
            command.extend(["--compile-database", str(self.compile_database)])
        if self.target_binary is not None:
            command.extend(["--target-binary", str(self.target_binary)])
        return ProjectSpec(
            source_root=self.source_root,
            output_root=self.run_dir / OUTPUT_DIR,
            name=self.name,
            analysis_compile_database=self.compile_database,
            verification_backend="command",
            build_command=command,
            native_default_build=True,
            harness_binary="{output}/hc-native-fuzzer",
            harness_source_filename=harness_source_filename,
            # Opt-in the generator requires for a REPLAYED_RUNTIME witness.
            scenario_exploratory_drafts=True,
        ).normalized()


def _settings(args: argparse.Namespace, run_dir: Path) -> _Settings:
    recorded: dict[str, Any] = {}
    project_file = run_dir / "project.json"
    if project_file.is_file():
        loaded = json.loads(project_file.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            recorded = loaded
    origins: dict[str, str] = {}

    def choose(name: str, flag: Path | None, recorded_key: str) -> Path | None:
        if flag is not None:
            origins[name] = "argument"
            return Path(flag).expanduser().resolve()
        if recorded.get(recorded_key):
            origins[name] = "project.json"
            return Path(str(recorded[recorded_key])).expanduser().resolve()
        return None

    source = choose("source_root", getattr(args, "source", None), "source_root")
    if source is None:
        raise ValueError("--source is required (RUN/project.json records no source_root)")
    if not source.is_dir():
        raise ValueError(f"source root is not a directory: {source}")
    database = choose(
        "compile_database", getattr(args, "compile_database", None), "analysis_compile_database")
    if database is not None and not database.is_file():
        raise ValueError(f"compile database does not exist: {database}")
    binary = choose("target_binary", getattr(args, "target_binary", None), "")
    if binary is not None and not binary.is_file():
        raise ValueError(f"target binary does not exist: {binary}")
    attempts = int(getattr(args, "attempts", 2))
    if attempts < 1:
        raise ValueError("--attempts must be at least 1")
    return _Settings(
        run_dir=run_dir, source_root=source, compile_database=database, target_binary=binary,
        attempts=attempts, build=not bool(getattr(args, "no_build", False)),
        name=str(recorded.get("name") or source.name), origins=origins)


class ContextHarnessGeneratorAgent(ScenarioHarnessGeneratorAgent):
    """The existing generator, driven by measured execution instead of static proof.

    The inherited source-reading step stops code generation when a fact about
    the application is not statically established (an indirect-call target, for
    example).  For an input context those facts are measured: the verified seeds
    were run on the original program and the functions they executed are known,
    and the built harness is compared with the original afterwards (seed replay
    and seed equivalence).  So unresolved source questions are handed to code
    generation as obligations to implement and verify, not as reasons to stop.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.converted_blockers: dict[str, list[dict[str, Any]]] = {}
        self._measured_context: dict[str, tuple[list[Any], dict[str, Any]]] = {}

    async def _discover_context(self, plan: HarnessPlan, witness: ScenarioWitness,
                                feedback: list[str]) -> tuple[list[Any], dict[str, Any]]:
        # Source reading is done once per plan; later attempts reuse it and pass
        # their feedback to code generation only.
        if plan.plan_id in self._measured_context:
            return self._measured_context[plan.plan_id]
        opened, discovery = await super()._discover_context(plan, witness, feedback)
        blockers = [item for item in (discovery.get("blocking_dependencies") or []) if isinstance(item, dict)]
        if blockers or not discovery.get("context_complete"):
            discovery = dict(discovery)
            obligations = [str(item) for item in (discovery.get("verification_obligations") or [])]
            obligations += [
                "Not established from source alone, to be handled in the harness and checked by seed replay "
                f"and seed equivalence: {item.get('description', '')} (needed for {item.get('required_for', '')})"
                for item in blockers]
            if not discovery.get("context_complete") and discovery.get("stop_reason"):
                obligations.append("Source reading ended early: " + str(discovery["stop_reason"]))
            discovery.update({"verification_obligations": obligations, "blocking_dependencies": [],
                              "context_complete": True, "stop_reason": ""})
            self.converted_blockers[plan.plan_id] = blockers
        result = (opened, discovery)
        self._measured_context[plan.plan_id] = result
        return result


def _symbolizer() -> str | None:
    return shutil.which("llvm-symbolizer") or shutil.which("addr2line")


def _equivalence_measurable(context: dict[str, Any], seeds: list[ContextSeed], *, build: bool) -> bool:
    return bool(build and context.get("driver_function_id") and _symbolizer()
                and any(seed.functions_beyond_baseline for seed in seeds))


_COVERED_FUNC = re.compile(r"^COVERED_FUNC: hits: \d+ edges: \d+/\d+ (\S+)", re.MULTILINE)


def _seed_equivalence(binary: Path, seeds: list[ContextSeed]) -> list[dict[str, Any]]:
    """Functions each seed executes in the built harness, against the original program.

    libFuzzer reports covered functions when a seed is loaded as a corpus
    (``-runs=0 -print_coverage=1``).  Names are compared, so two static
    functions with the same name in different files are not told apart.
    """

    environment = dict(os.environ, ASAN_SYMBOLIZER_PATH=_symbolizer() or "")
    results = []
    for seed in seeds:
        expected = set(seed.functions_beyond_baseline)
        if not expected:
            continue
        with tempfile.TemporaryDirectory(prefix="hc-equivalence-") as corpus:
            (Path(corpus) / "seed").write_bytes(seed.data)
            try:
                completed = subprocess.run(
                    [str(binary), corpus, "-runs=0", "-print_coverage=1"], env=environment,
                    capture_output=True, text=True, errors="replace", timeout=120, check=False)
                output = completed.stdout + completed.stderr
            except (OSError, subprocess.TimeoutExpired) as exc:
                output = f"{type(exc).__name__}: {exc}"
        executed = set(_COVERED_FUNC.findall(output))
        results.append({
            "seed_id": seed.seed_id, "original_functions": len(expected),
            "executed_in_harness": len(expected & executed), "missing": sorted(expected - executed),
            "measured": "COVERED_FUNC" in output})
    return results


def _blocking(report: GateReport, *, review: bool,
              deferred: frozenset[str] = frozenset()) -> list[GateCheck]:
    """Findings that stop a draft.

    Static gate: everything but the two checks it cannot prove for a seed.
    Independent review: any FAIL, and any WARN outside those two checks.
    ``deferred`` checks are decided later by seed equivalence of the built harness.
    """

    return [
        check for check in report.checks
        if check.status is not CheckStatus.PASS and check.check_id not in deferred and (
            check.check_id not in NOT_PROVEN_CHECK_IDS
            or (review and check.status is CheckStatus.FAIL))
    ]


def _checks_text(checks: list[GateCheck]) -> str:
    return "; ".join(f"{check.check_id} {check.status}: {check.evidence}" for check in checks)


async def _run_unit(
    context: dict[str, Any],
    delivery: str,
    *,
    settings: _Settings,
    store: ArtifactStore,
    graph: GraphStore,
    entries: dict[str, EntryRecord],
    llm: LLMProvider,
) -> dict[str, Any]:
    context_id = str(context["context_id"])
    name = _safe_name(f"{context_id}-{delivery}")
    unit_dir = Path(OUTPUT_DIR) / name
    row: dict[str, Any] = {
        "context_id": context_id, "delivery": delivery, "directory": str(unit_dir),
        "resource_kind": context.get("resource_kind"),
        "generated": False, "static_passed": False, "review_passed": False, "built": False,
        "seeds_available": 0, "seeds_replayed": 0, "seeds_replay_ok": 0,
        "status": STATUS_GENERATION_BLOCKED, "reason": "", "qualified": False,
        "attempt": None, "attempts": [], "notes": [],
    }
    seeds, skipped = load_seeds(settings.run_dir, context_id, delivery)
    row["seeds_available"] = len(seeds)
    if skipped:
        row["notes"].append("unusable seed files: " + "; ".join(skipped))
    try:
        unit = build_unit(context, delivery, graph, entries, seeds)
    except ValueError as exc:
        row["reason"] = str(exc)
        store.write_json(unit_dir / "status.json", row)
        return row
    row["notes"].extend(unit.notes)
    functions = graph.bundle.functions
    row.update({
        "entry_id": unit.action.entry_id,
        "entry_function": functions[unit.action.entry_function_id].name,
        "interpreter_function": functions[unit.interpreter_function_id].name,
        "witness_status": str(unit.witness.status),
        "witness_seed_id": seeds[0].seed_id,
        "plan_id": unit.plan.plan_id,
    })
    store.write_json(unit_dir / "context.json", context)
    store.write_json(unit_dir / "action.json", unit.action)
    store.write_json(unit_dir / "scenario-candidate.json", unit.candidate)
    store.write_json(unit_dir / "scenario-witness.json", unit.witness)
    store.write_json(unit_dir / "harness-plan.json", unit.plan)
    store.write_json(unit_dir / "plan-contract-audit.json", unit.plan_audit)
    if not unit.plan_audit.passed:
        row["reason"] = "plan contract audit failed: " + "; ".join(unit.plan_audit.failures)
        store.write_json(unit_dir / "status.json", row)
        return row

    plan, witness = unit.plan, unit.witness
    cpp = any(
        Path(functions[item].file).suffix.lower() in _CPP_SUFFIXES
        for item in [*plan.entry_function_ids, *plan.required_function_ids] if item in functions)
    project = settings.project("fuzz_target.cc" if cpp else "fuzz_target.c")
    generator = ContextHarnessGeneratorAgent(llm, graph, project)
    gate = ScenarioStaticHarnessGate(graph)
    deferred = (SEED_EQUIVALENCE_CHECK_IDS
                if _equivalence_measurable(context, unit.seeds, build=settings.build) else frozenset())
    feedback: list[str] = []
    seen: set[str] = set()

    def repeated(stage: str, report: GateReport) -> bool:
        signature = _gate_report_signature(stage, report)
        if signature in seen:
            return True
        seen.add(signature)
        return False

    try:
        for number in range(1, settings.attempts + 1):
            attempt = unit_dir / f"attempt-{number}"
            record: dict[str, Any] = {
                "attempt": number, "directory": str(attempt), "generated": False,
                "static_passed": False, "review_passed": False, "built": False,
                "seeds_replayed": 0, "seeds_replay_ok": 0,
                "status": STATUS_GENERATION_BLOCKED, "reason": "",
            }
            row["attempts"].append(record)
            try:
                draft = await generator.run(plan, witness, feedback=feedback)
            except Exception as exc:  # provider and transport errors are not repairable here
                record["reason"] = f"harness generator raised {type(exc).__name__}: {exc}"
                break
            source_name = Path(draft.manifest.source_file).name
            draft.manifest.source_file = str(attempt / source_name)
            harness = store.write_text(attempt / source_name, draft.code)
            store.write_json(attempt / "manifest.json", draft.manifest)
            store.write_json(attempt / "generator-audit.json", draft.self_audit)
            store.write_json(attempt / "source-questions-left-to-measurement.json",
                             generator.converted_blockers.get(plan.plan_id, []))
            store.write_json(attempt / "scenario-witness.json", witness)
            # The native builder reads required_source_files from this file
            # next to the harness source.
            store.write_json(attempt / "harness-plan.json", plan)
            record["harness_source"] = str(attempt / source_name)

            report = gate.check(draft, plan, witness)
            blocking = _blocking(report, review=False, deferred=deferred)
            store.write_json(attempt / "static-audit.json", {
                "checks": report.checks,
                "strict_passed": report.passed,
                "not_proven_check_ids": sorted(NOT_PROVEN_CHECK_IDS),
                "decided_by_seed_equivalence_check_ids": sorted(deferred),
                "blocking_check_ids": [check.check_id for check in blocking],
                "passed_for_unqualified_draft": not blocking,
            })
            if not draft.code.strip():
                record["reason"] = "generator returned no source: " + (
                    "; ".join(draft.generation_blockers) or "no blocker reported")
                if any(item.startswith(("CONTEXT_BLOCKED:", "WITNESS_BLOCKED:"))
                       for item in draft.generation_blockers) or repeated("context-static", report):
                    break
                feedback = _gate_feedback(GateReport(blocking), include_warnings=True)
                continue
            record["generated"] = True
            if blocking:
                record["status"] = STATUS_STATIC_FAILED
                record["reason"] = "static audit: " + _checks_text(blocking)
                if repeated("context-static", report):
                    break
                feedback = _gate_feedback(GateReport(blocking), include_warnings=True)
                continue
            record["static_passed"] = True

            try:
                review = await generator.review(draft, plan, witness, report)
            except Exception as exc:
                record["status"] = STATUS_REVIEW_FAILED
                record["reason"] = f"independent review raised {type(exc).__name__}: {exc}"
                break
            finally:
                await close_llm_session(llm, f"harness_verifier:{draft.manifest.harness_id}")
            rejected = _blocking(review, review=True, deferred=deferred)
            store.write_json(attempt / "independent-audit.json", {
                "checks": review.checks,
                "strict_passed": review.passed,
                "not_proven_check_ids": sorted(NOT_PROVEN_CHECK_IDS),
                "blocking_check_ids": [check.check_id for check in rejected],
                "passed_for_unqualified_draft": bool(review.checks) and not rejected,
            })
            if not review.checks or rejected:
                record["status"] = STATUS_REVIEW_FAILED
                record["reason"] = "independent review: " + (
                    _checks_text(rejected) or "no check was returned")
                if repeated("context-independent", review):
                    break
                feedback = _gate_feedback(GateReport(rejected), include_warnings=True)
                continue
            record["review_passed"] = True

            if not settings.build:
                record["status"] = STATUS_GENERATED_NOT_BUILT
                record["reason"] = "static audit and independent review passed; build disabled"
                break
            # Inlined functions would look unexecuted in the per-function report.
            previous_flags = os.environ.get("HARNESSCREATOR_NATIVE_EXTRA_CFLAGS")
            if deferred or _symbolizer():
                os.environ["HARNESSCREATOR_NATIVE_EXTRA_CFLAGS"] = ((previous_flags or "") + " -fno-inline").strip()
            try:
                binary, diagnostics, repairable = await _build(settings, store, attempt, harness)
            finally:
                if previous_flags is None:
                    os.environ.pop("HARNESSCREATOR_NATIVE_EXTRA_CFLAGS", None)
                else:
                    os.environ["HARNESSCREATOR_NATIVE_EXTRA_CFLAGS"] = previous_flags
            if binary is None:
                record["status"] = STATUS_BUILD_FAILED
                record["reason"] = "native build: " + _build_failure_excerpt(diagnostics, limit=4000)
                if not repairable:
                    break
                feedback = ["build diagnostics:\n" + _build_failure_excerpt(diagnostics)]
                continue
            record["built"] = True
            record["binary"] = str(binary)

            results = await _replay(store, attempt, binary, unit.seeds)
            failed = [item for item in results if not item["ok"]]
            record["seeds_replayed"] = len(results)
            record["seeds_replay_ok"] = len(results) - len(failed)
            if not failed:
                equivalence = _seed_equivalence(binary, unit.seeds) if deferred or _symbolizer() else []
                measured = [item for item in equivalence if item["measured"]]
                store.write_json(attempt / "seed-equivalence.json", {
                    "symbolizer": _symbolizer(), "results": equivalence,
                    "note": "functions the original executed for the seed beyond a run with no input, "
                            "compared by name with functions the harness executed for the same bytes"})
                record["seed_equivalence"] = {
                    "seeds_measured": len(measured),
                    "seeds_equivalent": len([item for item in measured if not item["missing"]])}
                mismatched = [item for item in measured if item["missing"]]
                if mismatched or (deferred and not measured):
                    record["status"] = STATUS_SEED_MISMATCH
                    record["reason"] = (
                        "the harness did not execute functions the original program executed for the same seed: "
                        + "; ".join(f"{item['seed_id']} missing {', '.join(item['missing'][:12])}"
                                    for item in mismatched[:3])
                        if mismatched else "seed equivalence could not be measured on the built harness")
                    feedback = [
                        "The built harness replayed the verified seeds without error, but for seed "
                        f"{item['seed_id']} it did not execute these functions that the original program "
                        f"executed for the same bytes: {', '.join(item['missing'][:40])}. The fuzz bytes must "
                        "reach the original code path that interprets them."
                        for item in mismatched[:3]]
                    continue
                if measured:
                    record["status"] = STATUS_SEED_EQUIVALENT
                    record["reason"] = (
                        f"built; {len(results)} verified seed(s) replayed cleanly and {len(measured)} measured "
                        "seed(s) executed every function the original executed for them. " + _QUALIFICATION_NOTE)
                else:
                    record["status"] = STATUS_BUILT_REPLAYED
                    record["reason"] = (
                        f"built; {len(results)} verified seed(s) exited 0 without a sanitizer "
                        "report; seed equivalence was not measured. " + _QUALIFICATION_NOTE)
                break
            record["status"] = STATUS_BUILT_REPLAY_FAILED
            record["reason"] = (
                f"{len(failed)} of {len(results)} verified seed(s) did not replay cleanly "
                "(harness fault or sanitizer-visible target defect; not triaged): "
                + ", ".join(item["seed_id"] for item in failed))
            feedback = [
                "The built harness did not replay a seed that the original program accepted. "
                f"seed {item['seed_id']} ({item['bytes']} bytes): exit {item['returncode']}"
                + (", timed out" if item["timed_out"] else "")
                + (", sanitizer report" if item["sanitizer_report"] else "")
                + "\n" + item["output_tail"]
                for item in failed[:3]
            ]
    finally:
        await generator.close_session(plan)

    best = max(row["attempts"], key=lambda item: (_PROGRESS[item["status"]], item["attempt"]))
    for key in ("generated", "static_passed", "review_passed", "built",
                "seeds_replayed", "seeds_replay_ok", "status", "reason"):
        row[key] = best[key]
    if "seed_equivalence" in best:
        row["seed_equivalence"] = best["seed_equivalence"]
    row["attempt"] = best["attempt"]
    for key in ("harness_source", "binary"):
        if key in best:
            row[key] = best[key]
    store.write_json(unit_dir / "status.json", row)
    return row


# --------------------------------------------------------------------------
# Entry point


def _select(
    contexts: list[dict[str, Any]], context_ids: list[str] | None, delivery: str | None,
) -> list[tuple[dict[str, Any], str]]:
    by_id = {str(item["context_id"]): item for item in contexts}
    if context_ids:
        unknown = [item for item in context_ids if item not in by_id]
        if unknown:
            raise ValueError("unknown context id: " + ", ".join(unknown))
        chosen = [by_id[item] for item in dict.fromkeys(context_ids)]
    else:
        chosen = [item for item in contexts if item.get("resource_kind") == "network"]
    selected: list[tuple[dict[str, Any], str]] = []
    for context in chosen:
        deliveries = sorted(str(item) for item in context.get("deliveries") or [])
        if delivery is None:
            selected.extend((context, item) for item in deliveries)
        elif delivery in deliveries or context_ids:
            # An explicitly named context without that delivery is reported as
            # blocked instead of being dropped silently.
            selected.append((context, delivery))
    return selected


def _write_summary(store: ArtifactStore, settings: _Settings, rows: list[dict[str, Any]]) -> Path:
    """Publish this invocation's rows; rows of other contexts are kept."""

    target = store.root / OUTPUT_DIR / "summary.json"
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    if target.is_file():
        try:
            previous = json.loads(target.read_text(encoding="utf-8")).get("harnesses") or []
        except (OSError, ValueError, AttributeError):
            previous = []
        for item in previous:
            if isinstance(item, dict):
                merged[(str(item.get("context_id")), str(item.get("delivery")))] = item
    for item in rows:
        merged[(item["context_id"], item["delivery"])] = item
    harnesses = list(merged.values())
    counts: dict[str, int] = {}
    for item in harnesses:
        counts[str(item.get("status"))] = counts.get(str(item.get("status")), 0) + 1
    return store.write_json(Path(OUTPUT_DIR) / "summary.json", {
        "source_root": str(settings.source_root),
        "compile_database": str(settings.compile_database) if settings.compile_database else None,
        "target_binary": str(settings.target_binary) if settings.target_binary else None,
        "setting_origins": settings.origins,
        "attempt_limit": settings.attempts,
        "build_enabled": settings.build,
        "witness_status": str(ScenarioStatus.REPLAYED_RUNTIME),
        "static_not_proven_check_ids": sorted(NOT_PROVEN_CHECK_IDS),
        "qualification": _QUALIFICATION_NOTE,
        "status_counts": counts,
        "harnesses": harnesses,
    })


def _emit(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] context-harness: {message}", file=sys.stderr, flush=True)


async def run_context_harness(args: argparse.Namespace, llm: LLMProvider) -> int:
    """Generate, audit, build and replay one harness per selected context and delivery.

    Returns 0 when every selected context+delivery reached the furthest state
    this stage can establish (``BUILT_REPLAYED_NOT_QUALIFIED``, or
    ``GENERATED_NOT_BUILT`` with ``--no-build``), 1 when any did not or
    nothing was selected, and 2 when the arguments or run artifacts are
    unusable.
    """

    run_dir = Path(args.run_dir).expanduser().resolve()
    try:
        settings = _settings(args, run_dir)
        settings.project("fuzz_target.c")  # validate the build description once
        graph = load_graph(run_dir)
        entries = load_verified_entries(run_dir)
        selected = _select(
            load_contexts(run_dir), getattr(args, "context", None), getattr(args, "delivery", None))
    except (OSError, ValueError) as exc:
        _emit(str(exc))
        return 2
    store = ArtifactStore(run_dir)
    rows: list[dict[str, Any]] = []
    _write_summary(store, settings, rows)
    if not selected:
        _emit("no input context selected (default is every network context; use --context)")
        return 1
    for context, delivery in selected:
        _emit(f"{context['context_id']} {delivery}: started")
        row = await _run_unit(
            context, delivery, settings=settings, store=store, graph=graph,
            entries=entries, llm=llm)
        rows.append(row)
        _write_summary(store, settings, rows)
        _emit(f"{row['context_id']} {row['delivery']}: {row['status']} - {row['reason']}")
    done = ((STATUS_BUILT_REPLAYED, STATUS_SEED_EQUIVALENT) if settings.build
            else (STATUS_GENERATED_NOT_BUILT,))
    return 0 if all(row["status"] in done for row in rows) else 1
