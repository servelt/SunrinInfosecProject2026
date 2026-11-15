"""Prepare one original FBv2 function for the existing product HP analyzer.

Preparation maps FBv2's selected function and Direction to an exact current
source span under an issued OSS-Fuzz qualification without model calls.  The
optional runner calls the product's existing HP roles through caller-supplied
pipelines. It does not execute a Target or modify original SP/Global state.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function


@dataclass(frozen=True)
class PreparedHPFunction:
    task_id: str
    function_id: str
    function_name: str
    direction_id: str
    source_file: str
    source: str
    source_start_line: int
    source_end_line: int
    source_sha256: str
    source_file_sha256: str
    harness_path: str
    harness_sha256: str
    binary_sha256: str
    source_tree_sha256: str
    contract_sha256: str
    analysis_scope: dict[str, Any]

    def receipt(self) -> dict[str, Any]:
        return {"status": "READY_FOR_HP_ANALYSIS", **asdict(self),
                "security_gate_credit": "NOT_CREDITED",
                "sp_global_effect": "UNCHANGED"}


def _unsupported(reason: str) -> dict[str, Any]:
    return {"status": "HP_UNSUPPORTED", "reason": reason,
            "security_gate_credit": "NOT_CREDITED",
            "sp_global_effect": "UNCHANGED"}


def prepare_hp_function(*, function: Function, direction: Direction,
                        qualification: Any, fuzzer: str,
                        sanitizer: str) -> PreparedHPFunction | dict[str, Any]:
    """Return exact source evidence or an isolated unsupported HP item."""
    from vulnerabilityanalysis.official_harness import (
        OfficialPinnedQualification, _qualification_pins_ok)
    from vulnerabilityanalysis.source import SourceRepository

    if (type(function) is not Function or type(direction) is not Direction or
            not function.function_id or not function.name or
            not direction.direction_id or
            function.task_id != direction.task_id or
            direction.fuzzer != fuzzer or
            not fuzzer or sanitizer != "address"):
        return _unsupported("FBV2_FUNCTION_OR_DIRECTION_INVALID")
    if direction.direction_id not in function.analyzed_by_directions:
        return _unsupported("FBV2_SP_SELECTION_NOT_COMPLETED")
    if (type(qualification) is not OfficialPinnedQualification or
            qualification.product_issued is not True or
            qualification.contract_kind !=
                "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2" or
            not _qualification_pins_ok(qualification)):
        return _unsupported("OFFICIAL_HARNESS_QUALIFICATION_INVALID")
    source_root = Path(qualification.source_root)
    harness = Path(qualification.harness)
    if (not source_root.is_absolute() or source_root.is_symlink() or
            source_root != source_root.resolve() or
            not harness.is_absolute() or harness.is_symlink() or
            not harness.is_file()):
        return _unsupported("QUALIFIED_SOURCE_OR_HARNESS_UNAVAILABLE")
    row: dict[str, Any] = {
        "function_id": function.function_id,
        "name": function.name,
        "file": function.file_path,
    }
    # Do not pass function.content as SourceRepository's raw substring probe.
    # A comment or prefix inside the file is not an exact function definition.
    if type(function.start_line) is int and function.start_line > 0:
        row["start_line"] = function.start_line
    if type(function.end_line) is int and function.end_line > 0:
        row["end_line"] = function.end_line
    try:
        repository = SourceRepository(source_root, {function.function_id: row})
        path = repository.source_path(function.function_id)
        definition_path, text, begin, end = repository._locate_definition(
            function.function_id)
        span = repository.open_function_span(function.function_id)
        if (definition_path != path or
                hashlib.sha256(text.encode("utf-8")).hexdigest() !=
                    span.source_file_sha256):
            return _unsupported("SOURCE_CHANGED_DURING_SPAN_LOOKUP")
        if (function.content and function.content.strip() not in
                {text[begin:end].strip(), span.source.strip()}):
            return _unsupported("FBV2_CONTENT_NOT_EXACT_DEFINITION")
        if "/* SOURCE TRUNCATED */" in span.source:
            return _unsupported("SOURCE_SPAN_EXCEEDS_HP_LIMIT")
        # Recheck all issued pins after source bytes were read.  The provider
        # must later repeat the same check before any physical HP turn.
        if not _qualification_pins_ok(qualification):
            return _unsupported("OFFICIAL_HARNESS_QUALIFICATION_CHANGED")
    except (OSError, ValueError, KeyError, UnicodeError) as exc:
        return _unsupported("EXACT_SOURCE_SPAN_UNAVAILABLE:" +
                            type(exc).__name__)
    scope = {
        "worker": {"fuzzer": fuzzer, "sanitizer": sanitizer},
        "direction": {
            "direction_id": direction.direction_id,
            "name": direction.name,
            "risk_level": direction.risk_level,
            "entry_functions": list(direction.entry_functions or []),
            "core_functions": list(direction.core_functions or []),
            "related_functions": [],
        },
        "selected_function": {
            "function_id": function.function_id,
            "function_name": function.name,
            "source_file": str(path),
            "source_start_line": span.start_line,
            "source_end_line": span.end_line,
            "runtime_reachable": "UNPROVEN_BY_HP_PREPARATION",
            "fbv2_source_match": ("EXACT_DEFINITION" if function.content else
                                  "NO_STORED_FBV2_CONTENT"),
        },
        "provenance_note": (
            "FBv2 selection and source context only; no SAFE judgment, "
            "attacker control, or vulnerability is established."),
    }
    return PreparedHPFunction(
        task_id=function.task_id, function_id=function.function_id,
        function_name=function.name, direction_id=direction.direction_id,
        source_file=str(path), source=span.source,
        source_start_line=span.start_line, source_end_line=span.end_line,
        source_sha256=span.source_sha256,
        source_file_sha256=span.source_file_sha256,
        harness_path=str(harness),
        harness_sha256=qualification.harness_sha256,
        binary_sha256=qualification.binary_sha256,
        source_tree_sha256=qualification.source_tree_sha256,
        contract_sha256=qualification.contract_sha256,
        analysis_scope=scope,
    )


def classify_hp_analysis(work: PreparedHPFunction,
                         analysis: Any | None = None,
                         error: BaseException | None = None) -> dict[str, Any]:
    """Classify HP-only progress; never change FBv2 SP/Global or Gate state."""
    from vulnerabilityanalysis.models import FunctionAnalysis

    if type(work) is not PreparedHPFunction:
        return _unsupported("HP_WORK_ITEM_INVALID")
    common = {"function_id": work.function_id,
              "direction_id": work.direction_id,
              "sp_global_effect": "UNCHANGED",
              "security_gate_credit": "NOT_CREDITED"}
    if error is not None:
        return {**common, "status": "INCOMPLETE_HP_ERROR",
                "error_type": type(error).__name__}
    if (type(analysis) is not FunctionAnalysis or
            analysis.function_id != work.function_id or
            analysis.function_name != work.function_name or
            analysis.source_file != work.source_file or
            analysis.direction_id != work.direction_id):
        return {**common, "status": "INCOMPLETE_HP_RESULT_MISMATCH"}
    if not analysis.safe_assumptions:
        return {**common, "status": "NO_SAFE_ASSUMPTION",
                "assertion_opportunity": "NONE"}
    return {**common, "status": "SAFE_PROPOSED_UNVERIFIED",
            "safe_assumption_count": len(analysis.safe_assumptions),
            "assertion_opportunity": "PENDING_INDEPENDENT_VALIDATION"}


def _prepared_pins_ok(work: PreparedHPFunction, qualification: Any) -> bool:
    """Rebind saved HP source to the issued checkout before each HP role."""
    from vulnerabilityanalysis.official_harness import (
        OfficialPinnedQualification, _qualification_pins_ok)
    from vulnerabilityanalysis.source import SourceRepository

    if (type(work) is not PreparedHPFunction or
            type(qualification) is not OfficialPinnedQualification or
            qualification.product_issued is not True or
            qualification.contract_kind !=
                "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2"):
        return False
    try:
        root = Path(qualification.source_root)
        path = Path(work.source_file)
        harness = Path(work.harness_path)
        if (not root.is_absolute() or root.is_symlink() or
                root != root.resolve() or not path.is_absolute() or
                path.is_symlink() or path != path.resolve() or
                root not in path.parents or not harness.is_absolute() or
                harness.is_symlink() or harness != harness.resolve() or
                harness != qualification.harness or
                work.harness_sha256 != qualification.harness_sha256 or
                work.binary_sha256 != qualification.binary_sha256 or
                work.source_tree_sha256 != qualification.source_tree_sha256 or
                work.contract_sha256 != qualification.contract_sha256 or
                not _qualification_pins_ok(qualification)):
            return False
        repository = SourceRepository(root, {work.function_id: {
            "function_id": work.function_id, "name": work.function_name,
            "file": str(path.relative_to(root)),
            "start_line": work.source_start_line,
            "end_line": work.source_end_line,
        }})
        span = repository.open_function_span(work.function_id)
        return (repository.source_path(work.function_id) == path and
                span.source == work.source and
                span.start_line == work.source_start_line and
                span.end_line == work.source_end_line and
                span.source_sha256 == work.source_sha256 and
                span.source_file_sha256 == work.source_file_sha256 and
                hashlib.sha256(work.source.encode("utf-8")).hexdigest() ==
                    work.source_sha256 and
                hashlib.sha256(harness.read_bytes()).hexdigest() ==
                    work.harness_sha256)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError):
        return False


def _context_pins_ok(pins: dict[Path, str]) -> bool:
    try:
        return all(path.is_file() and not path.is_symlink() and
                   path == path.resolve() and
                   hashlib.sha256(path.read_bytes()).hexdigest() == digest
                   for path, digest in pins.items())
    except (OSError, ValueError):
        return False


def _qualified_relink_recipe_ok(*, work: PreparedHPFunction,
                                qualification: Any, build_command: list[str],
                                manifest_path: Path,
                                manifest_sha256: str) -> bool:
    """Accept a fixture relinker whose own manifest binds the qualified inputs."""
    try:
        builder = Path(build_command[0])
        manifest = Path(manifest_path)
        if (len(build_command) != 4 or
                build_command != [str(builder), "{source}", "-o", "{binary}"] or
                not builder.is_absolute() or builder.is_symlink() or
                not builder.is_file() or builder != builder.resolve() or
                not manifest.is_absolute() or manifest.is_symlink() or
                not manifest.is_file() or manifest != manifest.resolve() or
                manifest != builder.with_name("multi_tu_assertion_build_manifest.json") or
                not isinstance(manifest_sha256, str) or
                hashlib.sha256(manifest.read_bytes()).hexdigest() != manifest_sha256):
            return False
        row = json.loads(manifest.read_text())
        root = Path(qualification.source_root)
        relative = Path(work.source_file).relative_to(root).as_posix()
        source_files = row.get("source_files")
        return (row.get("schema") == "MULTI_TU_ASSERTION_BUILD_V1" and
                row.get("kind") == "MD4C_ISOLATED_ASSERTION_RELINK_V1" and
                row.get("builder_sha256") == hashlib.sha256(builder.read_bytes()).hexdigest() and
                row.get("source_root") == str(root.resolve()) and
                row.get("harness_source") == str(Path(qualification.harness).resolve()) and
                row.get("official_binary") == str(Path(qualification.binary).resolve()) and
                row.get("official_binary_sha256") == qualification.binary_sha256 and
                isinstance(source_files, dict) and
                source_files.get(relative) == work.source_file_sha256 and
                any(Path(name).name == Path(qualification.harness).name and
                    digest == qualification.harness_sha256
                    for name, digest in source_files.items()) and
                relative in row.get("allowed_translation_units", {}))
    except (OSError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError):
        return False


def run_prepared_hp_assertion_handoff(
    *, work: PreparedHPFunction, qualification: Any,
    analysis_result: dict[str, Any], worker_id: str, assertion_id: str,
    output_dir: Path, build_command: list[str],
    run_command: list[str], guided_seconds: int = 0,
    timeout_seconds: float = 30.0,
    provider_free_fixture: bool = False,
    execute_callback: Callable[..., Any] | None = None,
    guided_callback: Callable[..., Any] | None = None,
    builder_manifest_path: Path | None = None,
    builder_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Hand one HP proposal to explicit Assertion execution callbacks.

    This bounded seam is for local integration fixtures. A public live caller
    also needs a pinned instrumented-build recipe, a durable one-shot claim,
    and an HP-specific V2 process envelope on the shared process ledger.
    None is issued by the current official Harness qualification, so live
    execution remains unavailable here. Fixture callbacks must be supplied
    explicitly; this function never starts a process by default. A proposal
    or witness never earns Security Gate or discovery credit here.
    """
    from vulnerabilityanalysis.models import Assertion

    common = {"function_id": getattr(work, "function_id", None),
              "direction_id": getattr(work, "direction_id", None),
              "sp_global_effect": "UNCHANGED",
              "security_gate_credit": "NOT_CREDITED",
              "discovery_credit": "NOT_CREDITED"}

    def blocked(reason: str) -> dict[str, Any]:
        return {**common, "status": "HP_ASSERTION_HANDOFF_BLOCKED",
                "reason": reason}

    if provider_free_fixture is not True:
        return blocked("LIVE_HP_INSTRUMENTED_BUILD_AND_ENVELOPE_NOT_ADMITTED")
    if (type(work) is not PreparedHPFunction or
            type(analysis_result) is not dict or
            type(worker_id) is not str or not worker_id or
            type(assertion_id) is not str or not assertion_id or
            type(guided_seconds) is not int or guided_seconds < 0 or
            guided_seconds > 60 or
            type(timeout_seconds) not in (int, float) or
            not 0 < timeout_seconds <= 60):
        return blocked("HP_HANDOFF_ARGUMENT_INVALID")
    if not _prepared_pins_ok(work, qualification):
        return blocked("PREPARED_SOURCE_OR_QUALIFICATION_CHANGED")
    canonical = lambda value: json.dumps(
        value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        if analysis_result.get("status") == "NO_SAFE_ASSUMPTION":
            return {**common, "status": "HP_ASSERTION_NOT_APPLICABLE",
                    "reason": "NO_SAFE_ASSUMPTION"}
        proposals = analysis_result["assertion_proposals"]
        if (analysis_result.get("status") != "ASSERTIONS_PROPOSED_UNVERIFIED" or
                analysis_result.get("assertion_execution") != "NOT_RUN" or
                analysis_result.get("function_id") != work.function_id or
                analysis_result.get("direction_id") != work.direction_id or
                type(proposals) is not list or
                analysis_result.get("assertion_count") != len(proposals) or
                analysis_result.get("proposed_assertion_count") != sum(
                    type(row) is dict and row.get("status") == "PROPOSED"
                    for row in proposals) or
                analysis_result.get("prepared_work_sha256") != hashlib.sha256(
                    canonical(asdict(work))).hexdigest() or
                analysis_result.get("assertion_proposals_sha256") !=
                    hashlib.sha256(canonical(proposals)).hexdigest()):
            return blocked("HP_PROPOSAL_RECEIPT_MISMATCH")
        proposed = [Assertion(**row) for row in proposals
                    if row["status"] == "PROPOSED" and
                    row.get("assertion_id") == assertion_id]
    except (KeyError, TypeError, ValueError, OverflowError):
        return blocked("HP_PROPOSAL_RECEIPT_INVALID")
    if not proposed:
        return blocked("HP_ASSERTION_ID_NOT_PROPOSED")
    if len(proposed) != 1:
        return blocked("HP_ASSERTION_ID_DUPLICATED")
    if (not callable(execute_callback) or
            guided_seconds and not callable(guided_callback)):
        return blocked("HP_FIXTURE_EXECUTION_CALLBACK_REQUIRED")
    assertion = proposed[0]
    try:
        location_file, raw_line = assertion.source_location.rsplit(":", 1)
        line = int(raw_line)
        location_path = Path(location_file)
        if not location_path.is_absolute():
            location_path = Path(qualification.source_root) / location_path
        source = Path(work.source_file)
        seed = Path(qualification.normal_seed)
        output_dir = Path(output_dir)
        harness = Path(work.harness_path)
        manifest_bound_recipe = (type(build_command) is list and
                                 str(harness) not in build_command)

        def execution_pins_ok() -> bool:
            return (_prepared_pins_ok(work, qualification) and
                    hashlib.sha256(seed.read_bytes()).hexdigest() ==
                    qualification.normal_seed_sha256 and
                    (not manifest_bound_recipe or (
                        builder_manifest_path is not None and
                        _qualified_relink_recipe_ok(
                            work=work, qualification=qualification,
                            build_command=build_command,
                            manifest_path=builder_manifest_path,
                            manifest_sha256=builder_manifest_sha256))))
        if (assertion.worker_id != worker_id or
                assertion.direction_id != work.direction_id or
                assertion.function != work.function_name or
                not assertion.assertion_id or
                not assertion.safe_assumption or
                not assertion.runtime_expression or
                location_path.is_symlink() or
                location_path.resolve() != source or
                not work.source_start_line <= line <= work.source_end_line or
                not seed.is_absolute() or seed.is_symlink() or
                seed != Path(qualification.normal_seed) or
                not seed.is_file() or
                hashlib.sha256(seed.read_bytes()).hexdigest() !=
                    qualification.normal_seed_sha256 or
                not output_dir.is_absolute() or output_dir.is_symlink() or
                output_dir.resolve() == source or output_dir.resolve() == seed or
                output_dir.resolve().is_relative_to(
                    Path(qualification.source_root))):
            return blocked("HP_ASSERTION_SOURCE_OR_SEED_MISMATCH")
        if (type(build_command) is not list or
                any(type(token) is not str or not token for token in build_command) or
                build_command.count("{source}") != 1 or
                build_command.count("{binary}") != 1 or
                (str(harness) not in build_command and not (
                    builder_manifest_path is not None and
                    _qualified_relink_recipe_ok(
                        work=work, qualification=qualification,
                        build_command=build_command,
                        manifest_path=builder_manifest_path,
                        manifest_sha256=builder_manifest_sha256))) or
                run_command != ["{binary}", "{input}"]):
            return blocked("HP_INSTRUMENTED_BUILD_RECIPE_UNSUPPORTED")
        if not execution_pins_ok():
            return blocked("PREPARED_SOURCE_OR_QUALIFICATION_CHANGED")
        executed, evidence = execute_callback(
            assertion, source, line, seed, output_dir / "execution",
            build_command, run_command, timeout_seconds=timeout_seconds)
        if not execution_pins_ok():
            return blocked("PREPARED_SOURCE_OR_QUALIFICATION_CHANGED")
        guided = None
        if guided_seconds and executed.status in {"HELD_FOR_EXECUTION", "VIOLATED"}:
            guided = guided_callback(
                executed, source, line, seed,
                output_dir / "guided", build_command, run_command,
                seconds=guided_seconds)
        if not execution_pins_ok():
            return blocked("PREPARED_SOURCE_OR_QUALIFICATION_CHANGED")
    except Exception as exc:
        return {**common, "status": "INCOMPLETE_HP_ASSERTION_HANDOFF",
                "error_type": type(exc).__name__}
    complete = (executed.status not in {"INVALID_ASSERTION", "BLOCKED", "ERROR"}
                and (guided is None or guided.get("status") in
                     {"RAN", "ASSERTION_WITNESS_OBSERVED"}))
    return {**common, "status": ("HP_ASSERTION_HANDOFF_COMPLETE" if complete
                                 else "INCOMPLETE_HP_ASSERTION_HANDOFF"),
            "assertion_id": assertion.assertion_id,
            "assertion_status": executed.status,
            "seed_sha256": qualification.normal_seed_sha256,
            "source_sha256": work.source_sha256,
            "evidence_id": getattr(evidence, "evidence_id", None),
            "guided_status": guided.get("status") if guided else "NOT_RUN",
            "guided_report": guided,
            "assertion_execution": "CALLER_SUPPLIED_CALLBACK_RESULT",
            "proposal_origin": "PROVIDER_FREE_FIXTURE"}


def _bounded_context(work: PreparedHPFunction, requests: list[Any],
                     qualification: Any) -> tuple[list[dict[str, str]],
                                                 list[dict[str, Any]],
                                                 dict[Path, str]]:
    """Resolve at most two first-round requests inside the issued source root."""
    from vulnerabilityanalysis.context import ContextResolver
    from vulnerabilityanalysis.models import ContextRequest
    from vulnerabilityanalysis.source import SourceRepository

    root = Path(qualification.source_root)
    repository = SourceRepository(root, {work.function_id: {
        "function_id": work.function_id, "name": work.function_name,
        "file": str(Path(work.source_file).relative_to(root)),
        "start_line": work.source_start_line,
        "end_line": work.source_end_line,
    }})
    resolver = ContextResolver(repository, max_chars=8_000,
                               call_graph_path=None, harness_path=None,
                               build_command=None)
    context: list[dict[str, str]] = []
    records: list[dict[str, Any]] = []
    pins: dict[Path, str] = {}
    seen_requests: set[tuple[str, str]] = set()
    seen_evidence: set[tuple[str, str, str]] = set()
    for index, request in enumerate(requests):
        record: dict[str, Any] = {
            "target": getattr(request, "target", None),
            "request_type": getattr(request, "request_type", None),
            "round": 0,
        }
        if index >= 2:
            record["status"] = "SKIPPED_PER_TURN_LIMIT"
            records.append(record)
            continue
        if (type(request) is not ContextRequest or
                request.requesting_function not in
                    {work.function_id, work.function_name}):
            record["status"] = "REQUESTING_FUNCTION_MISMATCH"
            records.append(record)
            continue
        key = (request.target, request.request_type)
        if key in seen_requests:
            record["status"] = "ALREADY_REQUESTED"
            records.append(record)
            continue
        seen_requests.add(key)
        try:
            resolved = resolver.resolve(replace(
                request, requesting_function=work.function_id))
            record["resolver_limit_events"] = list(resolver.last_limit_events)
        except (OSError, ValueError, KeyError, TypeError, UnicodeError):
            record["status"] = "RESOLUTION_FAILED"
            records.append(record)
            continue
        if not resolved:
            record["status"] = "NOT_FOUND"
            records.append(record)
            continue
        fresh: list[dict[str, str]] = []
        rejected_outside = False
        rejected_changed = False
        rejected_composite = False
        rejected_location = False
        for row in resolved:
            if type(row) is not dict or type(row.get("source")) is not str or not row["source"]:
                continue
            try:
                path = Path(row["source_file"])
                if (not path.is_absolute() or path.is_symlink() or
                        path != path.resolve() or not path.is_file() or
                        root not in path.parents):
                    rejected_outside = True
                    continue
                raw = path.read_bytes()
                current = raw.decode("utf-8", errors="replace")
                excerpt = row["source"]
                if ("/* SOURCE TRUNCATED */" in excerpt or
                        row.get("callsite_excerpt")):
                    rejected_composite = True
                    continue
                first = current.find(excerpt)
                if first < 0:
                    rejected_changed = True
                    continue
                if current.find(excerpt, first + 1) >= 0:
                    rejected_location = True
                    continue
                derived_location = f"{path}:{current.count(chr(10), 0, first) + 1}"
                location = row.get("source_location")
                if location is not None and location != derived_location:
                    rejected_location = True
                    continue
                if location is None:
                    row = {**row, "source_location": derived_location,
                           "location_evidence": "UNIQUE_CURRENT_SOURCE_EXCERPT"}
                digest = hashlib.sha256(raw).hexdigest()
            except (KeyError, OSError, ValueError, TypeError):
                rejected_outside = True
                continue
            evidence_key = (str(path), row.get("source_location", ""), row["source"])
            if evidence_key in seen_evidence:
                continue
            seen_evidence.add(evidence_key)
            pins[path] = digest
            fresh.append(row)
        context.extend(fresh)
        record["status"] = ("FETCHED" if fresh else
                            "OUTSIDE_QUALIFIED_SOURCE_ROOT" if rejected_outside
                            else "UNSUPPORTED_COMPOSITE_CONTEXT"
                            if rejected_composite else "LOCATION_UNPROVEN"
                            if rejected_location
                            else "CONTEXT_SOURCE_CHANGED_DURING_RESOLUTION"
                            if rejected_changed
                            else "NO_NEW_EVIDENCE")
        record["provided_count"] = len(fresh)
        records.append(record)
    return context, records, pins


async def run_prepared_hp_analysis(*, work: PreparedHPFunction,
                                   qualification: Any,
                                   analysis_pipeline: Any,
                                   assertion_pipeline: Any,
                                   worker_id: str,
                                   provider_free_fixture: bool = False
                                   ) -> dict[str, Any]:
    """Use the existing HP roles; all output remains unverified and HP-local.

    Live use requires two role-bound providers sharing the same campaign gate.
    Its caller must wait until original SP/Global model work has finished:
    an uncertain HP turn also blocks later roles on that shared gate.
    An explicit provider-free fixture mode admits scripted local tests only.
    This function neither chooses FBv2 work nor grants Gate/discovery credit.
    """
    from devtools.campaign_model_gate import CampaignLedgeredProvider
    from vulnerabilityanalysis.agents import AgentPipeline
    from vulnerabilityanalysis.models import Assertion, stable_id

    if (type(work) is not PreparedHPFunction or not worker_id or
            type(analysis_pipeline) is not AgentPipeline or
            type(assertion_pipeline) is not AgentPipeline or
            analysis_pipeline is assertion_pipeline or
            (getattr(analysis_pipeline.provider, "role", "function_analysis") !=
             "function_analysis") or
            (getattr(assertion_pipeline.provider, "role", "assertion_generator") !=
             "assertion_generator")):
        return _unsupported("HP_ROLE_PIPELINES_INVALID")
    if not provider_free_fixture:
        first = analysis_pipeline.provider
        second = assertion_pipeline.provider
        if (type(first) is not CampaignLedgeredProvider or
                type(second) is not CampaignLedgeredProvider or
                first.gate is not second.gate):
            return _unsupported("HP_SHARED_MODEL_LEDGER_REQUIRED")
    common = {"function_id": work.function_id,
              "direction_id": work.direction_id,
              "sp_global_effect": "UNCHANGED",
              "security_gate_credit": "NOT_CREDITED"}
    context: list[dict[str, str]] = []
    context_records: list[dict[str, Any]] = []
    context_pins: dict[Path, str] = {}
    reanalyses = 0

    def with_context(row: dict[str, Any]) -> dict[str, Any]:
        return {**row, "context_request_count": len(context_records),
                "context_provided_count": len(context),
                "context_reanalysis_count": reanalyses,
                "context_requests": list(context_records),
                "context_evidence": [{
                    "target": item.get("target"),
                    "source_file": item.get("source_file"),
                    "source_location": item.get("source_location"),
                    "source_file_sha256": context_pins.get(
                        Path(item["source_file"]))
                    if item.get("source_file") else None,
                } for item in context]}

    if not _prepared_pins_ok(work, qualification):
        return {**common, "status": "HP_UNSUPPORTED",
                "reason": "PREPARED_SOURCE_OR_QUALIFICATION_CHANGED"}
    phase = "FUNCTION_ANALYSIS"
    try:
        harness_path = Path(work.harness_path)
        harness_source = harness_path.read_text(encoding="utf-8")
        if (hashlib.sha256(harness_source.encode("utf-8")).hexdigest() !=
                work.harness_sha256 or not _prepared_pins_ok(work, qualification)):
            return {**common, "status": "HP_UNSUPPORTED",
                    "reason": "PREPARED_SOURCE_OR_QUALIFICATION_CHANGED"}
        analysis = await analysis_pipeline.analyze_function(
            work.function_id, work.function_name, work.source_file,
            work.source, context=[], harness_source=harness_source,
            harness_source_path=harness_path,
            analysis_scope=work.analysis_scope,
            source_start_line=work.source_start_line)
        if not provider_free_fixture:
            provider = analysis_pipeline.provider
            if (not provider.last_request_id or
                    provider.gate.verify_response_evidence(
                        provider.last_request_id)["status"] != "VERIFIED"):
                return {**common, "status": "INCOMPLETE_HP_MODEL_PROVENANCE",
                        "phase": phase}
        if not _prepared_pins_ok(work, qualification):
            return with_context({**common, "status": "HP_UNSUPPORTED",
                                 "reason": "PREPARED_SOURCE_OR_QUALIFICATION_CHANGED"})
        if analysis.direction_id not in (None, work.direction_id):
            return with_context({**common, "status": "INCOMPLETE_HP_RESULT_MISMATCH"})
        analysis.direction_id = work.direction_id
        requests = list(analysis.context_requests)
        omitted = list(getattr(analysis_pipeline,
                               "last_context_request_omitted", []))
        if requests:
            remaining = None
            if not provider_free_fixture:
                gate = analysis_pipeline.provider.gate
                remaining = gate.physical_max - gate.snapshot()["physical"]
            if remaining is not None and remaining < 2:
                context_records.extend({
                    "target": request.target,
                    "request_type": request.request_type,
                    "round": 0, "status": "SKIPPED_LLM_BUDGET",
                } for request in requests)
            elif not _prepared_pins_ok(work, qualification):
                return with_context({**common, "status": "HP_UNSUPPORTED",
                                     "reason": "PREPARED_SOURCE_OR_QUALIFICATION_CHANGED"})
            else:
                context, context_records, context_pins = _bounded_context(
                    work, requests, qualification)
            context_records.extend({
                "target": row.get("target"),
                "request_type": row.get("request_type"),
                "round": 0, "status": "SKIPPED_PER_TURN_LIMIT",
            } for row in omitted)
            if context:
                if (not _prepared_pins_ok(work, qualification) or
                        not _context_pins_ok(context_pins)):
                    return with_context({**common, "status": "HP_UNSUPPORTED",
                                         "reason": "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"})
                analysis = await analysis_pipeline.analyze_function(
                    work.function_id, work.function_name, work.source_file,
                    work.source, context=context, harness_source=harness_source,
                    harness_source_path=harness_path,
                    analysis_scope=work.analysis_scope,
                    source_start_line=work.source_start_line)
                reanalyses = 1
                if not provider_free_fixture:
                    provider = analysis_pipeline.provider
                    if (not provider.last_request_id or
                            provider.gate.verify_response_evidence(
                                provider.last_request_id)["status"] != "VERIFIED"):
                        return with_context({**common,
                            "status": "INCOMPLETE_HP_MODEL_PROVENANCE",
                            "phase": "FUNCTION_ANALYSIS_CONTEXT"})
                if analysis.direction_id not in (None, work.direction_id):
                    return with_context({**common,
                        "status": "INCOMPLETE_HP_RESULT_MISMATCH"})
                analysis.direction_id = work.direction_id
                context_records.extend({
                    "target": request.target,
                    "request_type": request.request_type,
                    "round": 1, "status": "SKIPPED_CONTEXT_ROUND_LIMIT",
                } for request in analysis.context_requests)
                context_records.extend({
                    "target": row.get("target"),
                    "request_type": row.get("request_type"),
                    "round": 1, "status": "SKIPPED_CONTEXT_ROUND_LIMIT",
                } for row in getattr(analysis_pipeline,
                                     "last_context_request_omitted", []))
        if context and (not _prepared_pins_ok(work, qualification) or
                        not _context_pins_ok(context_pins)):
            return with_context({**common, "status": "HP_UNSUPPORTED",
                                 "reason": "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"})
        classified = classify_hp_analysis(work, analysis)
        if classified["status"] != "SAFE_PROPOSED_UNVERIFIED":
            return with_context(classified)
        if (not _prepared_pins_ok(work, qualification) or
                not _context_pins_ok(context_pins)):
            return with_context({**common, "status": "HP_UNSUPPORTED",
                                 "reason": "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"})
        phase = "ASSERTION_GENERATION"
        assertions = await assertion_pipeline.generate_assertions(
            analysis, worker_id, work.direction_id, work.source,
            source_start_line=work.source_start_line, context=context,
            harness_source=harness_source, harness_source_path=harness_path)
        if provider_free_fixture and type(assertions) is list:
            # The product's Assertion Generator defaults to LLM provenance.
            # A scripted provider response must never inherit that label or ID.
            for assertion in assertions:
                if type(assertion) is Assertion:
                    assertion.assertion_id = stable_id(
                        "assert", "PROVIDER_FREE_FIXTURE", worker_id,
                        work.direction_id, work.function_name,
                        assertion.source_location, assertion.safe_assumption,
                        assertion.runtime_expression)
                    assertion.generation_method = "PROVIDER_FREE_FIXTURE"
        if not provider_free_fixture:
            provider = assertion_pipeline.provider
            if (not provider.last_request_id or
                    provider.gate.verify_response_evidence(
                        provider.last_request_id)["status"] != "VERIFIED"):
                return with_context({**common,
                                     "status": "INCOMPLETE_HP_MODEL_PROVENANCE",
                                     "phase": phase})
        if (not _prepared_pins_ok(work, qualification) or
                not _context_pins_ok(context_pins)):
            return with_context({**common, "status": "HP_UNSUPPORTED",
                                 "reason": "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"})
        if (type(assertions) is not list or any(
                type(row) is not Assertion or row.worker_id != worker_id or
                row.direction_id != work.direction_id or
                row.function != work.function_name for row in assertions)):
            return with_context({**common, "status": "INCOMPLETE_HP_RESULT_MISMATCH"})
        # Keep the exact unexecuted proposals for a later qualified Assertion
        # handoff. A count alone loses the expression and source location.
        # These hashes bind the handoff bytes; they do not verify an Assertion
        # or authorize instrumented execution.
        proposal_rows = [asdict(row) for row in assertions]
        canonical = lambda value: json.dumps(
            value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        proposed = sum(row.status == "PROPOSED" for row in assertions)
        return with_context({**common,
                             "status": "ASSERTIONS_PROPOSED_UNVERIFIED",
                             "safe_assumption_count": len(analysis.safe_assumptions),
                             "assertion_count": len(assertions),
                             "proposed_assertion_count": proposed,
                             "assertion_proposals": proposal_rows,
                             "assertion_proposals_sha256": hashlib.sha256(
                                 canonical(proposal_rows)).hexdigest(),
                             "prepared_work_sha256": hashlib.sha256(
                                 canonical(asdict(work))).hexdigest(),
                             "assertion_execution": "NOT_RUN"})
    except Exception as exc:
        return with_context({**classify_hp_analysis(work, error=exc),
                             "phase": phase})
