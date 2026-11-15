"""Prepare one original FBv2 function for the existing product HP analyzer.

Preparation maps FBv2's selected function and Direction to an exact current
source span under an issued OSS-Fuzz qualification without model calls.  The
optional runner calls the product's existing HP roles through caller-supplied
pipelines. A separately claimed, pinned physical handoff can execute the
existing product Assertion and Guided path; HP never modifies SP/Global state.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from collections import deque
from functools import partial
import hashlib
import json
import math
import os
from pathlib import Path
import re
import runpy
import stat
import time
from typing import Any, Callable

from fuzzingbrain.core.models.direction import Direction
from fuzzingbrain.core.models.function import Function


_INITIAL_CONTEXT_MAX_FUNCTIONS = 7
_INITIAL_CONTEXT_MAX_SOURCE_CHARS = 16_000
_INITIAL_CONTEXT_MAX_SOURCE_MACROS = 3
_INITIAL_CONTEXT_MAX_INITIALIZERS = 2
_INITIAL_CONTEXT_MAX_BUILD_DEFINES = 4
_INITIAL_CONTEXT_MAX_SUPPORT_CALLEES = 3


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
    selection_origin: str

    def receipt(self) -> dict[str, Any]:
        return {"status": "READY_FOR_HP_ANALYSIS", **asdict(self),
                "security_gate_credit": "NOT_CREDITED",
                "sp_global_effect": "UNCHANGED"}


def _unsupported(reason: str) -> dict[str, Any]:
    return {"status": "HP_UNSUPPORTED", "reason": reason,
            "security_gate_credit": "NOT_CREDITED",
            "sp_global_effect": "UNCHANGED"}


def _assumption_lifecycle_live_admission_ok(
        admission: Any, *, work: PreparedHPFunction, qualification: Any,
        analysis_pipeline: Any, assertion_pipeline: Any,
        max_context_reanalyses: int,
        catalog_manifest_sha256: str | None) -> bool:
    """Recheck the complete V5 live scope immediately before model use."""
    try:
        from devtools.original_hp_live_optin import (
            _assumption_lifecycle_engine_pins, _canonical_json_sha256,
            _canonical_json_bytes, _check_signed_spec,
            _signed_spec_subject_sha256,
            _verify_assumption_lifecycle_human_signature)
        from vulnerabilityanalysis import agents as agents_module
        from vulnerabilityanalysis.agents import (
            function_analysis_schema_sha256)

        token_keys = {
            "kind", "contract_kind", "task_id", "run_id",
            "signed_spec_subject_sha256", "spec_path", "spec_sha256",
            "approval_path", "approval_sha256", "approval_public_key_path",
            "approval_public_key_sha256", "scope_sha256", "scope"}
        if (type(admission) is not dict or set(admission) != token_keys or
                admission.get("kind") !=
                    "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_ADMISSION_V2" or
                admission.get("contract_kind") !=
                    "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5"):
            return False
        scope = admission.get("scope")
        if (type(scope) is not dict or set(scope) != {
                "kind", "contract_kind", "execution", "selection", "engine_pins",
                "function_analysis_schema_sha256", "qualification_pins",
                "model", "human_approval", "budgets", "credit"} or
                scope.get("kind") !=
                    "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_SCOPE_V2" or
                scope.get("contract_kind") !=
                    "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5" or
                admission.get("scope_sha256") !=
                    _canonical_json_sha256(scope)):
            return False

        spec_path = Path(admission.get("spec_path", ""))
        approval_path = Path(admission.get("approval_path", ""))
        spec_raw = _check_signed_spec(spec_path, admission.get("spec_sha256"))
        approval_raw = _check_signed_spec(
            approval_path, admission.get("approval_sha256"))
        spec = json.loads(spec_raw)
        approval = json.loads(approval_raw)
        subject_sha256 = _signed_spec_subject_sha256(spec)
        spec_identity = spec.get("identity") if type(spec) is dict else None
        if (type(spec_identity) is not dict or
                admission.get("task_id") != spec_identity.get("task_id") or
                admission.get("run_id") != spec_identity.get("run_id") or
                admission.get("signed_spec_subject_sha256") != subject_sha256 or
                scope.get("execution") != {
                    "task_id": admission.get("task_id"),
                    "run_id": admission.get("run_id"),
                    "signed_spec_subject_sha256": subject_sha256}):
            return False
        if (type(approval) is not dict or set(approval) != {
                "kind", "status", "decision", "reviewer_id", "reviewed_at",
                "scope", "signature"} or approval.get("kind") !=
                    "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_APPROVAL_V2" or
                approval.get("status") != "APPROVED" or
                type(approval.get("decision")) is not bool or
                approval["decision"] is not True or
                type(approval.get("reviewer_id")) is not str or
                not approval["reviewer_id"].strip() or
                type(approval.get("reviewed_at")) is not str or
                re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T"
                             r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                             approval["reviewed_at"]) is None or
                _canonical_json_bytes(approval.get("scope")) !=
                    _canonical_json_bytes(scope)):
            return False
        public_key_path = Path(admission.get("approval_public_key_path", ""))
        public_key_sha256 = admission.get("approval_public_key_sha256")
        if (not public_key_path.is_absolute() or public_key_path.is_symlink() or
                not public_key_path.is_file() or
                public_key_path != public_key_path.resolve(strict=True) or
                type(public_key_sha256) is not str or
                re.fullmatch(r"[0-9a-f]{64}", public_key_sha256) is None or
                hashlib.sha256(public_key_path.read_bytes()).hexdigest() !=
                    public_key_sha256 or
                not _verify_assumption_lifecycle_human_signature(
                approval, public_key_path=public_key_path,
                public_key_sha256=public_key_sha256)):
            return False
        hp = spec.get("hp") if type(spec) is dict else None
        control = spec.get("hp_only") if type(spec) is dict else None
        caps = spec.get("caps") if type(spec) is dict else None
        closure = (control.get("assumption_evidence_closure")
                   if type(control) is dict else None)
        selection_evidence = work.analysis_scope.get("selection_evidence")
        if (type(hp) is not dict or type(control) is not dict or
                type(caps) is not dict or
                type(closure) is not dict or closure != {
                    "enabled": True,
                    "contract_kind":
                        "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
                    "one_attempt": True,
                    "approval_path": str(approval_path),
                    "approval_sha256": admission.get("approval_sha256"),
                    "approval_public_key_path": str(public_key_path),
                    "approval_public_key_sha256": public_key_sha256,
                } or work.selection_origin != "SIGNED_MANUAL_HP_CONTROL" or
                type(selection_evidence) is not dict or
                admission.get("task_id") != work.task_id or
                admission.get("run_id") != selection_evidence.get("run_id") or
                selection_evidence.get("spec_sha256") !=
                    admission.get("spec_sha256")):
            return False

        product_src = Path(agents_module.__file__).resolve().parent.parent
        if (scope.get("engine_pins") !=
                _assumption_lifecycle_engine_pins(product_src) or
                scope.get("function_analysis_schema_sha256") !=
                    function_analysis_schema_sha256()):
            return False
        if scope.get("selection") != {
                "function_name": work.function_name,
                "automatic_discovery": False, "one_attempt": True}:
            return False
        pins = scope.get("qualification_pins")
        if (type(pins) is not dict or pins != {
                "source_tree_sha256": qualification.source_tree_sha256,
                "contract_sha256": qualification.contract_sha256,
                "harness_sha256": qualification.harness_sha256,
                "binary_sha256": qualification.binary_sha256,
                "normal_seed_sha256": getattr(
                    qualification, "normal_seed_sha256", None),
                "functions_json_sha256": control.get(
                    "functions_json_sha256"),
                "catalog_manifest_sha256": catalog_manifest_sha256,
                } or
                work.source_tree_sha256 != pins["source_tree_sha256"] or
                work.contract_sha256 != pins["contract_sha256"] or
                work.harness_sha256 != pins["harness_sha256"] or
                work.binary_sha256 != pins["binary_sha256"]):
            return False

        first = analysis_pipeline.provider
        second = assertion_pipeline.provider
        transports = {
            "function_analysis": first.provider,
            "assertion_generator": second.provider,
        }
        model = scope.get("model")
        routes = model.get("routes") if type(model) is dict else None
        if type(routes) is not dict or set(routes) != set(transports):
            return False
        executable_sha = model.get("codex_executable_sha256")
        for role, transport in transports.items():
            if (routes.get(role) != {
                    "model": getattr(transport, "model", None),
                    "reasoning": getattr(transport, "effort", None)} or
                    getattr(transport, "executable_sha256", None) !=
                        executable_sha):
                return False
        budgets = scope.get("budgets")
        gate = first.gate
        if (type(budgets) is not dict or budgets != {
                "max_model_calls": hp.get("max_model_calls"),
                "max_context_reanalyses": max_context_reanalyses,
                "max_context_requests_per_turn": 2,
                "physical_model_calls": caps.get("physical_model_calls"),
                "calls_per_agent": caps.get("calls_per_agent"),
                "model_wall_seconds": caps.get("model_wall_seconds"),
                "model_turn_seconds": caps.get("model_turn_seconds"),
                "physical": hp.get("physical"),
                } or
                gate.physical_max != caps.get("physical_model_calls") or
                gate.wall_seconds != caps.get("model_wall_seconds") or
                caps.get("calls_per_agent") != gate.physical_max or
                getattr(transports["function_analysis"],
                        "timeout_seconds", None) !=
                    caps.get("model_turn_seconds") or
                getattr(transports["assertion_generator"],
                        "timeout_seconds", None) !=
                    caps.get("model_turn_seconds") or
                analysis_pipeline.max_context_requests != 2 or
                assertion_pipeline.max_context_requests != 2 or
                hp.get("max_model_calls") != gate.physical_max or
                control.get("max_context_reanalyses", 2) !=
                    max_context_reanalyses or
                scope.get("credit") != {
                    "automatic_discovery": False,
                    "security_gate_credit": "NOT_CREDITED"}):
            return False
        return True
    except (AttributeError, KeyError, OSError, TypeError, ValueError,
            UnicodeError):
        return False


def _parallel_hp_evidence_ok(evidence: Any, *, task_id: str,
                             function_id: str, direction_id: str,
                             qualification: Any) -> bool:
    """Bind an HP-origin selection and one-shot claim to issued source pins."""
    from devtools.parallel_hp_selection import (
        verify_parallel_hp_execution_claim)
    try:
        expected = {
            "origin": "PARALLEL_HP_PRE_SP_SELECTION_V1",
            "task_id": task_id, "function_id": function_id,
            "direction_id": direction_id,
            "source_tree_sha256": qualification.source_tree_sha256,
            "contract_sha256": qualification.contract_sha256,
        }
        extra = {"run_id", "spec_sha256", "direction_plan_sha256",
                 "function_catalog_sha256", "selection_receipt_sha256",
                 "execution_claim_sha256", "run_dir"}
        return (type(evidence) is dict and
                set(evidence) == set(expected) | extra and
                all(evidence.get(key) == value
                    for key, value in expected.items()) and
                type(evidence.get("run_dir")) is str and
                verify_parallel_hp_execution_claim(
                    run_dir=Path(evidence["run_dir"]),
                    task_id=task_id, run_id=evidence.get("run_id"),
                    spec_sha256=evidence.get("spec_sha256"),
                    function_id=function_id, direction_id=direction_id,
                    direction_plan_sha256=evidence.get(
                        "direction_plan_sha256"),
                    function_catalog_sha256=evidence.get(
                        "function_catalog_sha256"),
                    selection_receipt_sha256=evidence.get(
                        "selection_receipt_sha256"),
                    execution_claim_sha256=evidence.get(
                        "execution_claim_sha256")))
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def prepare_hp_function(*, function: Function, direction: Direction,
                        qualification: Any, fuzzer: str,
                        sanitizer: str,
                        provider_free_selection_evidence: dict[str, str] | None = None,
                        signed_manual_hp_selection_evidence: dict[str, str] | None = None,
                        signed_auto_hp_selection_evidence: dict[str, str] | None = None,
                        parallel_hp_selection_evidence: dict[str, str] | None = None
                        ) -> PreparedHPFunction | dict[str, Any]:
    """Return exact source evidence or an isolated unsupported HP item.

    Explicit selection evidence admits a local fixture without an SP completion
    marker. Its origin is carried forward and cannot be used by the live roles.
    """
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
    if sum(value is not None for value in (
            provider_free_selection_evidence,
            signed_manual_hp_selection_evidence,
            signed_auto_hp_selection_evidence,
            parallel_hp_selection_evidence)) > 1:
        return _unsupported("HP_SELECTION_ORIGINS_CONFLICT")
    if (provider_free_selection_evidence is None and
            signed_manual_hp_selection_evidence is None and
            signed_auto_hp_selection_evidence is None and
            parallel_hp_selection_evidence is None and
            direction.direction_id not in function.analyzed_by_directions):
        return _unsupported("FBV2_SP_SELECTION_NOT_COMPLETED")
    if (type(qualification) is not OfficialPinnedQualification or
            qualification.product_issued is not True or
            qualification.contract_kind !=
                "OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2" or
            not _qualification_pins_ok(qualification)):
        return _unsupported("OFFICIAL_HARNESS_QUALIFICATION_INVALID")
    if provider_free_selection_evidence is not None:
        expected_selection = {
            "origin": "PROVIDER_FREE_FIXTURE",
            "task_id": function.task_id,
            "function_id": function.function_id,
            "direction_id": direction.direction_id,
            "source_tree_sha256": qualification.source_tree_sha256,
            "contract_sha256": qualification.contract_sha256,
        }
        if (type(provider_free_selection_evidence) is not dict or
                provider_free_selection_evidence != expected_selection):
            return _unsupported("PROVIDER_FREE_SELECTION_EVIDENCE_INVALID")
    if signed_manual_hp_selection_evidence is not None:
        evidence = signed_manual_hp_selection_evidence
        expected = {
            "origin": "SIGNED_MANUAL_HP_CONTROL",
            "task_id": function.task_id,
            "function_id": function.function_id,
            "direction_id": direction.direction_id,
            "source_tree_sha256": qualification.source_tree_sha256,
            "contract_sha256": qualification.contract_sha256,
        }
        if (type(evidence) is not dict or
                set(evidence) != set(expected) | {
                    "run_id", "spec_sha256", "selection_claim_sha256"} or
                any(evidence.get(key) != value for key, value in expected.items()) or
                any(type(evidence.get(key)) is not str or
                    re.fullmatch(r"[0-9a-f]{64}", evidence[key]) is None
                    for key in ("spec_sha256", "selection_claim_sha256")) or
                type(evidence.get("run_id")) is not str or
                re.fullmatch(r"[0-9a-f]{24}", evidence["run_id"]) is None):
            return _unsupported("SIGNED_MANUAL_HP_SELECTION_EVIDENCE_INVALID")
    if signed_auto_hp_selection_evidence is not None:
        evidence = signed_auto_hp_selection_evidence
        expected = {
            "origin": "SIGNED_AUTO_HP_AFTER_LOCAL_SP_EXHAUSTION",
            "task_id": function.task_id,
            "function_id": function.function_id,
            "direction_id": direction.direction_id,
            "source_tree_sha256": qualification.source_tree_sha256,
            "contract_sha256": qualification.contract_sha256,
        }
        if (type(evidence) is not dict or
                set(evidence) != set(expected) | {
                    "run_id", "spec_sha256", "selection_receipt_sha256",
                    "hp_run_claim_sha256"} or
                any(evidence.get(key) != value for key, value in expected.items()) or
                any(type(evidence.get(key)) is not str or
                    re.fullmatch(r"[0-9a-f]{64}", evidence[key]) is None
                    for key in ("spec_sha256", "selection_receipt_sha256",
                                "hp_run_claim_sha256")) or
                type(evidence.get("run_id")) is not str or
                re.fullmatch(r"[0-9a-f]{24}", evidence["run_id"]) is None):
            return _unsupported("SIGNED_AUTO_HP_SELECTION_EVIDENCE_INVALID")
    if parallel_hp_selection_evidence is not None:
        if not _parallel_hp_evidence_ok(
                parallel_hp_selection_evidence, task_id=function.task_id,
                function_id=function.function_id,
                direction_id=direction.direction_id,
                qualification=qualification):
            return _unsupported("PARALLEL_HP_SELECTION_EVIDENCE_INVALID")
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
        "selection_origin": ("PROVIDER_FREE_FIXTURE" if
                             provider_free_selection_evidence is not None else
                             "SIGNED_MANUAL_HP_CONTROL" if
                             signed_manual_hp_selection_evidence is not None else
                             "SIGNED_AUTO_HP_AFTER_LOCAL_SP_EXHAUSTION" if
                             signed_auto_hp_selection_evidence is not None else
                             "PARALLEL_HP_PRE_SP_SELECTION_V1" if
                             parallel_hp_selection_evidence is not None else
                             "FBV2_SP_SELECTION"),
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
            "Explicit provider-free fixture selection and source context "
            "only; no FBv2 SP completion, SAFE judgment, attacker control, "
            "or vulnerability is established." if
            provider_free_selection_evidence is not None else
            "Signed manual HP control selection and source context only; "
            "no FBv2 SP completion, automatic discovery, or vulnerability "
            "is established." if
            signed_manual_hp_selection_evidence is not None else
            "Signed automatic FBv2 function selection after local SP "
            "opportunity exhaustion; no SP completion, SAFE judgment, "
            "or vulnerability is established." if
            signed_auto_hp_selection_evidence is not None else
            "Pinned parallel HP function selection before SP analysis; "
            "no SP conclusion, SAFE judgment, or vulnerability is "
            "established." if
            parallel_hp_selection_evidence is not None else
            "FBv2 selection and source context only; no SAFE judgment, "
            "attacker control, or vulnerability is established."),
    }
    if signed_manual_hp_selection_evidence is not None:
        scope["selection_evidence"] = dict(signed_manual_hp_selection_evidence)
    if signed_auto_hp_selection_evidence is not None:
        scope["selection_evidence"] = dict(signed_auto_hp_selection_evidence)
    if parallel_hp_selection_evidence is not None:
        scope["selection_evidence"] = dict(parallel_hp_selection_evidence)
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
        selection_origin=scope["selection_origin"],
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
    # AgentPipeline keeps an unlinked raw SAFE proposal in `unknowns` instead
    # of promoting it to an Assertion candidate. Preserve only counts here:
    # a future live receipt can distinguish no proposal from a filtered one
    # without changing prompts or treating the proposal as a verified SAFE.
    unlinked = sum(type(item) is str and item.startswith(
        "Unlinked proposed safety assumption (not an Assertion candidate): ")
        for item in analysis.unknowns)
    unlisted = sum(type(item) is str and item.startswith(
        "Unlisted explicit safe assumption (not an Assertion candidate): ")
        for item in analysis.unknowns)
    selection = {
        "retained_safe_count": len(analysis.safe_assumptions),
        "unlinked_proposal_count": unlinked,
        "unlisted_explicit_count": unlisted,
        "selection_reason": (
            "RETAINED_EXPLICIT_SAFE" if analysis.safe_assumptions else
            "UNLINKED_PROPOSAL_FILTERED" if unlinked else
            "EXPLICIT_SAFE_OMITTED_FROM_TOP_LEVEL" if unlisted else
            "NO_SAFE_PROPOSAL_OBSERVED"),
    }
    if not analysis.safe_assumptions:
        return {**common, "status": "NO_SAFE_ASSUMPTION",
                "assertion_opportunity": "NONE",
                "safe_selection_observation": selection}
    return {**common, "status": "SAFE_PROPOSED_UNVERIFIED",
            "safe_assumption_count": len(analysis.safe_assumptions),
            "assertion_opportunity": "PENDING_INDEPENDENT_VALIDATION",
            "safe_selection_observation": selection}


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
    if (work.selection_origin == "PARALLEL_HP_PRE_SP_SELECTION_V1" and
            (work.analysis_scope.get("selection_origin") !=
                 work.selection_origin or
             not _parallel_hp_evidence_ok(
                 work.analysis_scope.get("selection_evidence"),
                 task_id=work.task_id, function_id=work.function_id,
                 direction_id=work.direction_id,
                 qualification=qualification))):
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


def _verified_hp_turn(provider: Any, role: str) -> dict[str, str] | None:
    """Snapshot one completed response from the shared CampaignModelGate."""
    try:
        request_id = provider.last_request_id
        if (type(request_id) is not str or not request_id or
                provider.role != role):
            return None
        rows = [entry for entry in provider.gate.snapshot()["records"]
                if entry.get("request_id") == request_id]
        evidence = provider.gate.verify_response_evidence(request_id)
        if (len(rows) != 1 or rows[0].get("status") != "COMPLETED" or
                rows[0].get("role") != role or
                rows[0].get("owner_id") != provider.owner_id or
                evidence.get("status") != "VERIFIED" or
                evidence.get("request_id") != request_id or
                type(evidence.get("response_sha256")) is not str or
                len(evidence["response_sha256"]) != 64 or
                not evidence.get("thread_id") or not evidence.get("turn_id")):
            return None
        return {"role": role, "owner_id": provider.owner_id,
                "request_id": request_id,
                "response_sha256": evidence["response_sha256"],
                "thread_id": evidence["thread_id"],
                "turn_id": evidence["turn_id"]}
    except Exception:
        return None


def _read_pinned_regular_bytes(path: Path, expected_sha256: str) -> bytes:
    """Read canonical pinned bytes once and bind path identity to the handle."""
    path = Path(path)
    if (not isinstance(expected_sha256, str) or
            re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None or
            not path.is_absolute() or path.is_symlink() or
            path != path.resolve(strict=True)):
        raise ValueError("pinned file identity is invalid")
    descriptor = os.open(
        path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
        getattr(os, "O_CLOEXEC", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("pinned file is not regular")
        chunks = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(descriptor)
        linked = path.stat(follow_symlinks=False)
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                row.st_mtime_ns, row.st_ctime_ns)
        raw = b"".join(chunks)
        if (identity(before) != identity(after) or
                identity(after) != identity(linked) or
                hashlib.sha256(raw).hexdigest() != expected_sha256):
            raise ValueError("pinned file changed")
        return raw
    finally:
        os.close(descriptor)


def _read_pinned_manifest(path: Path, expected_sha256: str) -> tuple[bytes, dict]:
    raw = _read_pinned_regular_bytes(path, expected_sha256)
    row = json.loads(raw.decode("utf-8"))
    if type(row) is not dict:
        raise ValueError("build manifest is not an object")
    return raw, row


def _pinned_manifest_file(entry: object, *, expected_path: Path | None = None,
                          expected_sha256: str | None = None) -> Path | None:
    """Return one canonical, byte-pinned file from a trusted build manifest."""
    if type(entry) is not dict or set(entry) != {"path", "sha256"}:
        return None
    path = Path(entry.get("path")) if type(entry.get("path")) is str else None
    digest = entry.get("sha256")
    try:
        if (path is None or not path.is_absolute() or path.is_symlink() or
                not path.is_file() or path != path.resolve(strict=True) or
                type(digest) is not str or
                not re.fullmatch(r"[0-9a-f]{64}", digest) or
                (expected_path is not None and
                 path != expected_path.resolve(strict=True)) or
                (expected_sha256 is not None and digest != expected_sha256)):
            return None
        _read_pinned_regular_bytes(path, digest)
    except (OSError, ValueError):
        return None
    return path


def _qualified_manifest_target_ok(*, qualification: Any, builder: Path,
                                  builder_sha256: str, manifest_path: Path,
                                  manifest_sha256: str) -> bool:
    """Bind a reviewed recipe to the issued official-Harness qualification."""
    try:
        manifest = Path(manifest_path)
        _read_pinned_regular_bytes(builder, builder_sha256)
        _, row = _read_pinned_manifest(manifest, manifest_sha256)
        root = Path(qualification.source_root).resolve(strict=True)
        harness = Path(qualification.harness).resolve(strict=True)
        binary = Path(qualification.binary).resolve(strict=True)
        common = (row.get("builder_sha256") == builder_sha256 and
                  row.get("source_root") == str(root))
        if not common:
            return False
        if (row.get("schema") == "MULTI_TU_ASSERTION_BUILD_V1" and
                row.get("kind") == "MD4C_ISOLATED_ASSERTION_RELINK_V1"):
            return (manifest == builder.with_name(
                        "multi_tu_assertion_build_manifest.json") and
                    row.get("harness_source") == str(harness) and
                    row.get("official_binary") == str(binary) and
                    row.get("official_binary_sha256") ==
                        qualification.binary_sha256)
        if (row.get("schema") != "QUALIFIED_SINGLE_TU_ASSERTION_BUILD_V1" or
                row.get("kind") != "CJSON_ISOLATED_ASSERTION_REBUILD_V1" or
                manifest != builder.with_name(
                    "cjson_assertion_build_manifest.json") or
                row.get("build_semantic_alignment") !=
                    "CJSON_CMAKE_CORE_MACROS_C89_ASAN_FUZZER_V1" or
                row.get("instrumented_source_transport") !=
                    "STDIN_WITH_PINNED_SOURCE_LINE_DIRECTIVE_V1" or
                row.get("allowed_output_names") != [
                    "guided-target", "instrumented-target", "original-target"] or
                row.get("output_publication") !=
                    "SAME_DIRECTORY_ATOMIC_LINK_NO_OVERWRITE_V1" or
                row.get("log_publication") !=
                    "PRIVATE_REGULAR_FILE_EXCLUSIVE_NOFOLLOW_V1" or
                _pinned_manifest_file(
                    row.get("interpreter"),
                    expected_path=Path("/usr/bin/python3.12"),
                    expected_sha256=
                    "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
                    is None or
                row.get("fixed_flags") != [
                    "-DCJSON_API_VISIBILITY", "-DCJSON_EXPORT_SYMBOLS",
                    "-DENABLE_LOCALES", "-std=c89", "-O1", "-g",
                    "-fno-omit-frame-pointer", "-fsanitize=fuzzer,address"]):
            return False
        return (
            _pinned_manifest_file(
                row.get("harness_source"), expected_path=harness,
                expected_sha256=qualification.harness_sha256) is not None and
            _pinned_manifest_file(
                row.get("official_binary"), expected_path=binary,
                expected_sha256=qualification.binary_sha256) is not None and
            _pinned_manifest_file(row.get("compiler")) is not None and
            _pinned_manifest_file(
                row.get("header_source"), expected_path=root / "cJSON.h")
                is not None and
            _pinned_manifest_file(
                row.get("harness_header_source"),
                expected_path=harness.parent.parent / "cJSON.h",
                expected_sha256=row["header_source"]["sha256"])
                is not None and
            _pinned_manifest_file(
                row.get("original_source"), expected_path=root / "cJSON.c")
                is not None)
    except (OSError, ValueError, TypeError, AttributeError,
            json.JSONDecodeError):
        return False


def _reviewed_relink_build_command(
        builder: Path, manifest_path: Path,
        manifest_sha256: str) -> list[str]:
    """Derive the only argv admitted by a pinned relinker manifest."""
    _, row = _read_pinned_manifest(manifest_path, manifest_sha256)
    if row.get("schema") == "QUALIFIED_SINGLE_TU_ASSERTION_BUILD_V1":
        interpreter = _pinned_manifest_file(
            row.get("interpreter"), expected_path=Path("/usr/bin/python3.12"),
            expected_sha256=
            "e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f")
        if interpreter is None:
            raise ValueError("cJSON relinker interpreter is not pinned")
        return [str(interpreter), "-I", str(builder),
                "--manifest-sha256", manifest_sha256,
                "{source}", "-o", "{binary}"]
    return [str(builder), "{source}", "-o", "{binary}"]


def _qualified_relink_recipe_ok(*, work: PreparedHPFunction,
                                qualification: Any, build_command: list[str],
                                manifest_path: Path,
                                manifest_sha256: str) -> bool:
    """Accept a reviewed relinker whose manifest binds all qualified inputs."""
    try:
        manifest = Path(manifest_path)
        _, row = _read_pinned_manifest(manifest, manifest_sha256)
        cjson_recipe = (
            row.get("schema") == "QUALIFIED_SINGLE_TU_ASSERTION_BUILD_V1")
        builder = Path(build_command[2] if cjson_recipe else build_command[0])
        expected_command = _reviewed_relink_build_command(
            builder, manifest, manifest_sha256)
        builder_sha256 = row.get("builder_sha256")
        if (build_command != expected_command or
                not isinstance(builder_sha256, str) or
                not _qualified_manifest_target_ok(
                    qualification=qualification, builder=builder,
                    builder_sha256=builder_sha256,
                    manifest_path=manifest, manifest_sha256=manifest_sha256)):
            return False
        root = Path(qualification.source_root)
        relative = Path(work.source_file).relative_to(root).as_posix()
        source_files = row.get("source_files")
        if (not isinstance(source_files, dict) or
                source_files.get(relative) != work.source_file_sha256):
            return False
        if row.get("schema") == "MULTI_TU_ASSERTION_BUILD_V1":
            return (any(
                        Path(name).name == Path(qualification.harness).name and
                        digest == qualification.harness_sha256
                        for name, digest in source_files.items()) and
                    relative in row.get("allowed_translation_units", {}))
        expected_sources = {
            "cJSON.c": work.source_file_sha256,
            "cJSON.h": row["header_source"]["sha256"],
            "fuzzing/cjson_read_fuzzer.c": qualification.harness_sha256,
        }
        return (relative == "cJSON.c" and source_files == expected_sources and
                row.get("allowed_translation_units") == {
                    relative: work.source_file_sha256} and
                row.get("original_source") == {
                    "path": str(Path(work.source_file).resolve()),
                    "sha256": work.source_file_sha256})
    except (OSError, ValueError, TypeError, KeyError, IndexError, json.JSONDecodeError):
        return False


def _qualified_context_build_command(
    work: PreparedHPFunction, qualification: Any,
    physical: dict[str, Any] | None,
) -> tuple[list[str] | None, dict[str, str] | None,
           dict[str, str] | None]:
    """Reuse a reviewed relinker's pinned compile flags for HP context."""
    if physical is None:
        return None, None, None
    try:
        builder = Path(physical["builder_path"])
        manifest = Path(physical["manifest_path"])
        command = _reviewed_relink_build_command(
            builder, manifest, physical["manifest_sha256"])
        _read_pinned_regular_bytes(builder, physical["builder_sha256"])
        if (physical.get("enabled") is not True or
                not _qualified_relink_recipe_ok(
                    work=work, qualification=qualification,
                    build_command=command, manifest_path=manifest,
                    manifest_sha256=physical["manifest_sha256"])):
            raise ValueError("HP context build recipe changed")
        _, row = _read_pinned_manifest(
            manifest, physical["manifest_sha256"])
        if row.get("schema") == "QUALIFIED_SINGLE_TU_ASSERTION_BUILD_V1":
            compiler = _pinned_manifest_file(row.get("compiler"))
            root = Path(qualification.source_root).resolve(strict=True)
            source_hashes = row.get("source_files")
            if (compiler is None or type(source_hashes) is not dict or
                    any(type(key) is not str or type(value) is not str or
                        not re.fullmatch(r"[0-9a-f]{64}", value)
                        for key, value in source_hashes.items())):
                raise ValueError("HP context source pins are invalid")
            environment = {"HOME": str(Path(work.source_file).parent),
                           "PATH": "/usr/bin:/bin",
                           "TMPDIR": str(Path(work.source_file).parent),
                           "LC_ALL": "C", "LANG": "C"}
            return ([str(compiler), *row["fixed_flags"], "-I" + str(root),
                     "{source}"], source_hashes, environment)
        # The checked builder already derives the flags from the pinned
        # official receipt. Its preflight also checks source and toolchain
        # hashes; no second flag parser or guessed include path is needed.
        loaded = runpy.run_path(str(builder), run_name="fbv2_hp_context")
        if (hashlib.sha256(builder.read_bytes()).hexdigest() !=
                physical["builder_sha256"]):
            raise ValueError("HP context builder changed during load")
        build_manifest, receipt = loaded["_verified"](manifest)
        root = Path(qualification.source_root)
        relative = Path(work.source_file).relative_to(root).as_posix()
        if relative not in build_manifest["allowed_translation_units"]:
            raise ValueError("HP context translation unit is not qualified")
        compiler = loaded["LLVM_BIN"] / "clang"
        source_hashes = build_manifest["source_files"]
        if (type(source_hashes) is not dict or
                any(type(key) is not str or type(value) is not str or
                    len(value) != 64 for key, value in source_hashes.items())):
            raise ValueError("HP context source pins are invalid")
        return ([str(compiler), *loaded["_flags"](receipt, relative, root),
                 "{source}"], source_hashes, loaded["_child_environment"]())
    except (AttributeError, OSError, KeyError, TypeError,
            ValueError, RuntimeError) as exc:
        raise ValueError("HP context build recipe unavailable") from exc


def _qualified_context_process_envelope(
    bound: Any, work: PreparedHPFunction, qualification: Any,
    physical: dict[str, Any] | None, pin_check: Callable[[], None],
):
    """Account each HP context compiler in the existing shared V2 ledger."""
    if physical is None:
        return None
    from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2

    expected = _qualified_context_build_command(work, qualification, physical)

    def pin(_phase: str, _command: list[str]) -> None:
        pin_check()
        if (not _prepared_pins_ok(work, qualification) or
                _qualified_context_build_command(work, qualification,
                                                 physical) != expected):
            raise ValueError("HP context source or build recipe changed")

    context_wall_limit = float(physical["total_wall_seconds"])

    class HPContextProcessEnvelope(DevelopmentProcessEnvelopeV2):
        """Charge one cumulative context-process window across model turns.

        The ordinary envelope starts its deadline at construction.  HP needs
        that same limit for the compiler processes, while model analysis
        between context requests has its own signed model budget.
        """

        def before_process(self, command: list[str], *, cwd: Path | None,
                           env: dict[str, str] | None, timeout: float,
                           kind: str, segment: str):
            if (kind != "AUX_PROCESS" or segment not in {
                    "hp_context.active_lines",
                    "hp_context.macro_definitions"}):
                raise ValueError("HP context process identity changed")
            receipt, _ = self.ledger.receipt_snapshot()
            if (receipt["stop_status"] is not None or
                    any(key.startswith(self._prefix)
                        for key in receipt["active"])):
                raise RuntimeError("HP context process account is unsettled")
            rows = [row for row in receipt["finished"]
                    if row["key"].startswith(self._prefix)]
            if len(rows) != self._next_ordinal:
                raise RuntimeError("HP context process ordinal changed")
            elapsed = []
            for ordinal, row in enumerate(rows):
                seconds = row.get("physical_seconds")
                if (not row["key"].startswith(
                        f"{self._prefix}{ordinal:06d}:") or
                        row["key"].rsplit(":", 1)[-1] not in {
                            "hp_context.active_lines",
                            "hp_context.macro_definitions"} or
                        row.get("kind") != "AUX_PROCESS" or
                        row.get("cleanup_complete") is not True or
                        row.get("output_limited") is not False or
                        row.get("overrun") is not False or
                        type(seconds) not in (int, float) or
                        not math.isfinite(seconds) or seconds < 0):
                    raise RuntimeError("HP context process receipt changed")
                elapsed.append(float(seconds))
            remaining = context_wall_limit - math.fsum(elapsed)
            self.deadline_monotonic = time.monotonic() + max(0.0, remaining)
            return super().before_process(
                command, cwd=cwd, env=env, timeout=timeout,
                kind=kind, segment=segment)

    return HPContextProcessEnvelope(
        bound.process_ledger, work_item_id=bound.identity.task_id,
        assertion_id="hp_context", attempt_id=bound.identity.run_id,
        output_limit_bytes=physical["output_limit_bytes"],
        total_wall_seconds=physical["total_wall_seconds"],
        pin_hook=pin)


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
    live_process_envelope: Any | None = None,
    live_claim_path: Path | None = None,
    live_claim_sha256: str | None = None,
) -> dict[str, Any]:
    """Hand one HP proposal to explicit Assertion execution callbacks.

    Fixtures provide callbacks explicitly. A live caller additionally needs a
    pinned instrumented-build recipe, durable one-shot claim, and HP-specific
    V2 process envelope on the shared ledger. The public live CLI keeps its
    separate admission guard. A proposal or witness never earns Gate or
    discovery credit here.
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

    if (type(work) is PreparedHPFunction and
            (work.selection_origin == "PROVIDER_FREE_FIXTURE" or
             work.analysis_scope.get("selection_origin") ==
             "PROVIDER_FREE_FIXTURE") and provider_free_fixture is not True):
        return blocked("PROVIDER_FREE_SELECTION_CANNOT_RUN_LIVE")

    if provider_free_fixture is not True:
        # The public CLI still blocks HP live model calls. This narrow seam
        # makes the physical handoff reviewable under a separate, one-shot
        # signed builder claim. A caller cannot substitute ad hoc callbacks.
        try:
            from dev_process_envelope_v2 import DevelopmentProcessEnvelopeV2
            from vulnerabilityanalysis.assertions import (
                execute_assertion, guided_fuzz_assertion)
        except ImportError:
            return blocked("LIVE_HP_INSTRUMENTED_BUILD_AND_ENVELOPE_NOT_ADMITTED")
        claim = Path(live_claim_path) if live_claim_path is not None else None
        try:
            claim_raw = claim.read_bytes() if claim is not None else None
            claim_row = json.loads(claim_raw) if claim_raw is not None else None
            proposal_sha = hashlib.sha256(json.dumps(
                analysis_result, sort_keys=True, separators=(",", ":"),
                allow_nan=False).encode()).hexdigest()
            provenance_sha = hashlib.sha256(json.dumps(
                analysis_result.get("hp_model_provenance"), sort_keys=True,
                separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        except (OSError, ValueError, TypeError):
            claim_raw = None
            claim_row = None
            proposal_sha = None
            provenance_sha = None
        if (type(live_process_envelope) is not DevelopmentProcessEnvelopeV2 or
                claim is None or not claim.is_absolute() or
                claim.is_symlink() or not claim.is_file() or
                claim != claim.resolve() or
                type(live_claim_sha256) is not str or
                claim_raw is None or
                hashlib.sha256(claim_raw).hexdigest() !=
                    live_claim_sha256 or
                type(claim_row) is not dict or
                claim_row.get("kind") != "FBV2_HP_PHYSICAL_CLAIM_V1" or
                claim_row.get("task_id") != getattr(work, "task_id", None) or
                claim_row.get("run_id") != live_process_envelope.attempt_id or
                claim_row.get("worker_id") != worker_id or
                claim_row.get("function_id") != getattr(work, "function_id", None) or
                claim_row.get("direction_id") != getattr(work, "direction_id", None) or
                claim_row.get("assertion_id") != assertion_id or
                type(claim_row.get("assertion_selection")) is not dict or
                claim_row["assertion_selection"].get(
                    "selected_assertion_id") != assertion_id or
                claim_row.get("proposal_sha256") != proposal_sha or
                claim_row.get("hp_model_provenance") !=
                    analysis_result.get("hp_model_provenance") or
                claim_row.get("hp_model_provenance_sha256") !=
                    provenance_sha or
                claim_row.get("source_sha256") != getattr(work, "source_sha256", None) or
                claim_row.get("source_tree_sha256") != getattr(work, "source_tree_sha256", None) or
                claim_row.get("harness_sha256") != getattr(work, "harness_sha256", None) or
                claim_row.get("binary_sha256") != getattr(work, "binary_sha256", None) or
                claim_row.get("manifest_sha256") != builder_manifest_sha256 or
                claim_row.get("build_command") != build_command or
                claim_row.get("build_command_sha256") != hashlib.sha256(
                    json.dumps(build_command, sort_keys=True,
                               separators=(",", ":"),
                               allow_nan=False).encode()).hexdigest() or
                builder_manifest_path is None or
                builder_manifest_sha256 is None or
                execute_callback is not None or guided_callback is not None or
                live_process_envelope.assertion_id != assertion_id or
                live_process_envelope.work_item_id !=
                    getattr(work, "task_id", None)):
            return blocked("LIVE_HP_INSTRUMENTED_BUILD_AND_ENVELOPE_NOT_ADMITTED")
        execute_callback = partial(
            execute_assertion, process_envelope=live_process_envelope)
        guided_callback = partial(
            guided_fuzz_assertion, process_envelope=live_process_envelope)
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
        # A seed can miss the assertion even when mutations can reach it.
        # NOT_REACHED is a valid starting point for Guided Fuzzing.
        if guided_seconds and executed.status in {
                "HELD_FOR_EXECUTION", "VIOLATED", "NOT_REACHED"}:
            guided = guided_callback(
                executed, source, line, seed,
                output_dir / "guided", build_command, run_command,
                seconds=guided_seconds)
        if not execution_pins_ok():
            return blocked("PREPARED_SOURCE_OR_QUALIFICATION_CHANGED")
    except Exception as exc:
        return {**common, "status": "INCOMPLETE_HP_ASSERTION_HANDOFF",
                "error_type": type(exc).__name__}
    from devtools.hp_result_observations import hp_physical_observations
    complete = (type(executed.status) is str and
                executed.status in {"HELD_FOR_EXECUTION", "VIOLATED", "NOT_REACHED"}
                and (guided_seconds == 0 or
                     type(guided) is dict and type(guided.get("status")) is str and
                     guided.get("status") in
                     {"RAN", "ASSERTION_WITNESS_OBSERVED"}))
    observations = hp_physical_observations(executed.status, guided)
    handoff_status = ("HP_ASSERTION_HANDOFF_COMPLETE" if complete else
                      "HP_GUIDED_CRASH_OBSERVED_UNGATED" if
                      observations["guided_crash_observed_ungated"] is True else
                      "INCOMPLETE_HP_ASSERTION_HANDOFF")
    result = {**common, "status": handoff_status,
            "assertion_id": assertion.assertion_id,
            "assertion_status": executed.status,
            "seed_sha256": qualification.normal_seed_sha256,
            "source_sha256": work.source_sha256,
            "evidence_id": getattr(evidence, "evidence_id", None),
            "guided_status": (guided.get("status") if type(guided) is dict else
                              "NOT_RUN" if guided is None else "INVALID_REPORT"),
            "guided_report": guided,
            "physical_observations": observations,
            "assertion_execution": ("CALLER_SUPPLIED_CALLBACK_RESULT"
                                    if provider_free_fixture else
                                    "PINNED_PRODUCT_CALLBACK_RESULT"),
            "proposal_origin": ("PROVIDER_FREE_FIXTURE" if provider_free_fixture
                                else "PINNED_HP_PROPOSAL_UNCREDITED")}
    if (not provider_free_fixture and
            handoff_status == "HP_GUIDED_CRASH_OBSERVED_UNGATED"):
        from devtools.hp_guided_crash_freeze import (
            freeze_reported_hp_guided_crash_leads)
        try:
            result["hp_crash_freeze"] = freeze_reported_hp_guided_crash_leads(
                handoff=result, task_id=work.task_id,
                run_id=live_process_envelope.attempt_id,
                worker_id=worker_id, function_id=work.function_id,
                direction_id=work.direction_id,
                assertion_id=assertion.assertion_id,
                guided_dir=output_dir / "guided",
                claim_root=output_dir / "hp-crash-claims",
                process_ledger=live_process_envelope.ledger)
        except Exception as exc:
            # A malformed or missing artifact must remain visible as an
            # incomplete lead, never erase the observed Crash or grant credit.
            result["hp_crash_freeze"] = {
                "status": "INCOMPLETE_HP_CRASH_LEAD_FREEZE",
                "error_type": type(exc).__name__,
                "security_gate_credit": "NOT_CREDITED",
                "discovery_credit": "NOT_CREDITED"}
    return result


def _pinned_context_graph(work: PreparedHPFunction, qualification: Any,
                          manifest_path: Path, manifest_sha256: str
                          ) -> tuple[dict[str, dict[str, Any]], Path, str,
                                     dict[Path, str]]:
    """Load only the V2 function IDs and edges pinned by the issued manifest."""
    manifest = Path(manifest_path)
    if (not manifest.is_absolute() or manifest.is_symlink() or
            manifest != manifest.resolve() or
            not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256)):
        raise ValueError("HP context manifest identity is invalid")
    raw = manifest.read_bytes()
    if hashlib.sha256(raw).hexdigest() != manifest_sha256:
        raise ValueError("HP context manifest changed")
    body = json.loads(raw)
    catalog = body.get("catalog", {})
    pins: dict[Path, str] = {manifest: manifest_sha256}
    artifacts: dict[str, Path] = {}
    artifact_bytes: dict[str, bytes] = {}
    for name in ("functions", "edges"):
        entry = catalog.get(name)
        if type(entry) is not dict or set(entry) != {"path", "sha256"}:
            raise ValueError("HP context artifact is not pinned")
        path = Path(entry["path"])
        digest = entry["sha256"]
        if (not path.is_absolute() or path.is_symlink() or
                path != path.resolve() or not path.is_file() or
                path.suffix != ".jsonl" or path.stat().st_size > 16_000_000 or
                type(digest) is not str or
                not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("HP context artifact changed")
        content = path.read_bytes()
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError("HP context artifact changed")
        artifacts[name] = path
        artifact_bytes[name] = content
        pins[path] = digest
    source_root = Path(qualification.source_root)
    relative = str(Path(work.source_file).relative_to(source_root))
    if (body.get("source_files", {}).get(relative) !=
            work.source_file_sha256 or
            body.get("asan_binary", {}).get("sha256") != work.binary_sha256):
        raise ValueError("HP context catalog differs from qualified source or binary")
    rows = [json.loads(line) for line in
            artifact_bytes["functions"].decode("utf-8").splitlines()
            if line.strip()]
    functions: dict[str, dict[str, Any]] = {}
    selected: list[str] = []
    for row in rows:
        if type(row) is not dict:
            raise ValueError("HP context function row is invalid")
        key = row.get("function_id")
        if (type(key) is not str or not re.fullmatch(r"fn-[0-9a-f]{20}", key)
                or key in functions):
            raise ValueError("HP context function identity is invalid")
        functions[key] = row
        if (row.get("name") == work.function_name and
                row.get("file") == relative and
                row.get("start_line") == work.source_start_line and
                row.get("end_line") == work.source_end_line and
                row.get("source", "").strip() == work.source.strip()):
            selected.append(key)
    if len(selected) != 1 or not functions:
        raise ValueError("HP function has no unique pinned context graph identity")
    return functions, artifacts["edges"], selected[0], pins


def _pinned_static_call_path(work: PreparedHPFunction, qualification: Any,
                             manifest_path: Path, manifest_sha256: str
                             ) -> tuple[dict[str, Any], dict[Path, str]]:
    """Describe a bounded source call path, never input-specific reachability."""
    from vulnerabilityanalysis.source import _mask_noncode

    functions, edges_path, target_id, pins = _pinned_context_graph(
        work, qualification, manifest_path, manifest_sha256)
    body = json.loads(Path(manifest_path).read_bytes())
    primary_entry = body.get("entry_function")
    declared_entries = body.get("entry_functions")
    if declared_entries is None:
        entry_names = [primary_entry]
    else:
        if (type(declared_entries) is not list or not declared_entries or
                len(declared_entries) > 100 or
                any(type(name) is not str or
                    not re.fullmatch(r"[A-Za-z_]\w*", name)
                    for name in declared_entries) or
                len(declared_entries) != len(set(declared_entries)) or
                primary_entry not in declared_entries):
            raise ValueError("HP static entry functions are invalid")
        entry_names = list(declared_entries)
    if (type(primary_entry) is not str or
            not re.fullmatch(r"[A-Za-z_]\w*", primary_entry) or
            len(functions) > 1_000):
        raise ValueError("HP static entry function is not unique")
    entry_rows: list[tuple[str, str]] = []
    for entry_name in entry_names:
        matches = [key for key, row in functions.items()
                   if row.get("name") == entry_name]
        if len(matches) != 1:
            raise ValueError("HP static entry function is not unique")
        entry_rows.append((entry_name, matches[0]))
    harness = Path(work.harness_path)
    if (not harness.is_file() or harness.is_symlink() or
            hashlib.sha256(harness.read_bytes()).hexdigest() !=
                work.harness_sha256 or
            any(re.search(r"\b" + re.escape(entry_name) + r"\s*\(",
                          _mask_noncode(harness.read_text(encoding="utf-8")))
                is None for entry_name, _ in entry_rows)):
        raise ValueError("HP static entry is not in the pinned harness")
    pins[harness] = work.harness_sha256
    raw_edges = edges_path.read_text(encoding="utf-8").splitlines()
    if len(raw_edges) > 10_000:
        raise ValueError("HP static call graph exceeds bound")
    graph: dict[str, list[dict[str, Any]]] = {}
    for line in raw_edges:
        if not line.strip():
            continue
        edge = json.loads(line)
        if (type(edge) is not dict or
                edge.get("kind") not in {"DIRECT_AST_ID", "SOURCE_DIRECT_COMPILED"}):
            continue
        caller, callee = edge.get("caller_id"), edge.get("callee_id")
        if (caller in functions and callee in functions and
                type(edge.get("line")) is int and
                type(edge.get("edge_id")) is str):
            graph.setdefault(caller, []).append(edge)
    for edges in graph.values():
        edges.sort(key=lambda row: row["edge_id"])
    queue = deque((entry_id, [], entry_name)
                  for entry_name, entry_id in entry_rows)
    seen = {entry_id for _, entry_id in entry_rows}
    path: list[dict[str, Any]] | None = None
    selected_entry: str | None = None
    while queue:
        current, prefix, entry_name = queue.popleft()
        if current == target_id:
            path = prefix
            selected_entry = entry_name
            break
        if len(prefix) >= 8:
            continue
        for edge in graph.get(current, []):
            callee = edge["callee_id"]
            if callee not in seen:
                seen.add(callee)
                queue.append((callee, [*prefix, edge], entry_name))
    # The harness entry is a valid zero-edge path to itself. Its direct
    # harness call was pinned above; no graph edge is needed or invented.
    if path is None or selected_entry is None:
        raise ValueError("HP target has no bounded pinned direct-call path")
    root = Path(qualification.source_root)
    source_hashes = body.get("source_files")
    if type(source_hashes) is not dict:
        raise ValueError("HP static source pin table is missing")
    evidence: list[dict[str, Any]] = []
    for edge in path:
        caller = functions[edge["caller_id"]]
        callee = functions[edge["callee_id"]]
        relative = caller.get("file")
        line_number = edge["line"]
        callee_name = callee.get("name")
        if (type(relative) is not str or type(callee_name) is not str or
                not re.fullmatch(r"[A-Za-z_]\w*", callee_name) or
                type(caller.get("start_line")) is not int or
                type(caller.get("end_line")) is not int or
                not caller["start_line"] <= line_number <= caller["end_line"]):
            raise ValueError("HP static callsite identity is invalid")
        source = root / relative
        if (source.is_symlink() or not source.is_file() or
                source != source.resolve() or root not in source.parents or
                source.stat().st_size > 8_000_000):
            raise ValueError("HP static callsite source is unsafe")
        wanted = source_hashes.get(relative)
        if (type(wanted) is not str or
                not re.fullmatch(r"[0-9a-f]{64}", wanted) or
                hashlib.sha256(source.read_bytes()).hexdigest() != wanted):
            raise ValueError("HP static callsite source changed")
        lines = source.read_text(encoding="utf-8").splitlines()
        if (line_number > len(lines) or
                re.search(r"\b" + re.escape(callee_name) + r"\s*\(",
                          lines[line_number - 1]) is None):
            raise ValueError("HP static callsite is absent")
        pins[source] = wanted
        evidence.append({
            "caller": caller["name"], "callee": callee_name,
            "callsite": f"{relative}:{line_number}",
            "edge_id": edge["edge_id"], "edge_kind": edge["kind"],
            "source_file_sha256": wanted,
        })
    static_path = {
        "evidence_level": ("PINNED_HARNESS_ENTRY_ONLY" if not path else
                           "PINNED_STATIC_DIRECT_CALL_PATH_ONLY"),
        "runtime_reachability": "UNPROVEN_FOR_ANY_INPUT",
        "entry_function": selected_entry,
        "target_function": work.function_name,
        "manifest_sha256": manifest_sha256,
        "functions_sha256": body["catalog"]["functions"]["sha256"],
        "edges_sha256": body["catalog"]["edges"]["sha256"],
        "edges": evidence,
    }
    if (len(json.dumps(static_path, sort_keys=True)) > 5_000 or
            not _context_pins_ok(pins)):
        raise ValueError("HP static call path changed or exceeded bound")
    return static_path, pins


def _pinned_initial_context_plan(
        work: PreparedHPFunction, qualification: Any,
        manifest_path: Path, manifest_sha256: str,
        static_path: dict[str, Any],
        context_build_command: list[str] | None,
        ) -> tuple[list[dict[str, str]], list[dict[str, str]],
                   list[dict[str, Any]]]:
    """Plan a small generic first-turn evidence bundle from pinned artifacts.

    The bundle contains no target-name allowlist and no SAFE claim. It keeps
    the full source for a bounded set of call-path functions, then adds at most
    one source-ordered support callee per target/path function. Function-like
    macros actually invoked by the selected source and active -D settings
    actually referenced by the selected evidence are added separately.
    """
    functions, edges_path, selected_key, _ = _pinned_context_graph(
        work, qualification, manifest_path, manifest_sha256)
    if (type(static_path) is not dict or
            static_path.get("target_function") != work.function_name or
            type(static_path.get("edges")) is not list):
        raise ValueError("HP initial Context path is invalid")
    try:
        raw_edges = [json.loads(line) for line in
                     edges_path.read_text(encoding="utf-8").splitlines()
                     if line.strip()]
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("HP initial Context graph is unavailable") from exc
    usable_edges = [row for row in raw_edges
                    if type(row) is dict and
                    row.get("kind") in {
                        "DIRECT_AST_ID", "SOURCE_DIRECT_COMPILED"} and
                    row.get("caller_id") in functions and
                    row.get("callee_id") in functions and
                    type(row.get("line")) is int and
                    type(row.get("edge_id")) is str]
    edge_by_id = {row["edge_id"]: row for row in usable_edges}
    if len(edge_by_id) != len(usable_edges):
        raise ValueError("HP initial Context edge identity is ambiguous")

    path_ids: list[str] = []
    for evidence in static_path["edges"]:
        edge = edge_by_id.get(evidence.get("edge_id"))
        if (edge is None or
                functions[edge["caller_id"]].get("name") !=
                    evidence.get("caller") or
                functions[edge["callee_id"]].get("name") !=
                    evidence.get("callee")):
            raise ValueError("HP initial Context path differs from pinned graph")
        if edge["caller_id"] not in path_ids:
            path_ids.append(edge["caller_id"])
    # A zero-edge target is also the Harness entry and has no caller source to
    # preload. The selected function itself is already the main prompt body.
    # Keep the complete bounded path here. The bundle limits below must record
    # every omitted caller explicitly; silently taking only the endpoints can
    # otherwise make an incomplete path look like a measured SAFE=0 result.

    path_nodes = set(path_ids)
    path_nodes.add(selected_key)
    support_ids: list[str] = []
    by_caller: dict[str, list[dict[str, Any]]] = {}
    for edge in usable_edges:
        by_caller.setdefault(edge["caller_id"], []).append(edge)
    for rows in by_caller.values():
        rows.sort(key=lambda row: (row["line"], row["edge_id"]))
    # Prefer evidence immediately consumed by the selected function, then one
    # source-ordered helper from each caller on the path nearest the target.
    for caller_id in [selected_key, *reversed(path_ids)]:
        extra = next((row["callee_id"] for row in by_caller.get(caller_id, [])
                      if row["callee_id"] not in path_nodes and
                      row["callee_id"] not in support_ids), None)
        if extra is not None:
            support_ids.append(extra)
        if len(support_ids) >= _INITIAL_CONTEXT_MAX_SUPPORT_CALLEES:
            break

    planned: list[dict[str, str]] = []
    audit: list[dict[str, Any]] = []
    source_chars = 0
    chosen_ids: list[str] = []
    for function_id, evidence_kind in [
            *((key, "PINNED_STATIC_PATH_FUNCTION") for key in path_ids),
            *((key, "PINNED_SOURCE_ORDERED_SUPPORT_CALLEE")
              for key in support_ids)]:
        if function_id in chosen_ids:
            continue
        row = functions[function_id]
        source = row.get("source")
        name = row.get("name")
        if (type(source) is not str or not source.strip() or
                type(name) is not str or
                len(chosen_ids) >= _INITIAL_CONTEXT_MAX_FUNCTIONS or
                source_chars + len(source) >
                    _INITIAL_CONTEXT_MAX_SOURCE_CHARS):
            audit.append({
                "target": name, "request_type": "FUNCTION", "round": -1,
                "status": "NOT_PRELOADED_BUNDLE_LIMIT",
                "evidence_kind": evidence_kind,
            })
            continue
        chosen_ids.append(function_id)
        source_chars += len(source)
        planned.append({
            "target": name, "request_type": "FUNCTION",
            "reason": evidence_kind,
            "expected_information":
                "pinned source and input/state relation before first analysis",
            "evidence_kind": evidence_kind,
        })

    body = json.loads(Path(manifest_path).read_bytes())
    source_hashes = body.get("source_files")
    root = Path(qualification.source_root)
    relative = str(Path(work.source_file).relative_to(root))
    source_path = root / relative
    if (type(source_hashes) is not dict or
            source_hashes.get(relative) != work.source_file_sha256 or
            hashlib.sha256(source_path.read_bytes()).hexdigest() !=
                work.source_file_sha256):
        raise ValueError("HP initial Context source changed")
    whole_source = source_path.read_text(encoding="utf-8", errors="replace")
    referenced_source = "\n".join([
        work.source,
        *(functions[key].get("source", "") for key in chosen_ids),
    ])
    macro_names = list(dict.fromkeys(re.findall(
        r"(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)", whole_source)))
    # A selected function may depend on a small file-scope configuration
    # object before the first model turn.  Preload only declarations that are
    # both at translation-unit scope and textually referenced by the selected
    # function.  The resolver still proves the exact declaration, active build
    # branch and source pin; this scan merely plans bounded requests and makes
    # no runtime-immutability claim.
    from vulnerabilityanalysis.source import _mask_noncode
    masked_source = _mask_noncode(whole_source)
    initializer_names: list[str] = []
    declaration = re.compile(
        r"(?m)^[ \t]*(?:(?:static|const|extern|volatile|register)[ \t]+)*"
        r"(?:struct[ \t]+[A-Za-z_]\w*[ \t]+|"
        r"[A-Za-z_]\w*(?:[ \t]+|[ \t]*\*[ \t]*))+"
        r"([A-Za-z_]\w*)[ \t]*(?:\[[^\]\n]*\][ \t]*)*=(?!=)")
    for match in declaration.finditer(masked_source):
        name = match.group(1)
        if (masked_source[:match.start()].count("{") !=
                masked_source[:match.start()].count("}") or
                re.search(r"\b" + re.escape(name) + r"\b", work.source) is None):
            continue
        if name not in initializer_names:
            initializer_names.append(name)
    for index, name in enumerate(initializer_names):
        if index >= _INITIAL_CONTEXT_MAX_INITIALIZERS:
            audit.append({
                "target": name, "request_type": "INITIALIZER", "round": -1,
                "status": "NOT_PRELOADED_BUNDLE_LIMIT",
                "evidence_kind":
                    "PINNED_SELECTED_SOURCE_INITIALIZER_REFERENCE",
            })
            continue
        planned.append({
            "target": name, "request_type": "INITIALIZER",
            "reason": "PINNED_SELECTED_SOURCE_INITIALIZER_REFERENCE",
            "expected_information":
                "file-scope initial declaration only; runtime state and "
                "immutability remain unproven",
            "evidence_kind":
                "PINNED_SELECTED_SOURCE_INITIALIZER_REFERENCE",
        })

    macro_requests = 0
    for name in macro_names:
        if re.search(r"\b" + re.escape(name) + r"\s*\(",
                     referenced_source) is None:
            continue
        if macro_requests >= _INITIAL_CONTEXT_MAX_SOURCE_MACROS:
            audit.append({
                "target": name, "request_type": "MACRO", "round": -1,
                "status": "NOT_PRELOADED_BUNDLE_LIMIT",
                "evidence_kind": "PINNED_SELECTED_SOURCE_MACRO_REFERENCE",
            })
            continue
        planned.append({
            "target": name, "request_type": "MACRO",
            "reason": "PINNED_SELECTED_SOURCE_MACRO_REFERENCE",
            "expected_information":
                "exact active definition used by the selected source",
            "evidence_kind": "PINNED_SELECTED_SOURCE_MACRO_REFERENCE",
        })
        macro_requests += 1

    build_rows: list[dict[str, str]] = []
    if context_build_command is not None:
        if (type(context_build_command) is not list or
                any(type(item) is not str for item in context_build_command) or
                len(context_build_command) > 128):
            raise ValueError("HP initial Context build command is invalid")
        command_digest = hashlib.sha256(json.dumps(
            context_build_command, ensure_ascii=False,
            separators=(",", ":")).encode("utf-8")).hexdigest()
        build_define_requests = 0
        for flag in context_build_command:
            match = re.fullmatch(
                r"-D([A-Za-z_]\w*)(?:=(.{1,256}))?", flag)
            if (match is None or
                    re.search(r"\b" + re.escape(match.group(1)) + r"\b",
                              referenced_source) is None):
                continue
            name, value = match.group(1), match.group(2) or "1"
            if build_define_requests >= _INITIAL_CONTEXT_MAX_BUILD_DEFINES:
                audit.append({
                    "target": name,
                    "request_type": "BUILD_MACRO",
                    "round": -1,
                    "status": "NOT_PRELOADED_BUNDLE_LIMIT",
                    "evidence_kind": "PINNED_ACTIVE_BUILD_DEFINE",
                })
                continue
            build_rows.append({
                "target": name,
                "request_type": "BUILD_MACRO",
                "function_name": "PINNED_BUILD_CONFIGURATION",
                "source": f"{name}={value}",
                "source_file": "",
                "source_location": "PINNED_BUILD_COMMAND",
                "relation": "ACTIVE_BUILD_DEFINE",
                "build_flag": flag,
                "build_command_sha256": command_digest,
                "evidence_kind": "PINNED_ACTIVE_BUILD_DEFINE",
                "runtime_reachability": "NOT_APPLICABLE",
            })
            build_define_requests += 1
    return planned, build_rows, audit


def _pinned_prior_caller_macro_context(*, resolver: Any, request: Any,
                                       prior_context: list[dict[str, str]],
                                       catalog: dict[str, dict[str, Any]],
                                       graph_path: Path, graph_sha256: str,
                                       selected_key: str,
                                       root: Path, source_hashes: dict[str, str]
                                       ) -> list[dict[str, str]]:
    """Show a macro through an already fetched direct caller, not a new edge.

    The product's general caller-macro resolver requires an exact build
    command. This narrower HP path uses the issued Catalog and only source
    branches that the conservative parser marks true without build flags.
    It makes no runtime reachability or build-wide activation claim.
    """
    if not re.fullmatch(r"[A-Za-z_]\w*", request.target):
        return []
    from vulnerabilityanalysis.source import _mask_noncode
    callers = [row for row in prior_context if type(row) is dict and
               row.get("request_type") == "CALLER" and
               row.get("relation") == "CALLER_OF"]
    if not 0 < len(callers) <= 3:
        return []
    try:
        graph_bytes = graph_path.read_bytes()
        if hashlib.sha256(graph_bytes).hexdigest() != graph_sha256:
            return []
        raw_edges = [json.loads(line) for line in graph_bytes.decode("utf-8").splitlines()
                     if line.strip()]
    except (OSError, UnicodeError, ValueError):
        return []
    definitions: list[dict[str, str]] = []
    for prior in callers:
        caller_id = prior.get("function_id")
        caller = catalog.get(caller_id) if type(caller_id) is str else None
        if (type(caller) is not dict or prior.get("function_name") != caller.get("name") or
                prior.get("related_function") != catalog[selected_key].get("name") or
                prior.get("call_type") not in {"DIRECT_AST_ID", "SOURCE_DIRECT_COMPILED"} or
                prior.get("callsite_excerpt") or
                "/* SOURCE TRUNCATED */" in prior.get("source", "")):
            return []
        relative = caller.get("file")
        if type(relative) is not str:
            return []
        caller_path = root / relative
        if (caller_path.is_symlink() or not caller_path.is_file() or
                caller_path != caller_path.resolve() or root not in caller_path.parents or
                prior.get("source_file") != str(caller_path)):
            return []
        try:
            caller_text = caller_path.read_text(encoding="utf-8", errors="replace")
            if (hashlib.sha256(caller_path.read_bytes()).hexdigest() !=
                    source_hashes.get(relative)):
                return []
            macro_edge = prior.get("callsite_location") == "UNKNOWN"
            if macro_edge and prior["call_type"] != "DIRECT_AST_ID":
                return []
            expected = resolver._function_context(
                caller_id, request, relation="CALLER_OF", related=selected_key,
                call_type=(prior["call_type"] if macro_edge else "direct"),
                relation_evidence=("CALL_GRAPH" if macro_edge else
                                   "SOURCE_CALLSITE"))
            if (expected is None or any(prior.get(key) != expected.get(key)
                                        for key in ("function_id", "function_name",
                                                    "source_file", "source_location",
                                                    "source", "callsite_location"))):
                return []
            matching_edges = [edge for edge in raw_edges
                              if edge.get("caller_id") == caller_id and
                              edge.get("callee_id") == selected_key and
                              edge.get("kind") == prior["call_type"]]
            if macro_edge:
                # A compiler edge can point at a macro invocation even when
                # the callee name is absent from the caller's source text.
                if len(matching_edges) != 1 or type(matching_edges[0].get("line")) is not int:
                    return []
                callsite_line = matching_edges[0]["line"]
                lines = caller_text.splitlines()
                invocation_pattern = (r"\b" + re.escape(request.target) +
                                      r"\s*\(")
                if (not 1 <= callsite_line <= len(lines) or
                        len(re.findall(invocation_pattern,
                                       _mask_noncode(lines[callsite_line - 1]))) != 1):
                    return []
                callsite_location = f"{caller_path}:{callsite_line}"
            else:
                callsite_path, _, callsite_text = prior["callsite_location"].rpartition(":")
                callsite_line = int(callsite_text)
                if callsite_path != str(caller_path):
                    return []
                matching_edges = [edge for edge in matching_edges
                                  if edge.get("line") == callsite_line]
                callsite_location = prior["callsite_location"]
            if (len(matching_edges) != 1 or
                    prior["call_type"] != matching_edges[0]["kind"]):
                return []
            _, caller_states = resolver._type_active_source(caller_text)
            if caller_states[callsite_line - 1] is not True:
                return []
            macro = resolver._invoked_macro_context(
                request.target, replace(request, requesting_function=caller_id))
            if (macro is None or macro.get("relation") != "MACRO_INVOKED_BY" or
                    macro.get("related_function") != caller_id):
                continue
            if macro_edge:
                callee_name = catalog[selected_key]["name"]
                if not re.search(r"\b" + re.escape(callee_name) + r"\s*\(",
                                 _mask_noncode(macro["source"])):
                    return []
            macro_call_path, _, macro_call_text = macro["callsite_location"].rpartition(":")
            macro_call_line = int(macro_call_text)
            if (macro_call_path != str(caller_path) or
                    (macro_edge and macro_call_line != callsite_line) or
                    caller_states[macro_call_line - 1] is not True):
                return []
            macro_path = Path(macro["source_file"])
            if (macro_path.is_symlink() or not macro_path.is_file() or
                    macro_path != macro_path.resolve() or root not in macro_path.parents):
                return []
            macro_relative = str(macro_path.relative_to(root))
            if (hashlib.sha256(macro_path.read_bytes()).hexdigest() !=
                    source_hashes.get(macro_relative)):
                return []
            definition_line = int(macro["source_location"].rsplit(":", 1)[1])
            _, definition_states = resolver._type_active_source(
                macro_path.read_text(encoding="utf-8", errors="replace"))
            if definition_states[definition_line - 1] is not True:
                return []
            definitions.append({**macro,
                                "related_analyzed_function": selected_key,
                                "caller_callsite_location": callsite_location,
                                "call_graph_artifact": str(graph_path),
                                "relation_evidence": (
                                    "PINNED_COMPILER_EDGE_AND_MACRO_BODY" if macro_edge else
                                    "PINNED_DIRECT_EDGE_AND_SOURCE_CALLSITES"),
                                "source_branch_state": "TRUE_BY_CONSERVATIVE_STATIC_PARSER",
                                "build_activation": "UNPROVEN",
                                "runtime_reachability": "UNPROVEN_FOR_ANY_INPUT"})
        except (KeyError, OSError, ValueError, IndexError, TypeError, UnicodeError):
            return []
    if len({(row["source_file"], row["source_location"], row["source"])
            for row in definitions}) != 1:
        return []
    return definitions


def _pinned_prior_function_macro_context(*, resolver: Any, request: Any,
                                         prior_context: list[dict[str, str]],
                                         catalog: dict[str, dict[str, Any]],
                                         selected_key: str, root: Path,
                                         source_hashes: dict[str, str]
                                         ) -> list[dict[str, str]]:
    """Resolve one macro through function evidence already shown to the model.

    The normal resolver binds a MACRO request to the selected function.  A
    later model turn may instead ask about a macro used by an already supplied
    helper.  Admit that relation only when the helper row exactly matches the
    pinned Catalog/source and every matching helper reaches the same active
    macro definition.  This does not search unrelated repository functions.
    """
    if not re.fullmatch(r"[A-Za-z_]\w*", request.target):
        return []
    matches: list[dict[str, str]] = []
    for prior in prior_context:
        if (type(prior) is not dict or
                prior.get("request_type") != "FUNCTION"):
            continue
        function_id = prior.get("function_id")
        function = catalog.get(function_id) if type(function_id) is str else None
        if type(function) is not dict:
            continue
        relative = function.get("file")
        start_line = function.get("start_line")
        source = function.get("source")
        name = function.get("name")
        if (type(relative) is not str or type(start_line) is not int or
                type(source) is not str or type(name) is not str or
                prior.get("function_name") != name or
                prior.get("source") != source or
                prior.get("source_location") !=
                    str(root / relative) + f":{start_line}" or
                "/* SOURCE TRUNCATED */" in source or
                re.search(r"\b" + re.escape(request.target) + r"\s*\(",
                          source) is None):
            continue
        path = root / relative
        try:
            if (path.is_symlink() or not path.is_file() or
                    path != path.resolve() or root not in path.parents or
                    prior.get("source_file") != str(path) or
                    hashlib.sha256(path.read_bytes()).hexdigest() !=
                        source_hashes.get(relative)):
                return []
            macro = resolver._invoked_macro_context(
                request.target,
                replace(request, requesting_function=function_id))
            if (macro is None or
                    macro.get("relation") != "MACRO_INVOKED_BY" or
                    macro.get("related_function") != function_id):
                continue
            macro_path = Path(macro["source_file"])
            if (macro_path.is_symlink() or not macro_path.is_file() or
                    macro_path != macro_path.resolve() or
                    root not in macro_path.parents or
                    hashlib.sha256(macro_path.read_bytes()).hexdigest() !=
                        source_hashes.get(str(macro_path.relative_to(root)))):
                return []
            matches.append({
                **macro,
                "related_analyzed_function": selected_key,
                "related_provided_function": function_id,
                "relation_evidence":
                    "PINNED_PROVIDED_FUNCTION_SOURCE_AND_MACRO_CALLSITE",
                "runtime_reachability": "UNPROVEN_FOR_ANY_INPUT",
            })
        except (KeyError, OSError, ValueError, TypeError):
            return []
    if not matches:
        return []
    definitions = {(row["source_file"], row["source_location"], row["source"])
                   for row in matches}
    return matches if len(definitions) == 1 else []


def _bounded_context(work: PreparedHPFunction, requests: list[Any],
                     qualification: Any, *,
                     context_build_command: list[str] | None = None,
                     context_source_hashes: dict[str, str] | None = None,
                     context_build_environment: dict[str, str] | None = None,
                     context_process_envelope: Any | None = None,
                     catalog_manifest_path: Path | None = None,
                     catalog_manifest_sha256: str | None = None,
                     enforce_manifest_source_pins: bool = False,
                     prior_context: list[dict[str, str]] | None = None,
                     seen_requests: set[tuple[str, str]] | None = None,
                     attempted_requests: set[tuple[str, str]] | None = None,
                     round_index: int = 0
                     ) -> tuple[list[dict[str, str]],
                                                 list[dict[str, Any]],
                                                 dict[Path, str]]:
    """Resolve at most two requests inside the issued source root."""
    from vulnerabilityanalysis.context import ContextResolver
    from vulnerabilityanalysis.models import ContextRequest
    from vulnerabilityanalysis.source import SourceRepository

    root = Path(qualification.source_root)
    pins: dict[Path, str] = {}
    source_hashes: dict[str, str] | None = None
    selected_key = work.function_id
    graph_path = None
    if catalog_manifest_path is not None or catalog_manifest_sha256 is not None:
        if catalog_manifest_path is None or catalog_manifest_sha256 is None:
            raise ValueError("HP context catalog pin is incomplete")
        catalog, graph_path, selected_key, pins = _pinned_context_graph(
            work, qualification, catalog_manifest_path,
            catalog_manifest_sha256)
        if enforce_manifest_source_pins:
            source_hashes = json.loads(
                Path(catalog_manifest_path).read_bytes()).get("source_files")
            if type(source_hashes) is not dict:
                raise ValueError("HP context source pin table is missing")
    else:
        catalog = {work.function_id: {
            "function_id": work.function_id, "name": work.function_name,
            "file": str(Path(work.source_file).relative_to(root)),
            "start_line": work.source_start_line,
            "end_line": work.source_end_line,
        }}
    if context_source_hashes is not None:
        if (type(context_source_hashes) is not dict or
                (source_hashes is not None and any(
                    key in source_hashes and source_hashes[key] != digest
                    for key, digest in context_source_hashes.items()))):
            raise ValueError("HP context source pin tables disagree")
        source_hashes = {**context_source_hashes, **(source_hashes or {})}
    repository = SourceRepository(root, catalog)
    # The issued md4c Catalog includes input-flow functions larger than 8 KB.
    # Admit a complete excerpt only in the pinned no-hint context path; the
    # ordinary HP path keeps its existing smaller bound.
    resolver = ContextResolver(repository,
                               max_chars=20_000 if enforce_manifest_source_pins else 8_000,
                               call_graph_path=graph_path, harness_path=None,
                               build_command=context_build_command,
                               build_environment=context_build_environment,
                               process_envelope=context_process_envelope)
    context: list[dict[str, str]] = []
    records: list[dict[str, Any]] = []
    if seen_requests is None:
        seen_requests = set()
    if attempted_requests is None:
        attempted_requests = set()
    seen_evidence: set[tuple[str, str, str]] = set()
    for index, request in enumerate(requests):
        record: dict[str, Any] = {
            "target": getattr(request, "target", None),
            "request_type": getattr(request, "request_type", None),
            "round": round_index,
        }
        if getattr(request, "hypothesis_index", None) is not None:
            record.update({
                "hypothesis_index": request.hypothesis_index,
                "attribution_verified": getattr(
                    request, "attribution_verified", False) is True,
                "related_hypothesis": getattr(
                    request, "related_hypothesis", ""),
                "related_judgment": getattr(
                    request, "related_judgment", ""),
                "related_reason": getattr(
                    request, "related_reason", ""),
                "related_source_location": getattr(
                    request, "related_source_location", ""),
                "related_security_property": getattr(
                    request, "related_security_property", ""),
                "related_safe_assumption": getattr(
                    request, "related_safe_assumption", ""),
            })
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
        if key in attempted_requests:
            record["status"] = "PREVIOUSLY_UNRESOLVED"
            records.append(record)
            continue
        attempted_requests.add(key)
        try:
            target = request.target
            if (request.request_type.upper() == "CALLER" and
                    target in {work.function_id, work.function_name}):
                target = "callers"
            elif (graph_path is not None and
                  request.request_type.upper() == "FUNCTION"):
                # The issued V2 Catalog is keyed by stable IDs; the HP role
                # requests source by C symbol. Only resolve an exact unique
                # name, leaving duplicate symbols unresolved.
                named = [key for key, row in catalog.items()
                         if row.get("name") == target]
                if len(named) == 1:
                    target = named[0]
            resolved = resolver.resolve(replace(
                request, requesting_function=selected_key, target=target))
            resolver_limit_events = list(resolver.last_limit_events)
            macro_alias = False
            if (not resolved and request.request_type.upper() == "TYPE" and
                    re.fullmatch(r"[A-Za-z_]\w*", target)):
                # C code may spell a type through an object-like macro (md4c
                # uses SZ/OFF).  Show only the proven macro definition.  It is
                # not a typedef, an expansion, or evidence of type layout.
                macros = resolver.resolve(replace(
                    request, requesting_function=selected_key, target=target,
                    request_type="MACRO"))
                resolver_limit_events.extend(resolver.last_limit_events)
                if len(macros) == 1:
                    macro = macros[0]
                    alias = re.fullmatch(
                        r"\s*#\s*define\s+" + re.escape(target) +
                        r"\s+([A-Za-z_]\w*)\s*", macro.get("source", ""))
                    if (alias is not None and alias.group(1) != target and
                            macro.get("definition_kind") == "OBJECT_LIKE_MACRO" and
                            macro.get("relation") == "MACRO_REFERENCED_BY" and
                            macro.get("related_function") == selected_key):
                        resolved = [{**macro, "original_request_type": "TYPE",
                                     "evidence_kind": "OBJECT_MACRO_ALIAS_ONLY",
                                     "type_layout_proven": "false"}]
                        macro_alias = True
            if (not resolved and request.request_type.upper() == "MACRO" and
                    graph_path is not None and source_hashes is not None and
                    prior_context):
                resolved = _pinned_prior_caller_macro_context(
                    resolver=resolver, request=request,
                    prior_context=prior_context, catalog=catalog,
                    graph_path=graph_path, graph_sha256=pins[graph_path],
                    selected_key=selected_key,
                    root=root, source_hashes=source_hashes)
                if resolved:
                    record["evidence_kind"] = "PINNED_DIRECT_CALLER_MACRO_ONLY"
            if (not resolved and request.request_type.upper() == "MACRO" and
                    source_hashes is not None and prior_context):
                resolved = _pinned_prior_function_macro_context(
                    resolver=resolver, request=request,
                    prior_context=prior_context, catalog=catalog,
                    selected_key=selected_key, root=root,
                    source_hashes=source_hashes)
                if resolved:
                    record["evidence_kind"] = (
                        "PINNED_PROVIDED_FUNCTION_MACRO_ONLY")
            record["resolver_limit_events"] = resolver_limit_events
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
        rejected_pin = False
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
                span_start = row.get("source_span_start")
                span_end = row.get("source_span_end")
                transformed = span_start is not None or span_end is not None
                if transformed and (
                        type(span_start) is not str or
                        type(span_end) is not str or
                        re.fullmatch(r"\d+", span_start) is None or
                        re.fullmatch(r"\d+", span_end) is None or
                        row.get("request_type") != "TYPE" or
                        row.get("relation_evidence") !=
                            "TYPEDEF_TAG_AND_COMPLETE_REACHABLE_DEFINITION" or
                        row.get("build_evidence") !=
                            "EXACT_COMMAND_PREPROCESSED_DECLARATION" or
                        context_build_command is None):
                    rejected_composite = True
                    continue
                if transformed:
                    first, end = int(span_start), int(span_end)
                    if not 0 <= first < end <= len(current):
                        rejected_changed = True
                        continue
                    anchor = current[first:end]
                else:
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
                if transformed:
                    active = resolver._active_build_lines(path)
                    if active is None:
                        rejected_composite = True
                        continue
                    start_line = current.count("\n", 0, first) + 1
                    active_lines = active.get(path, set())
                    reconstructed = "".join(
                        text if start_line + offset in active_lines else
                        re.sub(r"[^\n]", " ", text)
                        for offset, text in enumerate(
                            anchor.splitlines(keepends=True))).strip()
                    if reconstructed != excerpt:
                        rejected_changed = True
                        continue
                    # The model sees only active source. The original span is
                    # checked against the pinned file and stays out of context.
                    row = {key: value for key, value in row.items()
                           if key not in {"source_span_start", "source_span_end"}}
                if location is None:
                    row = {**row, "source_location": derived_location,
                           "location_evidence": "UNIQUE_CURRENT_SOURCE_EXCERPT"}
                digest = hashlib.sha256(raw).hexdigest()
                if (source_hashes is not None and
                        source_hashes.get(str(path.relative_to(root))) != digest):
                    rejected_pin = True
                    continue
            except (KeyError, OSError, ValueError, TypeError):
                rejected_outside = True
                continue
            evidence_key = (str(path), row.get("source_location", ""), row["source"])
            if evidence_key in seen_evidence:
                continue
            seen_evidence.add(evidence_key)
            pins[path] = digest
            fresh.append(row)
        if rejected_pin:
            raise ValueError("HP context source differs from issued manifest")
        context.extend(fresh)
        if fresh:
            # `seen_requests` means evidence was actually delivered.  Keep a
            # failed lookup only in `attempted_requests`; otherwise a later
            # model request would be mislabeled ALREADY_REQUESTED even though
            # the model never received the requested source.
            seen_requests.add(key)
        if fresh and macro_alias:
            seen_requests.add((target, "MACRO"))
            record["provided_request_type"] = "MACRO"
            record["evidence_kind"] = "OBJECT_MACRO_ALIAS_ONLY"
            record["type_layout_proven"] = False
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


def _unresolved_context_records(
        records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return newest unsatisfied record for each exact Context identity."""
    failed = {
        "SKIPPED_CONTEXT_ROUND_LIMIT", "SKIPPED_LLM_BUDGET",
        "SKIPPED_PER_TURN_LIMIT", "PREVIOUSLY_UNRESOLVED", "NOT_FOUND",
        "RESOLUTION_FAILED", "OUTSIDE_QUALIFIED_SOURCE_ROOT",
        "UNSUPPORTED_COMPOSITE_CONTEXT", "LOCATION_UNPROVEN",
        "CONTEXT_SOURCE_CHANGED_DURING_RESOLUTION", "NO_NEW_EVIDENCE",
        "REQUESTING_FUNCTION_MISMATCH", "NOT_PRELOADED_BUNDLE_LIMIT",
    }
    resolved = {"FETCHED", "ALREADY_REQUESTED"}
    unresolved: dict[tuple[Any, Any], tuple[int, dict[str, Any]]] = {}
    for index, row in enumerate(records):
        key = (row.get("target"), row.get("request_type"))
        status = row.get("status")
        if status in resolved:
            unresolved.pop(key, None)
        elif status in failed:
            unresolved[key] = (index, dict(row))
    return [item[1] for item in sorted(
        unresolved.values(), key=lambda item: item[0])]


def _last_unresolved_context_status(
        records: list[dict[str, Any]]) -> str | None:
    """Return the newest Context failure that was never later satisfied."""
    unresolved = _unresolved_context_records(records)
    return unresolved[-1].get("status") if unresolved else None


def _candidate_scoped_context_closure(
        lifecycle_rows: list[dict[str, Any]],
        context_records: list[dict[str, Any]],
        *, selected_source_file: str | None = None,
        ) -> tuple[list[str], dict[str, list[str]]]:
    """Select uniquely identifiable SAFE IDs under conservative Host binding.

    A same-response index proves only which evaluation row the model named; it
    does not prove the natural-language request is semantically related.  The
    Host permits candidate-scoped closure only for a structurally bound,
    separate ``POSSIBLE_BUG`` lead with no SAFE text.  UNKNOWN, SAFE,
    malformed and ambiguous bindings block every candidate.
    """
    def normalized_text(value: Any) -> str:
        return " ".join(value.split()) if isinstance(value, str) else ""

    def normalized_property(value: Any) -> str:
        if not isinstance(value, str):
            return ""
        return " ".join(filter(None, re.split(
            r"[^a-z0-9]+", value.casefold())))

    def exact_target_is_named(target: str, text: str) -> bool:
        if re.fullmatch(r"[A-Za-z_]\w*", target):
            return re.search(
                rf"(?<![A-Za-z0-9_]){re.escape(target)}"
                rf"(?![A-Za-z0-9_])", text) is not None
        return bool(target) and target in text

    def canonical_location(value: Any) -> tuple[str, int] | None:
        if not isinstance(value, str) or not selected_source_file:
            return None
        try:
            claimed_file, line_text = value.rsplit(":", 1)
            line = int(line_text)
        except (ValueError, IndexError):
            return None
        selected = Path(selected_source_file)
        claimed = Path(claimed_file)
        if claimed.is_absolute():
            if claimed.resolve(strict=False) != selected.resolve(strict=False):
                return None
        else:
            if not claimed.parts or ".." in claimed.parts:
                return None
            selected_parts = selected.parts
            if (len(claimed.parts) > len(selected_parts) or
                    selected_parts[-len(claimed.parts):] != claimed.parts):
                return None
        return str(selected.resolve(strict=False)), line

    candidates = [row for row in lifecycle_rows
                  if row.get("disposition") == "VALIDATED_SAFE" and
                  not row.get("required_context") and
                  isinstance(row.get("assumption_id"), str) and
                  row.get("assumption_id")]
    unresolved = _unresolved_context_records(context_records)
    eligible: list[str] = []
    blocked: dict[str, list[str]] = {}
    text_counts: dict[str, int] = {}
    for candidate in candidates:
        text = normalized_text(candidate.get("safe_assumption"))
        text_counts[text] = text_counts.get(text, 0) + 1
    for candidate in candidates:
        candidate_id = candidate["assumption_id"]
        reasons: list[str] = []
        candidate_text = normalized_text(candidate.get("safe_assumption"))
        if not candidate_text or text_counts.get(candidate_text, 0) != 1:
            reasons.append("AMBIGUOUS_SAFE_TEXT_IDENTITY")
        candidate_location = canonical_location(candidate.get("source_location"))
        candidate_property = normalized_property(
            candidate.get("security_property"))
        if candidate_location is None or not candidate_property:
            reasons.append("INVALID_CANDIDATE_IDENTITY")
        for record in unresolved:
            target = str(record.get("target") or "UNKNOWN")
            request_type = str(record.get("request_type") or "UNKNOWN")
            identity = f"{target}:{request_type}"
            if record.get("attribution_verified") is not True:
                reasons.append(f"UNVERIFIED_ATTRIBUTION:{identity}")
                continue
            related_text = (
                str(record.get("related_hypothesis") or "") + "\n" +
                str(record.get("related_reason") or ""))
            if (target == "UNKNOWN" or
                    not exact_target_is_named(target, related_text)):
                reasons.append(f"UNVERIFIED_LEXICAL_BINDING:{identity}")
                continue
            if (record.get("related_judgment") != "POSSIBLE_BUG" or
                    normalized_text(record.get("related_safe_assumption"))):
                reasons.append(f"NON_BUG_OR_SAFE_ATTRIBUTION:{identity}")
                continue
            related_location = canonical_location(
                record.get("related_source_location"))
            related_property = normalized_property(
                record.get("related_security_property"))
            if related_location is None or not related_property:
                reasons.append(f"INVALID_RELATED_IDENTITY:{identity}")
                continue
            # Free-text property labels cannot establish semantic
            # independence (for example, "bounded read" versus "read remains
            # within bounds").  The same pinned source location therefore
            # blocks the candidate regardless of the model's property label.
            if related_location == candidate_location:
                reasons.append(f"SAME_SOURCE_LOCATION:{identity}")
        if reasons:
            blocked[candidate_id] = reasons
        else:
            eligible.append(candidate_id)
    return eligible, blocked


async def run_prepared_hp_analysis(*, work: PreparedHPFunction,
                                   qualification: Any,
                                   analysis_pipeline: Any,
                                   assertion_pipeline: Any,
                                   worker_id: str,
                                   provider_free_fixture: bool = False,
                                   context_build_command: list[str] | None = None,
                                   context_source_hashes: dict[str, str] | None = None,
                                   context_build_environment: dict[str, str] | None = None,
                                   context_process_envelope: Any | None = None,
                                   catalog_manifest_path: Path | None = None,
                                   catalog_manifest_sha256: str | None = None,
                                   max_context_reanalyses: int = 1,
                                   bounded_nohint_hp_context: bool = False,
                                   signed_manual_third_context_round: bool = False,
                                   per_assumption_evidence_closure: bool = False,
                                   assumption_lifecycle_live_admission:
                                       dict[str, Any] | None = None
                                   ) -> dict[str, Any]:
    """Use the existing HP roles; all output remains unverified and HP-local.

    Live use requires two role-bound providers sharing the same campaign gate.
    The historical post-Worker caller waits for SP/Global settlement. A
    parallel caller must preserve shared-gate admission and join both tracks
    before global settlement; an uncertain turn blocks new shared-gate work.
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
    if ((work.selection_origin == "PROVIDER_FREE_FIXTURE" or
         work.analysis_scope.get("selection_origin") ==
         "PROVIDER_FREE_FIXTURE") and provider_free_fixture is not True):
        return _unsupported("PROVIDER_FREE_SELECTION_CANNOT_RUN_LIVE")
    bounded_catalog = (bounded_nohint_hp_context is True and
                       work.selection_origin in {
                           "FBV2_SP_SELECTION",
                           "SIGNED_AUTO_HP_AFTER_LOCAL_SP_EXHAUSTION",
                           "PARALLEL_HP_PRE_SP_SELECTION_V1"})
    manual_catalog = work.selection_origin == "SIGNED_MANUAL_HP_CONTROL"
    if (type(bounded_nohint_hp_context) is not bool or
            type(signed_manual_third_context_round) is not bool or
            type(per_assumption_evidence_closure) is not bool or
            (bounded_nohint_hp_context and not bounded_catalog) or
            (signed_manual_third_context_round and
             not (manual_catalog and max_context_reanalyses == 3)) or
            type(max_context_reanalyses) is not int or
            max_context_reanalyses not in (1, 2, 3) or
            (max_context_reanalyses > 1 and
             (not (manual_catalog or bounded_catalog) or
              catalog_manifest_path is None or
              catalog_manifest_sha256 is None)) or
            (max_context_reanalyses == 3 and not bounded_catalog and
             not signed_manual_third_context_round)):
        return _unsupported("HP_CONTEXT_ROUND_CONTRACT_INVALID")
    if per_assumption_evidence_closure and not provider_free_fixture:
        if assumption_lifecycle_live_admission is None:
            return _unsupported(
                "HP_ASSUMPTION_LIFECYCLE_LIVE_APPROVAL_REQUIRED")
        if not _assumption_lifecycle_live_admission_ok(
                assumption_lifecycle_live_admission, work=work,
                qualification=qualification,
                analysis_pipeline=analysis_pipeline,
                assertion_pipeline=assertion_pipeline,
                max_context_reanalyses=max_context_reanalyses,
                catalog_manifest_sha256=catalog_manifest_sha256):
            return _unsupported(
                "HP_ASSUMPTION_LIFECYCLE_LIVE_ADMISSION_INVALID")
    elif assumption_lifecycle_live_admission is not None:
        return _unsupported("HP_ASSUMPTION_LIFECYCLE_LIVE_ADMISSION_INVALID")
    if not provider_free_fixture:
        first = analysis_pipeline.provider
        second = assertion_pipeline.provider
        if (type(first) is not CampaignLedgeredProvider or
                type(second) is not CampaignLedgeredProvider or
                first.gate is not second.gate):
            return _unsupported("HP_SHARED_MODEL_LEDGER_REQUIRED")
        if (context_build_command is not None and
                (context_build_environment is None or
                 context_process_envelope is None)):
            return _unsupported("HP_CONTEXT_PROCESS_ACCOUNTING_REQUIRED")
    common = {"function_id": work.function_id,
              "direction_id": work.direction_id,
              "sp_global_effect": "UNCHANGED",
              "security_gate_credit": "NOT_CREDITED"}
    context: list[dict[str, str]] = []
    context_records: list[dict[str, Any]] = []
    context_pins: dict[Path, str] = {}
    seen_requests: set[tuple[str, str]] = set()
    attempted_requests: set[tuple[str, str]] = set()
    preload_context_incomplete = False
    static_path: dict[str, Any] | None = None
    static_path_status: str | None = None
    analysis_scope = work.analysis_scope
    reanalyses = 0
    analysis_turns: list[dict[str, str]] = []
    assertion_turn: dict[str, str] | None = None
    assumption_lifecycle_history: list[dict[str, Any]] = []
    assumption_lifecycle_ledger: dict[str, dict[str, Any]] = {}
    candidate_context_closure_observation: dict[str, Any] | None = None

    lifecycle_contract = {
        "kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5",
        "stable_identity": (
            "function_id+canonical_pinned_source_file+line+"
            "normalized_security_property+normalized_text"),
        "candidate_lineage_identity": (
            "function_id+canonical_pinned_source_file+line+normalized_text"),
        "terminal_anchor_tombstone": (
            "function_id+canonical_pinned_source_file+line; empty-ID candidates "
            "at an already-terminal, current-round-terminal, or omitted-prior "
            "anchor are rejected because model-authored property and assumption "
            "prose are not authoritative identities"),
        "terminal_anchor_settlement": (
            "after all prior/current/omitted rows are accounted, no "
            "VALIDATED_SAFE candidate ID may coexist at one canonical anchor "
            "with another candidate ID in a terminal non-SAFE disposition"),
        "omitted_prior_candidate": "INCOMPLETE",
        "validated_safe_requires": [
            "CURRENT_EXPLICIT_SAFE_JUDGMENT",
            "CURRENT_TOP_LEVEL_SAFE_ASSUMPTION",
            "EXACT_PINNED_SOURCE_FILE_LINE_QUOTE",
            "EXACT_SOURCE_LOCATION_AND_SECURITY_PROPERTY",
            "NO_UNRESOLVED_CANDIDATE_CONTEXT",
            "HOST_BOUND_INDEXED_REQUEST_ATTRIBUTION",
        ],
        "terminal_dispositions": [
            "VALIDATED_SAFE", "RECLASSIFIED_VALIDATION", "INVALIDATED",
            "INCOMPLETE", "ASSERTION_INELIGIBLE",
        ],
    }

    def current_lifecycle_contract() -> dict[str, Any]:
        evidence = [{
            "evidence_id": "SELECTED_SOURCE",
            "kind": "SELECTED_FUNCTION_SOURCE",
            "target": work.function_name,
            "source_location": (
                f"{work.source_file}:{work.source_start_line}-"
                f"{work.source_end_line}"),
            "source_sha256": work.source_file_sha256,
        }]
        for index, item in enumerate(context):
            source_file = item.get("source_file")
            source_sha = (context_pins.get(Path(source_file))
                          if source_file else None)
            target = item.get("target") or item.get("function_name") or "UNKNOWN"
            location = item.get("source_location") or str(source_file or "UNKNOWN")
            evidence.append({
                "evidence_id": stable_id(
                    "context", index, target, location, source_sha),
                "kind": item.get("evidence_kind", "PINNED_CONTEXT_SOURCE"),
                "target": target,
                "source_location": location,
                "source_sha256": source_sha,
            })
        return {**lifecycle_contract, "available_evidence": evidence}

    def record_assumption_lifecycle(analysis: Any, round_index: int) -> None:
        if not per_assumption_evidence_closure:
            return
        for row in getattr(analysis, "safe_assumption_lifecycle", []):
            assumption_id = row.get("assumption_id")
            if isinstance(assumption_id, str) and assumption_id:
                assumption_lifecycle_ledger[assumption_id] = dict(row)
            assumption_lifecycle_history.append({
                **row,
                "round": round_index,
                "assertion_eligible": (
                    row.get("disposition") == "VALIDATED_SAFE" and
                    not row.get("required_context")),
            })

    def prior_tracked_assumptions() -> list[dict[str, Any]]:
        if not per_assumption_evidence_closure:
            return []
        # Keep every issued ID in the run ledger.  Terminal rows are passed
        # back so the product validator can enforce monotonicity; unresolved
        # INCOMPLETE rows cannot disappear into a later SAFE=0 snapshot.
        return [dict(row) for row in assumption_lifecycle_ledger.values()]

    def with_context(row: dict[str, Any]) -> dict[str, Any]:
        return {**row, "context_request_count": len(context_records),
                "context_provided_count": len(context),
                "context_reanalysis_count": reanalyses,
                "context_requests": list(context_records),
                **({"assumption_lifecycle_contract": current_lifecycle_contract(),
                    "assumption_lifecycle_history": list(
                        assumption_lifecycle_history),
                    "assumption_lifecycle_ledger": [
                        dict(item) for item in
                        assumption_lifecycle_ledger.values()]}
                   if per_assumption_evidence_closure else {}),
                **({"static_call_path": static_path}
                   if static_path is not None else {}),
                **({"candidate_context_closure":
                        candidate_context_closure_observation}
                   if candidate_context_closure_observation is not None else {}),
                "context_evidence": [{
                    "target": item.get("target"),
                    "source_file": item.get("source_file"),
                    "source_location": item.get("source_location"),
                    "source_file_sha256": context_pins.get(
                        Path(item["source_file"]))
                    if item.get("source_file") else None,
                } for item in context]}

    def unresolved_request_record(
        request: Any, round_index: int, status: str
    ) -> dict[str, Any]:
        """Preserve Host-verified hypothesis attribution at every stop edge."""
        get = (request.get if isinstance(request, dict)
               else lambda key, default=None: getattr(request, key, default))
        record = {
            "target": get("target"),
            "request_type": get("request_type"),
            "request_reason": get("reason"),
            "expected_information": get("expected_information"),
            "round": round_index,
            "status": status,
        }
        if get("hypothesis_index") is not None:
            record.update({
                "hypothesis_index": get("hypothesis_index"),
                "attribution_verified": get(
                    "attribution_verified", False) is True,
                "related_hypothesis": get("related_hypothesis", ""),
                "related_judgment": get("related_judgment", ""),
                "related_reason": get("related_reason", ""),
                "related_source_location": get(
                    "related_source_location", ""),
                "related_security_property": get(
                    "related_security_property", ""),
                "related_safe_assumption": get(
                    "related_safe_assumption", ""),
            })
        return record

    if not _prepared_pins_ok(work, qualification):
        return {**common, "status": "HP_UNSUPPORTED",
                "reason": "PREPARED_SOURCE_OR_QUALIFICATION_CHANGED"}
    if catalog_manifest_path is not None or catalog_manifest_sha256 is not None:
        if (not (manual_catalog or bounded_catalog) or
                catalog_manifest_path is None or
                catalog_manifest_sha256 is None):
            return {**common, "status": "HP_UNSUPPORTED",
                    "reason": "PINNED_CONTEXT_CATALOG_UNAVAILABLE"}
        try:
            if manual_catalog:
                static_path, path_pins = _pinned_static_call_path(
                    work, qualification, catalog_manifest_path,
                    catalog_manifest_sha256)
            else:
                _, _, _, path_pins = _pinned_context_graph(
                    work, qualification, catalog_manifest_path,
                    catalog_manifest_sha256)
                try:
                    # The automatic SP choice may have a proven direct path
                    # from the Harness, but may also be reached only through
                    # callbacks. Supply the former without claiming runtime
                    # reachability or rejecting the latter.
                    static_path, static_pins = _pinned_static_call_path(
                        work, qualification, catalog_manifest_path,
                        catalog_manifest_sha256)
                except ValueError as exc:
                    if str(exc) == "HP target has no bounded pinned direct-call path":
                        static_path_status = "NO_PINNED_DIRECT_PATH"
                    elif str(exc) == "HP static callsite is absent":
                        # A compiler edge can originate at a macro invocation.
                        # The optional source-level path is then unproven, but
                        # the separately pinned function/catalog remain usable.
                        static_path_status = "SOURCE_CALLSITE_UNPROVEN"
                    else:
                        raise
                else:
                    path_pins.update(static_pins)
        except (OSError, ValueError, KeyError, TypeError, UnicodeError):
            return {**common, "status": "HP_UNSUPPORTED",
                    "reason": ("PINNED_STATIC_CALL_PATH_UNAVAILABLE"
                               if manual_catalog else
                               "PINNED_CONTEXT_CATALOG_UNAVAILABLE")}
        context_pins.update(path_pins)
        if manual_catalog:
            analysis_scope = {**work.analysis_scope,
                              "static_call_path": static_path}
        else:
            analysis_scope = {**work.analysis_scope,
                              "context_catalog_evidence":
                              "PINNED_CATALOG_SOURCE_ONLY",
                              "runtime_reachability":
                              "UNPROVEN_FOR_ANY_INPUT"}
            if static_path is not None:
                analysis_scope["static_call_path"] = static_path
            elif static_path_status is not None:
                analysis_scope["static_call_path_status"] = static_path_status
        if not _context_pins_ok(context_pins):
            return {**common, "status": "HP_UNSUPPORTED",
                    "reason": "PINNED_CONTEXT_CATALOG_UNAVAILABLE"}
    phase = "FUNCTION_ANALYSIS"
    try:
        harness_path = Path(work.harness_path)
        harness_source = harness_path.read_text(encoding="utf-8")
        if (hashlib.sha256(harness_source.encode("utf-8")).hexdigest() !=
                work.harness_sha256 or not _prepared_pins_ok(work, qualification)):
            return {**common, "status": "HP_UNSUPPORTED",
                    "reason": "PREPARED_SOURCE_OR_QUALIFICATION_CHANGED"}
        if ((bounded_catalog or manual_catalog) and static_path is not None and
                static_path["edges"]):
            # Build a bounded generic evidence bundle from the issued graph,
            # selected source, and already-qualified compile command. It never
            # names a target-specific helper or adds a SAFE/runtime claim.
            from vulnerabilityanalysis.models import ContextRequest

            plan, build_rows, plan_audit = _pinned_initial_context_plan(
                work, qualification, catalog_manifest_path,
                catalog_manifest_sha256, static_path,
                context_build_command)
            evidence_kind = {
                (row["target"], row["request_type"]): row["evidence_kind"]
                for row in plan
            }
            required_path = {
                (row["target"], row["request_type"]) for row in plan
                if row["evidence_kind"] == "PINNED_STATIC_PATH_FUNCTION"
            }
            context_records.extend(plan_audit)
            preload_context_incomplete = (
                preload_context_incomplete or any(
                    row.get("evidence_kind") ==
                        "PINNED_STATIC_PATH_FUNCTION" and
                    row.get("status") != "FETCHED"
                    for row in plan_audit))
            for first in range(0, len(plan), 2):
                chunk = plan[first:first + 2]
                requests = [ContextRequest(
                    requesting_function=work.function_id,
                    target=row["target"],
                    request_type=row["request_type"],
                    reason=row["reason"],
                    expected_information=row["expected_information"])
                    for row in chunk]
                fetched, records, fetched_pins = _bounded_context(
                    work, requests, qualification,
                    context_build_command=context_build_command,
                    context_source_hashes=context_source_hashes,
                    context_build_environment=context_build_environment,
                    context_process_envelope=context_process_envelope,
                    catalog_manifest_path=catalog_manifest_path,
                    catalog_manifest_sha256=catalog_manifest_sha256,
                    enforce_manifest_source_pins=True,
                    prior_context=list(context),
                    seen_requests=seen_requests,
                    attempted_requests=attempted_requests, round_index=-1)
                for row in records:
                    row["evidence_kind"] = evidence_kind.get(
                        (row.get("target"), row.get("request_type")))
                context.extend(fetched)
                context_records.extend(records)
                context_pins.update(fetched_pins)
                preload_context_incomplete = (
                    preload_context_incomplete or any(
                        (row.get("target"), row.get("request_type")) in
                            required_path and row.get("status") != "FETCHED"
                        for row in records))
            for row in build_rows:
                context.append(row)
                context_records.append({
                    "target": row["target"],
                    "request_type": row["request_type"],
                    "round": -1,
                    "status": "FETCHED",
                    "provided_count": 1,
                    "evidence_kind": row["evidence_kind"],
                    "build_command_sha256": row["build_command_sha256"],
                })
                # A later model MACRO request for an already supplied active
                # build definition must not trigger an unpinned new lookup.
                seen_requests.add((row["target"], "MACRO"))
                seen_requests.add((row["target"], "BUILD_MACRO"))
            if not _context_pins_ok(context_pins):
                return with_context({**common, "status": "HP_UNSUPPORTED",
                                     "reason": "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"})
        analysis = await analysis_pipeline.analyze_function(
            work.function_id, work.function_name, work.source_file,
            work.source, context=list(context), harness_source=harness_source,
            harness_source_path=harness_path,
            analysis_scope=analysis_scope,
            source_start_line=work.source_start_line,
            assumption_lifecycle_contract=(
                current_lifecycle_contract()
                if per_assumption_evidence_closure else None),
            prior_safe_assumptions=[])
        record_assumption_lifecycle(analysis, 0)
        if not provider_free_fixture:
            provider = analysis_pipeline.provider
            turn = _verified_hp_turn(provider, "function_analysis")
            if turn is None:
                return {**common, "status": "INCOMPLETE_HP_MODEL_PROVENANCE",
                        "phase": phase}
            analysis_turns.append(turn)
        if not _prepared_pins_ok(work, qualification):
            return with_context({**common, "status": "HP_UNSUPPORTED",
                                 "reason": "PREPARED_SOURCE_OR_QUALIFICATION_CHANGED"})
        if not _context_pins_ok(context_pins):
            return with_context({**common, "status": "HP_UNSUPPORTED",
                                 "reason": "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"})
        if analysis.direction_id not in (None, work.direction_id):
            return with_context({**common, "status": "INCOMPLETE_HP_RESULT_MISMATCH"})
        analysis.direction_id = work.direction_id
        for round_index in range(max_context_reanalyses + 1):
            requests = list(analysis.context_requests)
            omitted = list(getattr(analysis_pipeline,
                                   "last_context_request_omitted", []))
            if round_index == max_context_reanalyses:
                context_records.extend(unresolved_request_record(
                    request, round_index, "SKIPPED_CONTEXT_ROUND_LIMIT"
                ) for request in requests)
                context_records.extend(unresolved_request_record(
                    row, round_index, "SKIPPED_CONTEXT_ROUND_LIMIT"
                ) for row in omitted)
                break
            if not requests and not omitted:
                break
            remaining = None
            if not provider_free_fixture:
                gate = analysis_pipeline.provider.gate
                remaining = (None if gate.physical_max is None else
                             gate.physical_max - gate.snapshot()["physical"])
            if remaining is not None and remaining < 2:
                context_records.extend(unresolved_request_record(
                    request, round_index, "SKIPPED_LLM_BUDGET"
                ) for request in requests)
                context_records.extend(unresolved_request_record(
                    row, round_index, "SKIPPED_LLM_BUDGET"
                ) for row in omitted)
                break
            if (not _prepared_pins_ok(work, qualification) or
                    not _context_pins_ok(context_pins)):
                return with_context({**common, "status": "HP_UNSUPPORTED",
                                     "reason": "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"})
            fetched, records, fetched_pins = _bounded_context(
                work, requests, qualification,
                context_build_command=context_build_command,
                context_source_hashes=context_source_hashes,
                context_build_environment=context_build_environment,
                context_process_envelope=context_process_envelope,
                catalog_manifest_path=catalog_manifest_path,
                catalog_manifest_sha256=catalog_manifest_sha256,
                enforce_manifest_source_pins=bounded_catalog,
                prior_context=context,
                seen_requests=seen_requests,
                attempted_requests=attempted_requests,
                round_index=round_index)
            context_records.extend(records)
            context_records.extend(unresolved_request_record(
                row, round_index, "SKIPPED_PER_TURN_LIMIT"
            ) for row in omitted)
            context_pins.update(fetched_pins)
            # A model may ask again for context already present in its first
            # prompt. Give it the existing evidence once more rather than
            # treating the duplicate as a terminal lack of context.
            repeat_with_existing = (
                (bounded_catalog or manual_catalog) and context and requests and
                records and all(row["status"] == "ALREADY_REQUESTED"
                                for row in records))
            if not fetched and not repeat_with_existing:
                break
            context.extend(fetched)
            if (not _prepared_pins_ok(work, qualification) or
                    not _context_pins_ok(context_pins)):
                return with_context({**common, "status": "HP_UNSUPPORTED",
                                     "reason": "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"})
            prior_assumptions = prior_tracked_assumptions()
            analysis = await analysis_pipeline.analyze_function(
                work.function_id, work.function_name, work.source_file,
                work.source, context=list(context), harness_source=harness_source,
                harness_source_path=harness_path,
                analysis_scope=analysis_scope,
                source_start_line=work.source_start_line,
                assumption_lifecycle_contract=(
                    current_lifecycle_contract()
                    if per_assumption_evidence_closure else None),
                prior_safe_assumptions=prior_assumptions)
            reanalyses += 1
            record_assumption_lifecycle(analysis, reanalyses)
            if not provider_free_fixture:
                provider = analysis_pipeline.provider
                turn = _verified_hp_turn(provider, "function_analysis")
                if turn is None or turn["request_id"] in {
                        prior["request_id"] for prior in analysis_turns}:
                    return with_context({**common,
                        "status": "INCOMPLETE_HP_MODEL_PROVENANCE",
                        "phase": "FUNCTION_ANALYSIS_CONTEXT"})
                analysis_turns.append(turn)
            if analysis.direction_id not in (None, work.direction_id):
                return with_context({**common,
                    "status": "INCOMPLETE_HP_RESULT_MISMATCH"})
            analysis.direction_id = work.direction_id
            if (not _prepared_pins_ok(work, qualification) or
                    not _context_pins_ok(context_pins)):
                return with_context({**common, "status": "HP_UNSUPPORTED",
                                     "reason": "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"})
        if context and (not _prepared_pins_ok(work, qualification) or
                        not _context_pins_ok(context_pins)):
            return with_context({**common, "status": "HP_UNSUPPORTED",
                                 "reason": "CONTEXT_SOURCE_OR_QUALIFICATION_CHANGED"})
        classified = classify_hp_analysis(work, analysis)
        if per_assumption_evidence_closure:
            unresolved_assumptions = [
                row for row in assumption_lifecycle_ledger.values()
                if row.get("disposition") in {
                    "PROPOSED", "NEEDS_CONTEXT", "INCOMPLETE"}]
            if unresolved_assumptions:
                return with_context({
                    **common,
                    "status": "INCOMPLETE_HP_ASSUMPTION_EVIDENCE",
                    "reason": "ASSUMPTION_EVIDENCE_NOT_CLOSED",
                    "assertion_opportunity": "NONE",
                    "safe_selection_observation": classified.get(
                        "safe_selection_observation"),
                    "unresolved_assumption_ids": [
                        row.get("assumption_id") for row in unresolved_assumptions],
                })
        # A completed model response is not a completed SAFE-yield
        # measurement when that same response still requests material source
        # and the host declines it solely because the signed context/model
        # budget ended.  Calling this NO_SAFE_ASSUMPTION would conflate a
        # source-backed negative judgment with an administratively truncated
        # analysis.  Preserve the model's empty SAFE list, but settle the item
        # as incomplete so a caller cannot count it as measured SAFE=0.
        context_stop = _last_unresolved_context_status(context_records)
        if context_stop is not None and per_assumption_evidence_closure:
            eligible_ids, blocked_ids = _candidate_scoped_context_closure(
                list(assumption_lifecycle_ledger.values()), context_records,
                selected_source_file=work.source_file)
            candidate_context_closure_observation = {
                "policy": "HP_HOST_BOUND_INDEXED_REQUEST_ATTRIBUTION_V2",
                "unresolved_context_count": len(
                    _unresolved_context_records(context_records)),
                "eligible_assumption_ids": list(eligible_ids),
                "blocked_assumption_ids": dict(blocked_ids),
            }
            if eligible_ids:
                eligible_rows = [
                    row for row in assumption_lifecycle_ledger.values()
                    if row.get("assumption_id") in set(eligible_ids)
                ]
                eligible_assumptions = {
                    row.get("safe_assumption") for row in eligible_rows
                    if isinstance(row.get("safe_assumption"), str)
                }
                filtered_assumptions = [
                    assumption for assumption in analysis.safe_assumptions
                    if assumption in eligible_assumptions
                ]
                if filtered_assumptions:
                    eligible_identity = {
                        (" ".join(str(row.get("safe_assumption", "")).split()),
                         " ".join(str(row.get("source_location", "")).split()),
                         " ".join(str(row.get("security_property", "")).split()))
                        for row in eligible_rows
                    }
                    filtered_evaluations = [
                        row for row in analysis.hypothesis_evaluations
                        if (" ".join(str(row.get("safe_assumption", "")).split()),
                            " ".join(str(row.get("source_location", "")).split()),
                            " ".join(str(row.get("security_property", "")).split()))
                        in eligible_identity
                    ]
                    analysis = replace(
                        analysis,
                        safe_assumptions=filtered_assumptions,
                        safe_assumption_lifecycle=[
                            dict(row) for row in eligible_rows],
                        hypothesis_evaluations=filtered_evaluations)
                    classified = classify_hp_analysis(work, analysis)
                    if classified["status"] == "SAFE_PROPOSED_UNVERIFIED":
                        context_stop = None
        if (context_stop is not None and
                (per_assumption_evidence_closure or
                 classified["status"] == "NO_SAFE_ASSUMPTION")):
            reason = {
                "SKIPPED_CONTEXT_ROUND_LIMIT": "CONTEXT_ROUND_LIMIT",
                "SKIPPED_LLM_BUDGET": "MODEL_CALL_BUDGET_RESERVED",
                "SKIPPED_PER_TURN_LIMIT": "CONTEXT_PER_TURN_LIMIT",
            }.get(context_stop, "CONTEXT_EVIDENCE_UNAVAILABLE")
            return with_context({
                **common,
                "status": "INCOMPLETE_HP_CONTEXT",
                "reason": reason,
                "assertion_opportunity": "NONE",
                "safe_selection_observation": classified.get(
                    "safe_selection_observation"),
            })
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
            assertion_turn = _verified_hp_turn(provider, "assertion_generator")
            if (assertion_turn is None or
                    assertion_turn["request_id"] in {
                        prior["request_id"] for prior in analysis_turns}):
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
        # Preserve the exact positional SAFE list seen by Assertion Generator.
        # Candidate-scoped closure may filter the final Function Analysis
        # snapshot, so replaying raw safe_assumptions later can shift safe_id
        # onto a blocked candidate.  This is an unverified handoff artifact,
        # not a new SAFE claim; the live verifier rebinds every entry to the
        # raw Function Analysis evidence before any physical execution.
        assertion_input_safes = list(analysis.safe_assumptions)
        proposed = sum(row.status == "PROPOSED" for row in assertions)
        dispositions = list(assertion_pipeline.last_assertion_dispositions)
        return with_context({**common,
                             "status": ("ASSERTIONS_PROPOSED_UNVERIFIED" if
                                        assertions else "NO_ASSERTION_PROPOSAL"),
                             "hp_model_provenance": (None if
                                 provider_free_fixture else {
                                     "function_analysis_turns": analysis_turns,
                                     "assertion_generator_turn": assertion_turn}),
                             "proposal_origin": ("PROVIDER_FREE_FIXTURE" if
                                 provider_free_fixture else
                                 "VERIFIED_CAMPAIGN_MODEL"),
                             "safe_selection_observation": classified.get(
                                 "safe_selection_observation"),
                             "safe_assumption_count": len(analysis.safe_assumptions),
                             "assertion_input_safe_assumptions":
                                 assertion_input_safes,
                             "assertion_input_safe_assumptions_sha256":
                                 hashlib.sha256(canonical(
                                     assertion_input_safes)).hexdigest(),
                             "assertion_count": len(assertions),
                             "proposed_assertion_count": proposed,
                             "assertion_dispositions": dispositions,
                             "assertion_proposals": proposal_rows,
                             "assertion_proposals_sha256": hashlib.sha256(
                                 canonical(proposal_rows)).hexdigest(),
                             "prepared_work_sha256": hashlib.sha256(
                                 canonical(asdict(work))).hexdigest(),
                             "assertion_execution": "NOT_RUN"})
    except Exception as exc:
        return with_context({**classify_hp_analysis(work, error=exc),
                             "phase": phase})
