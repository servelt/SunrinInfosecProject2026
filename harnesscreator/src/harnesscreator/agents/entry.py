from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from ..analysis.graph import GraphStore, _code_only
from ..analysis.declarations import DeclarationIndex, SourceDeclaration
from ..llm.base import LLMProvider, close_llm_session
from ..models import (
    AnalysisBundle,
    AnalysisDisposition,
    EntryCandidate,
    EntryRecord,
    EntrySiteKind,
    Evidence,
    FunctionMetadata,
    Verdict,
    as_json,
    evidence_from_dict,
    stable_id,
    unique_strings,
)
from ..tracing import TraceCallback, emit_trace
from ..analysis.input_apis import SOURCE_APIS
from .common import (
    concurrent_map,
    function_payload,
    function_ref,
    is_non_product_build_target,
    object_list,
    string_list,
)


_NON_PRODUCT_PATH_PARTS = {
    "bench", "benchmark", "benchmarks", "fuzz", "fuzzer", "fuzzers",
    "fuzzing", "test", "tests", "testing",
}

_INTERNAL_RUNTIME_API_PREFIXES = (
    "lua_", "lual_", "py_", "rb_", "jcall_", "jni_",
)

_NON_INGRESS_API_MARKERS = {
    "append", "callback", "dispatch", "emit", "encode", "format", "free",
    "getfield", "getglobal", "getmetatable", "gettop", "isfunction", "isinteger",
    "isstring", "istable", "next", "push", "rawget", "ref", "send", "serialize",
    "setfield", "toboolean", "tointeger", "tolstring", "tonumber", "tostring",
    "touserdata", "type", "write",
}

_INGRESS_NAME_PATTERN = re.compile(
    r"(?:^|_)(?:dequeue|fetch|fread|fgets|getdelim|getenv|getline|input|loadfile|"
    r"mq_receive|msgrcv|pop_message|pread|read|readfile|readlink|receive|recv|recvfrom|"
    r"recvmsg|scan|ssl_read|wsarecv)(?:_|$)",
    re.IGNORECASE,
)

_CALLBACK_REGISTRATION_PATTERN = re.compile(
    r"(?:^|_)(?:add|async|install|on|register|set|start|subscribe).*(?:callback|handler|"
    r"message|read|receive|request)|(?:callback|handler).*(?:add|register|set)(?:_|$)",
    re.IGNORECASE,
)

_CALLBACK_PAYLOAD_PATTERN = re.compile(
    r"\b(?:body|buf|buffer|bytes|data|input|message|packet|payload|request)\w*\b",
    re.IGNORECASE,
)

_PROCESS_ENTRY_NAMES = {"main", "wmain", "winmain", "wwinmain"}
_SOURCE_APIS_CASEFOLD = {name.casefold(): channel for name, channel in SOURCE_APIS.items()}

# These calls can be prerequisites for an input path, but they do not copy an
# externally supplied data value into the program.  In particular, ``accept``
# creates a connected resource; the peer's request data enters later through a
# receive/read primitive.  Keep this deny-list in addition to the positive
# source catalog so a recall-oriented model cannot redefine control events as
# Input Entries.
_NON_DATA_BOUNDARY_APIS = {
    "accept",
    "accept4",
    "bind",
    "close",
    "connect",
    "epoll_wait",
    "eventfd",
    "kevent",
    "listen",
    "poll",
    "select",
    "socket",
}

# Preserve the causal walk: one newly opened function determines the next
# request.  A batch hides which source changed the Entry verdict.
MAX_TARGETED_CONTEXT_ADDITIONS_PER_ROUND = 1


ENTRY_GENERATOR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["candidates", "inspected_function_ids"],
    "properties": {
        "inspected_function_ids": {
            "type": "array", "items": {"type": "string"},
        },
        "candidates": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "function_id", "source_api", "line", "site_kind", "first_acquisition",
                    "boundary_subject", "channel_hint", "rationale", "confidence"
                ],
                "properties": {
                    "function_id": {"type": "string"},
                    "source_api": {"type": "string"},
                    "line": {"type": ["integer", "null"]},
                    "site_kind": {
                        "type": "string",
                        "enum": [item.value for item in EntrySiteKind],
                    },
                    "first_acquisition": {"type": "boolean"},
                    "boundary_subject": {"type": "string"},
                    "channel_hint": {"type": "string"},
                    "rationale": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                },
            },
        }
    },
}


SETTLE_FOLLOW_UP = (
    "Your last answer was UNRESOLVED and requested no source. Analyse once more. Name the one fact "
    "that decides whether this site is the first external data acquisition and request, from "
    "available_context_functions, the function or declaration that shows it. If no listed source can "
    "show it, decide VERIFIED or REJECTED on the evidence already shown. Address family, transport, "
    "ACLs, authentication, attacker control and configuration are not reasons for UNRESOLVED."
)

ENTRY_VERIFIER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "status", "channel_kind", "attacker_control", "provenance_path", "consumer_hints",
        "evidence", "unknowns", "rationale", "first_acquisition_confirmed",
        "context_complete", "requested_function_ids",
        "requested_declaration_name", "list_declarations", "declaration_name_filter",
    ],
    "properties": {
        "status": {"type": "string", "enum": ["VERIFIED", "REJECTED", "UNRESOLVED"]},
        "channel_kind": {"type": "string"},
        "attacker_control": {"type": "string", "enum": ["full", "partial", "none", "unknown"]},
        "provenance_path": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["function_id", "relation"],
                "properties": {"function_id": {"type": "string"}, "relation": {"type": "string"}},
            },
        },
        "consumer_hints": {"type": "array", "items": {"type": "string"}},
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind", "function_id", "file", "line", "detail"],
                "properties": {
                    "kind": {"type": "string"}, "function_id": {"type": "string"},
                    "file": {"type": "string"}, "line": {"type": ["integer", "null"]},
                    "detail": {"type": "string"},
                },
            },
        },
        "unknowns": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
        "first_acquisition_confirmed": {"type": "boolean"},
        "context_complete": {"type": "boolean"},
        "requested_function_ids": {"type": "array", "items": {"type": "string"}},
        "requested_declaration_name": {"type": "string"},
        "list_declarations": {"type": "boolean"},
        "declaration_name_filter": {"type": "string"},
    },
}


class EntryGeneratorAgent:
    def __init__(
        self,
        llm: LLMProvider,
        *,
        chunk_size: int = 32,
        max_batch_chars: int = 120_000,
        target_names: list[str] | None = None,
        preferred_source_files: set[str] | None = None,
        configured_target_files: set[str] | None = None,
        trace: TraceCallback | None = None,
        scope_function_ids: set[str] | None = None,
    ):
        self.llm = llm
        # Delta scans: only these functions are inspected (None = every product function).
        self.scope_function_ids = scope_function_ids
        self.chunk_size = chunk_size
        self.max_batch_chars = max_batch_chars
        self.target_names = unique_strings(
            item.strip() for item in (target_names or []) if item.strip()
        )
        self.preferred_source_files = set(preferred_source_files or ())
        self.configured_target_files = (
            set(configured_target_files)
            if configured_target_files is not None else None
        )
        self.trace = trace
        self.incomplete_functions: list[dict[str, str]] = []

    def product_function_ids(self, bundle: AnalysisBundle) -> set[str]:
        """Use a checked target closure when present, otherwise stay broad.

        Fuzz Introspector commonly indexes several executables from one source
        tree. Empty build-target metadata is unknown membership, not proof of
        exclusion: indirect calls and missing source links can hide a real
        input callback from the direct call graph. A complete configured Make
        closure can scope translation units for the requested target; headers
        without dependency metadata remain eligible.
        """

        normalized_targets = {
            _normalized_target_name(item) for item in self.target_names
            if _normalized_target_name(item)
        }
        generally_product = {
            function.function_id
            for function in bundle.functions.values()
            if _is_product_function(function, normalized_targets)
        }
        if self.configured_target_files is not None:
            # The adjacent configured Make target supplied a complete
            # source/object closure. Limit source analysis to that target;
            # runtime equivalence to a pre-existing binary remains unproven.
            return {
                function_id for function_id in generally_product
                if (bundle.functions[function_id].file
                    in self.configured_target_files
                    # A translation unit can compile definitions from header
                    # or other included files even when dependency metadata
                    # is unavailable. Only filter known C/C++ source units.
                    or PurePosixPath(bundle.functions[function_id].file).suffix.lower()
                    not in {".c", ".cc", ".cpp", ".cxx"})
            }
        if not normalized_targets:
            return generally_product
        anchors = {
            function.function_id
            for function in bundle.functions.values()
            if function.function_id in generally_product
            and any(
                _normalized_target_name(target) in normalized_targets
                for target in function.build_targets
            )
        }
        # Projects without usable build-target metadata retain the original
        # generic path instead of silently excluding their whole program.
        if not anchors:
            return generally_product

        return {
            function_id for function_id in generally_product
            if not bundle.functions[function_id].build_targets
            or any(
                _normalized_target_name(target) in normalized_targets
                for target in bundle.functions[function_id].build_targets
            )
        }

    def batches(
        self, bundle: AnalysisBundle
    ) -> list[list[tuple[FunctionMetadata, dict[str, Any]]]]:
        """Group complete functions without omitting or truncating any source.

        Batching is only a transport optimization. The model must acknowledge
        each function ID; an unacknowledged function is retried alone. An
        oversized function remains a single complete request.
        """

        product_ids = self.product_function_ids(bundle)
        batches: list[list[tuple[FunctionMetadata, dict[str, Any]]]] = []
        current: list[tuple[FunctionMetadata, dict[str, Any]]] = []
        current_chars = 0
        # DWARF may be incomplete or refer to another build. A matched source
        # is positive scheduling evidence only: no unmatched function is
        # removed from the Entry inventory.
        functions = sorted(
            bundle.function_list(),
            key=lambda item: item.file not in self.preferred_source_files,
        )
        for function in functions:
            if function.function_id not in product_ids:
                continue
            if self.scope_function_ids is not None and function.function_id not in self.scope_function_ids:
                continue
            payload = function_payload(
                function, source_limit=max(1, len(function.source) + 1),
            )
            payload_chars = len(json.dumps(payload, ensure_ascii=False))
            if current and (len(current) >= max(1, self.chunk_size)
                            or current_chars + payload_chars > max(1, self.max_batch_chars)):
                batches.append(current)
                current = []
                current_chars = 0
            current.append((function, payload))
            current_chars += payload_chars
        if current:
            batches.append(current)
        return batches

    async def run(
        self,
        bundle: AnalysisBundle,
        *,
        on_deterministic_candidates: Callable[[list[EntryCandidate]], None] | None = None,
        on_final_candidates: Callable[[list[EntryCandidate]], None] | None = None,
    ) -> list[EntryCandidate]:
        self.incomplete_functions = []
        product_ids = self.product_function_ids(bundle)
        candidates = self._deterministic_candidates(
            bundle, product_function_ids=product_ids
        )
        # These source-located candidates can be checked while the broader
        # LLM inventory continues. The callback cannot turn them VERIFIED;
        # the ordinary Entry Verifier still owns that decision.
        if on_deterministic_candidates is not None:
            on_deterministic_candidates(list(candidates))
        emit_trace(
            self.trace,
            "entry_generator",
            "deterministic_candidates",
            f"static API scan proposed {len(candidates)} candidates",
            candidates=[
                {
                    "candidate_id": item.candidate_id,
                    "function": function_ref(bundle.functions[item.function_id]),
                    "source_api": item.source_api,
                    "line": item.line,
                    "channel_hint": item.channel_hint,
                    "site_kind": str(item.site_kind),
                    "boundary_subject": item.boundary_subject,
                    "first_acquisition": item.first_acquisition,
                    "rationale": item.rationale,
                    "confidence": item.confidence,
                }
                for item in candidates
            ],
        )
        excluded_functions = [
            function_ref(function)
            for function in bundle.function_list()
            if function.function_id not in product_ids
        ]
        emit_trace(
            self.trace,
            "entry_generator",
            "function_prefilter",
            (
                f"kept {len(product_ids)} functions eligible for Entry inspection; "
                f"excluded {len(excluded_functions)} by path or different-target evidence"
            ),
            excluded_functions=excluded_functions,
        )
        batches = self.batches(bundle)

        async def analyze_batch(
            batch: list[tuple[FunctionMetadata, dict[str, Any]]]
        ) -> tuple[list[tuple[FunctionMetadata, dict[str, Any]]], dict[str, Any], str]:
            batch_functions = list({item.function_id: item for item, _ in batch}.values())
            emit_trace(
                self.trace,
                "entry_generator",
                "batch_started",
                f"inspect {len(batch_functions)} functions across {len(batch)} source excerpts",
                functions=[function_ref(item) for item in batch_functions],
                excerpt_count=len(batch),
            )
            async def ask(items: list[tuple[FunctionMetadata, dict[str, Any]]]) -> dict[str, Any]:
                return await self.llm.complete_json(
                    role="entry_generator",
                    instructions=(
                    "Inspect every supplied complete function separately and return its ID in "
                    "inspected_function_ids, including functions with no Entry. "
                    "Maximize recall only among FIRST DATA-ACQUISITION sites. An Input Entry is the exact point where "
                    "data supplied by a subject or interface outside the program first crosses into a program-owned "
                    "buffer, string, argument, object field, or other data-bearing storage. A function that merely "
                    "parses, converts, queries, dispatches, or "
                    "forwards a value already acquired by program code is NOT another Entry. Emit a candidate only "
                    "as one of: DIRECT_ACQUISITION for the concrete OS/library input call site; PROCESS_START for "
                    "main-style argv/envp acquisition; EXPORTED_API for a statically evidenced public ABI receiving "
                    "caller-owned arguments; or EXTERNAL_CALLBACK when registration evidence shows that an external "
                    "runtime invokes this function with a payload argument. A caller of a program-defined input "
                    "wrapper is not an Entry: select the wrapper's innermost external acquisition call instead. "
                    "accept/accept4, socket creation, connection setup, readiness events, status/error returns, and "
                    "resource handles are prerequisite execution state, not Input Entries. The later recv/read call "
                    "that copies request bytes is the Entry. Lua/Python/Ruby VM stack getters, parser/decoder "
                    "accessors, container/object getters, dispatch callbacks, readiness callbacks, output/write/send "
                    "APIs, and internal function-pointer callbacks are not first-acquisition sites. Dependency "
                    "certainty is not required for a concrete data input "
                    "primitive, so retain ambiguous read(fd) sites. Emit one candidate per concrete site and never "
                    "combine APIs or channels. Set first_acquisition=true only when the proposed line is that exact "
                    "crossing, and identify the external boundary_subject."
                ),
                    payload={"functions": [payload for _, payload in items]},
                    output_schema=ENTRY_GENERATOR_SCHEMA,
                )

            try:
                response = await ask(batch)
                known_ids = {function.function_id for function, _ in batch}
                reported_ids = set(string_list(response.get("inspected_function_ids")))
                if len(batch) == 1 and not reported_ids:
                    # Legacy providers may omit the acknowledgement; a
                    # successful single-function response still inspected its
                    # sole supplied function.
                    reported_ids = known_ids
                missing = [item for item in batch if item[0].function_id not in reported_ids]
                if missing:
                    recovered = list(object_list(response.get("candidates")))
                    failed: dict[str, str] = {}
                    for item in missing:
                        try:
                            retry = await ask([item])
                            recovered.extend(object_list(retry.get("candidates")))
                        except Exception as exc:
                            failed[item[0].function_id] = (
                                f"individual retry failed: {type(exc).__name__}: {exc}"
                            )
                    response = {
                        "candidates": recovered,
                        "inspected_function_ids": list(known_ids - set(failed)),
                        "_failed_functions": failed,
                    }
                return batch, response, ""
            except Exception as exc:
                # A grouped request may exceed the provider's context even
                # though each complete function fits. Retry individually;
                # failed functions stay visible as incomplete work.
                if len(batch) > 1:
                    recovered: list[dict[str, Any]] = []
                    failed: dict[str, str] = {}
                    for item in batch:
                        try:
                            retry = await ask([item])
                            recovered.extend(object_list(retry.get("candidates")))
                        except Exception as retry_exc:
                            failed[item[0].function_id] = (
                                f"grouped request failed ({type(exc).__name__}: {exc}); "
                                f"individual retry failed ({type(retry_exc).__name__}: {retry_exc})"
                            )
                    if len(failed) != len(batch):
                        return batch, {
                            "candidates": recovered,
                            "inspected_function_ids": [
                                item[0].function_id for item in batch
                                if item[0].function_id not in failed
                            ],
                            "_failed_functions": failed,
                        }, ""
                # Preserve deterministic candidates and mark every failed
                # function as uninspected; do not turn failure into no Entry.
                return batch, {"candidates": []}, f"{type(exc).__name__}: {exc}"

        async def analyzed_batches():
            concurrency = max(1, int(getattr(self.llm, "max_concurrency", 1)))
            consecutive_failed_waves = 0
            for offset in range(0, len(batches), concurrency):
                wave = batches[offset: offset + concurrency]
                wave_results = await concurrent_map(wave, analyze_batch, concurrency)
                for result in wave_results:
                    yield result
                if all(error for _batch, _response, error in wave_results):
                    consecutive_failed_waves += 1
                else:
                    consecutive_failed_waves = 0
                if consecutive_failed_waves >= 2:
                    for remaining_batch in batches[offset + concurrency:]:
                        yield (
                            remaining_batch, {"candidates": []},
                            "model infrastructure circuit opened after two failed waves",
                        )
                    return

        async for batch, response, failure in analyzed_batches():
            if failure:
                for function, _payload in batch:
                    self.incomplete_functions.append({
                        "function_id": function.function_id,
                        "name": function.name,
                        "reason": failure,
                    })
                emit_trace(
                    self.trace, "entry_generator", "function_uninspected",
                    failure, functions=[function_ref(item) for item, _ in batch],
                )
                if on_final_candidates is not None:
                    batch_ids = {function.function_id for function, _ in batch}
                    on_final_candidates(self._deduplicate_candidates(
                        [item for item in candidates if item.function_id in batch_ids], bundle,
                    ))
                continue
            known = {item.function_id: item for item, _ in batch}
            for function_id, reason in (response.get("_failed_functions") or {}).items():
                function = known.get(function_id)
                if function is not None:
                    self.incomplete_functions.append({
                        "function_id": function.function_id,
                        "name": function.name,
                        "reason": reason,
                    })
                    emit_trace(
                        self.trace, "entry_generator", "function_uninspected",
                        reason, functions=[function_ref(function)],
                    )
            accepted: list[dict[str, Any]] = []
            rejected: list[dict[str, Any]] = []
            for raw in object_list(response.get("candidates")):
                function = known.get(str(raw.get("function_id", "")))
                if not function:
                    rejected.append({"proposal": raw, "reason": "function_id was not in this batch"})
                    continue
                line = raw.get("line")
                if line is not None:
                    try:
                        line = int(line)
                    except (TypeError, ValueError):
                        line = None
                proposed_source_api = str(raw.get("source_api", "unknown"))
                proposed_line = line
                try:
                    site_kind = EntrySiteKind(str(raw.get("site_kind", "")))
                except ValueError:
                    rejected.append({"proposal": raw, "reason": "invalid or missing site_kind"})
                    continue
                if raw.get("first_acquisition") is not True:
                    rejected.append({
                        "proposal": raw,
                        "reason": "proposal was not asserted to be the first external acquisition",
                    })
                    continue
                boundary_subject = str(raw.get("boundary_subject", "")).strip()
                if not boundary_subject or boundary_subject.casefold() == "unknown":
                    rejected.append({
                        "proposal": raw,
                        "reason": "first acquisition requires an identified external boundary subject",
                    })
                    continue
                if site_kind is EntrySiteKind.DIRECT_ACQUISITION:
                    source_api, line = _canonical_candidate_site(
                        function, proposed_source_api, proposed_line
                    )
                else:
                    source_api, line = _canonical_boundary_site(
                        function, proposed_source_api, site_kind
                    )
                if _compound_source_api(proposed_source_api) and source_api == proposed_source_api:
                    rejected.append({
                        "proposal": raw,
                        "reason": "candidate combined multiple source APIs or Entry Sites",
                    })
                    continue
                if line is not None and not (
                    function.start_line <= line <= function.end_line
                ):
                    rejected.append({
                        "proposal": raw,
                        "reason": "candidate line was outside the proposed function",
                    })
                    continue
                rejection_reason = _candidate_rejection_reason(
                    bundle,
                    function,
                    source_api=source_api,
                    line=line,
                    site_kind=site_kind,
                    channel_hint=str(raw.get("channel_hint", "unknown")),
                )
                if rejection_reason:
                    rejected.append({"proposal": raw, "reason": rejection_reason})
                    continue
                evidence = Evidence(
                    kind="source",
                    function_id=function.function_id,
                    file=function.file,
                    line=line or function.start_line,
                    detail=f"candidate boundary call: {source_api}",
                )
                candidates.append(
                    EntryCandidate(
                        candidate_id=stable_id("entry-candidate", function.function_id, source_api, line),
                        function_id=function.function_id,
                        source_api=source_api,
                        line=line,
                        channel_hint=str(raw.get("channel_hint", "unknown")),
                        rationale=str(raw.get("rationale", "LLM candidate")),
                        confidence=_confidence(raw.get("confidence")),
                        evidence=[evidence],
                        site_kind=site_kind,
                        boundary_subject=boundary_subject,
                    )
                )
                accepted.append(
                    {
                        "function": function_ref(function),
                        "source_api": source_api,
                        "line": line,
                        "proposed_source_api": proposed_source_api,
                        "proposed_line": proposed_line,
                        "site_normalized": (
                            source_api != proposed_source_api or line != proposed_line
                        ),
                        "channel_hint": str(raw.get("channel_hint", "unknown")),
                        "site_kind": str(site_kind),
                        "boundary_subject": boundary_subject,
                        "first_acquisition": True,
                        "rationale": str(raw.get("rationale", "LLM candidate")),
                        "confidence": _confidence(raw.get("confidence")),
                    }
                )
            emit_trace(
                self.trace,
                "entry_generator",
                "batch_decision",
                f"accepted {len(accepted)} first-acquisition proposals; rejected {len(rejected)} proposals",
                functions=[
                    function_ref(item)
                    for item in {fn.function_id: fn for fn, _ in batch}.values()
                ],
                model_response=response,
                accepted=accepted,
                rejected=rejected,
            )
            if on_final_candidates is not None:
                batch_ids = set(known)
                on_final_candidates(self._deduplicate_candidates(
                    [item for item in candidates if item.function_id in batch_ids], bundle,
                ))
        result = self._deduplicate_candidates(candidates, bundle)
        emit_trace(
            self.trace,
            "entry_generator",
            "completed",
            f"produced {len(result)} deduplicated entry candidates",
            proposed_count=len(candidates),
            deduplicated_count=len(result),
        )
        return sorted(
            result,
            key=lambda item: (
                bundle.functions[item.function_id].file
                not in self.preferred_source_files
            ),
        )

    @staticmethod
    def _deduplicate_candidates(
        candidates: list[EntryCandidate], bundle: AnalysisBundle,
    ) -> list[EntryCandidate]:
        deduplicated: dict[tuple[str, str, int | None], EntryCandidate] = {}
        for item in candidates:
            function = bundle.functions.get(item.function_id)
            short = item.source_api.rsplit("::", 1)[-1]
            # Clang and the source indexer can report one C++ call as both a
            # qualified and an unqualified spelling (std::getline/getline).
            # Collapse only when the source line has exactly one such call.
            # Repeated calls of the same API on one line still need a column
            # in Entry identity; the current line-only model cannot separate
            # them and must not claim that it can.
            source_matches = (
                _direct_external_call_matches(function.source, short)
                if function is not None else []
            )
            matching_line_count = sum(
                function.start_line
                + function.source.count("\n", 0, match.start()) == item.line
                for match in source_matches
            ) if function is not None else 0
            api_key = (
                short.casefold() if matching_line_count == 1
                else item.source_api.casefold()
            )
            key = (item.function_id, api_key, item.line)
            if item.site_kind is EntrySiteKind.PROCESS_START:
                # argv arrives once per process.  The deterministic scan names the function's
                # first line, the model the line of `main (`; with GNU style those differ and
                # main() became two Entries.
                key = (item.function_id, "process_start", None)
            previous = deduplicated.get(key)
            if (previous is None or item.confidence > previous.confidence
                or (item.confidence == previous.confidence
                    and item.source_api.count("::")
                    > previous.source_api.count("::"))):
                deduplicated[key] = item
        return sorted(deduplicated.values(), key=lambda item: item.candidate_id)

    def _deterministic_candidates(
        self,
        bundle: AnalysisBundle,
        *,
        product_function_ids: set[str] | None = None,
    ) -> list[EntryCandidate]:
        result: list[EntryCandidate] = []
        allowed = (
            product_function_ids
            if product_function_ids is not None
            else self.product_function_ids(bundle)
        )
        for function in bundle.functions.values():
            if function.function_id not in allowed:
                continue
            process_entry = _process_entry_api(function)
            if process_entry is not None:
                result.append(
                    EntryCandidate(
                        candidate_id=stable_id(
                            "entry-candidate", function.function_id, process_entry, function.start_line
                        ),
                        function_id=function.function_id,
                        source_api=process_entry,
                        line=function.start_line,
                        channel_hint="process_start",
                        rationale="deterministic process-entry argument match",
                        confidence=0.95,
                        evidence=[Evidence(
                            kind="source",
                            function_id=function.function_id,
                            file=function.file,
                            line=function.start_line,
                            detail=f"process entry receives external {process_entry}",
                        )],
                        site_kind=EntrySiteKind.PROCESS_START,
                        boundary_subject="process launcher",
                    )
                )
            for api in function.external_calls:
                short = api.rsplit("::", 1)[-1]
                if short not in SOURCE_APIS:
                    continue
                # One function may contain several independent reads through the
                # same API.  An external_calls list is normally deduplicated, so
                # preserving only the first textual match silently merged Entry
                # Sites before the verifier ever saw them.
                textual_lines = {
                    function.start_line + function.source.count("\n", 0, match.start())
                    for match in _direct_external_call_matches(function.source, short)
                }
                # The parsed AST can locate a macro-expanded API or a
                # standard C++ input-stream member. Neither is a textual
                # global read/recv call in this function body.
                call_lines = sorted(textual_lines | {
                    int(site["line"])
                    for site in function.external_call_sites
                    if str(site.get("api", "")).rsplit("::", 1)[-1] == short
                    and site.get("provider") in {"clang-ast-c", "clang-ast-cpp"}
                    and (site.get("macro_expansion") is True
                         or site.get("standard_library_input") is True)
                    and isinstance(site.get("line"), int)
                    and function.start_line <= int(site["line"]) <= function.end_line
                })
                for line in call_lines:
                    compiler_site = _compiler_external_call_site(
                        function, api, line,
                    ) if line not in textual_lines else None
                    channel = (
                        str(compiler_site.get("channel_hint") or SOURCE_APIS[short])
                        if compiler_site else SOURCE_APIS[short]
                    )
                    evidence = Evidence(
                        kind="clang_ast_call" if compiler_site else "source",
                        function_id=function.function_id,
                        file=function.file,
                        line=line,
                        detail=(
                            f"Clang parsed input API {api}; "
                            f"spelled at {compiler_site.get('spelling_file')}:"
                            f"{compiler_site.get('spelling_line')}; "
                            f"compile command available="
                            f"{compiler_site.get('compile_command_available')}"
                            if compiler_site else f"known input-source API {api}"
                        ),
                    )
                    result.append(
                        EntryCandidate(
                            candidate_id=stable_id(
                                "entry-candidate", function.function_id, api, line
                            ),
                            function_id=function.function_id,
                            source_api=api,
                            line=line,
                            channel_hint=channel,
                            rationale=(
                                "compiler-resolved input call"
                                if compiler_site else "deterministic input-source API match"
                            ),
                            confidence=(
                                0.55 if compiler_site else
                                0.88 if short != "read" else 0.55
                            ),
                            evidence=[evidence],
                            site_kind=EntrySiteKind.DIRECT_ACQUISITION,
                            boundary_subject=_boundary_subject_for_channel(channel),
                        )
                    )
        return sorted(
            result,
            key=lambda item: (
                bundle.functions[item.function_id].file
                not in self.preferred_source_files
            ),
        )


def _compound_source_api(value: str) -> bool:
    normalized = value.casefold()
    return bool(
        re.search(r"[/|,;+]|\s+(?:and|or)\s+", normalized)
        or len(re.findall(r"[A-Za-z_]\w*\s*\(", value)) > 1
    )


def _canonical_candidate_site(
    function: FunctionMetadata,
    source_api: str,
    proposed_line: int | None,
) -> tuple[str, int | None]:
    """Resolve an LLM proposal to an actual external-call site when possible.

    Candidate generation has two producers: deterministic source matching and the
    broad LLM pass.  The latter may point at a nearby comment, blank line, or the
    function declaration.  Treating that approximate line as identity creates two
    Entries for the same call.  Canonicalization is deliberately limited to APIs
    already reported by static analysis; unknown callback-style boundaries retain
    their proposed location.
    """

    requested = source_api.rsplit("::", 1)[-1].casefold()
    matching_apis = [
        api
        for api in function.external_calls
        if api.rsplit("::", 1)[-1].casefold() == requested
    ]
    if not matching_apis:
        return source_api, proposed_line

    canonical_api = sorted(matching_apis, key=lambda item: (len(item), item))[0]
    lines = _external_call_lines(function, canonical_api)
    if not lines:
        return canonical_api, proposed_line
    if proposed_line in lines:
        return canonical_api, proposed_line
    if proposed_line is None:
        return canonical_api, lines[0]
    return canonical_api, min(lines, key=lambda item: (abs(item - proposed_line), item))


def _canonical_boundary_site(
    function: FunctionMetadata,
    source_api: str,
    site_kind: EntrySiteKind,
) -> tuple[str, int]:
    """Canonicalize function-entry boundaries independently of model wording."""

    if site_kind is EntrySiteKind.PROCESS_START:
        return _process_entry_api(function) or source_api, function.start_line
    return function.qualified_name or function.name, function.start_line


def _candidate_rejection_reason(
    bundle: AnalysisBundle,
    function: FunctionMetadata,
    *,
    source_api: str,
    line: int | None,
    site_kind: EntrySiteKind,
    channel_hint: str,
) -> str | None:
    """Enforce that a proposal denotes a first crossing, not a downstream use.

    The model is intentionally recall-oriented, but it may not redefine every
    consumer of external data as an Entry.  These checks use only static facts
    already present in the analysis bundle so they are deterministic and cheap.
    """

    if not _is_product_function(function):
        return "candidate belongs only to test, fuzz, or benchmark infrastructure"

    if site_kind is EntrySiteKind.DIRECT_ACQUISITION:
        if line is None:
            return "direct acquisition candidate has no concrete call-site line"
        actual_api = _matching_external_api(function, source_api)
        if actual_api is None:
            return "source_api is not an external call at the proposed function"
        if not _plausible_input_primitive(actual_api, channel_hint):
            return "external call does not acquire external data into program storage"
        call_lines = _external_call_lines(function, actual_api)
        if not call_lines:
            return "external-call metadata has no concrete direct acquisition call site"
        if line not in call_lines:
            return "candidate line is not the concrete external acquisition call site"
        return None

    if site_kind is EntrySiteKind.PROCESS_START:
        if _process_entry_api(function) is None:
            return "function is not a main-style process entry with external arguments"
        return None

    if site_kind is EntrySiteKind.EXPORTED_API:
        if not _is_statically_exported_api(function):
            return "public ABI ownership is not established by declaration and call graph metadata"
        return None

    if site_kind is EntrySiteKind.EXTERNAL_CALLBACK:
        if not _is_statically_external_payload_callback(bundle, function):
            return "external payload callback registration is not statically established"
        return None

    return "unsupported Entry site kind"


def _is_product_function(
    function: FunctionMetadata, selected_targets: set[str] | None = None,
) -> bool:
    lowered_name = function.name.casefold()
    if lowered_name.startswith(("llvmfuzzertestoneinput", "afl_test_one_input")):
        return False
    # A source path named test/, fuzz/, or examples/ is a scheduling hint,
    # not stronger evidence than exact membership in the selected executable.
    if selected_targets and any(
        _normalized_target_name(target) in selected_targets
        for target in function.build_targets
    ):
        return True
    normalized = function.file.replace("\\", "/")
    path_parts = {part.casefold() for part in PurePosixPath(normalized).parts}
    if path_parts & _NON_PRODUCT_PATH_PARTS:
        return False
    if function.build_targets and all(
        is_non_product_build_target(target) for target in function.build_targets
    ):
        return False
    return True


def _normalized_target_name(value: str) -> str:
    name = PurePosixPath(value.replace("\\", "/")).name.casefold()
    name = re.sub(r"\.(?:exe|out|bin)$", "", name)
    return re.sub(r"[^a-z0-9]+", "-", name).strip("-")


def _matching_external_api(function: FunctionMetadata, source_api: str) -> str | None:
    requested = source_api.rsplit("::", 1)[-1].casefold()
    matches = [
        api for api in function.external_calls
        if api.rsplit("::", 1)[-1].casefold() == requested
    ]
    return sorted(matches, key=lambda item: (len(item), item))[0] if matches else None


def _external_call_lines(function: FunctionMetadata, source_api: str) -> list[int]:
    spelling = source_api.rsplit("::", 1)[-1]
    textual = {
        function.start_line + function.source.count("\n", 0, match.start())
        for match in _direct_external_call_matches(function.source, spelling)
    }
    macro_lines = {
        int(site["line"])
        for site in function.external_call_sites
        if str(site.get("api", "")).rsplit("::", 1)[-1] == spelling
        and site.get("provider") in {"clang-ast-c", "clang-ast-cpp"}
        and (site.get("macro_expansion") is True
             or site.get("standard_library_input") is True)
        and isinstance(site.get("line"), int)
        and function.start_line <= int(site["line"]) <= function.end_line
    }
    return sorted(textual | macro_lines)


def _compiler_external_call_site(
    function: FunctionMetadata, source_api: str, line: int | None,
) -> dict[str, Any] | None:
    """Return a compiler-located macro or standard-stream acquisition site."""

    short = source_api.rsplit("::", 1)[-1]
    return next((
        site for site in function.external_call_sites
        if site.get("provider") in {"clang-ast-c", "clang-ast-cpp"}
        and (site.get("macro_expansion") is True
             or site.get("standard_library_input") is True)
        and str(site.get("api", "")).rsplit("::", 1)[-1] == short
        and site.get("line") == line
    ), None)


def _direct_external_call_matches(
    source: str,
    spelling: str,
) -> list[re.Match[str]]:
    """Exclude object/member callbacks that merely share an OS API name.

    Bootstrap parsers can conservatively report ``c->read(...)`` as an
    external call named ``read``.  The actual external acquisition is inside
    the project callback assigned to that member, so treating the invocation
    site as libc ``read`` violates the exact-first-acquisition definition.
    """

    result: list[re.Match[str]] = []
    code = _code_only(source)
    for match in re.finditer(rf"\b{re.escape(spelling)}\s*\(", code):
        prefix = code[max(0, match.start() - 64):match.start()]
        if re.search(r"(?:->|\.)\s*$", prefix):
            continue
        result.append(match)
    return result


def _plausible_input_primitive(source_api: str, channel_hint: str) -> bool:
    short = source_api.rsplit("::", 1)[-1]
    lowered = short.casefold()
    if lowered in _NON_DATA_BOUNDARY_APIS:
        return False
    if lowered in _SOURCE_APIS_CASEFOLD:
        return True
    if lowered.startswith(_INTERNAL_RUNTIME_API_PREFIXES):
        return False
    tokens = {token for token in re.split(r"[^a-z0-9]+", lowered) if token}
    if tokens & _NON_INGRESS_API_MARKERS:
        return False
    if _INGRESS_NAME_PATTERN.search(lowered):
        return True
    channel = channel_hint.casefold()
    external_channel = any(
        marker in channel
        for marker in ("network", "file", "stdin", "environment", "ipc", "rpc", "device", "database")
    )
    acquisition_verb = lowered.startswith(
        ("dequeue", "fetch", "input", "load", "pop", "read", "receive", "recv", "scan")
    )
    return external_channel and acquisition_verb


def _process_entry_api(function: FunctionMetadata) -> str | None:
    if function.name.casefold() not in _PROCESS_ENTRY_NAMES:
        return None
    signature = function.signature.casefold()
    for name in ("argv", "envp", "command_line", "argc"):
        if re.search(rf"\b{re.escape(name)}\b", signature):
            return name
    return None


def _is_statically_exported_api(function: FunctionMetadata) -> bool:
    declaration = function.declaration.strip()
    if not declaration or not function.headers or function.callers:
        return False
    combined = f"{declaration}\n{function.source[:function.source.find('{')]}".casefold()
    if re.search(r"\bstatic\b", combined):
        return False
    signature = function.signature
    open_paren = signature.find("(")
    close_paren = signature.rfind(")")
    if open_paren < 0 or close_paren <= open_paren:
        return False
    parameters = signature[open_paren + 1:close_paren].strip()
    return bool(parameters and parameters != "void")


def _is_statically_external_payload_callback(
    bundle: AnalysisBundle,
    function: FunctionMetadata,
) -> bool:
    lowered_name = function.name.casefold()
    if lowered_name.startswith(_INTERNAL_RUNTIME_API_PREFIXES):
        return False
    if not _CALLBACK_PAYLOAD_PATTERN.search(function.signature):
        return False
    reference_callers = {
        edge.caller_id
        for edge in bundle.edges
        if edge.callee_id == function.function_id and edge.kind == "function_reference"
    }
    for caller_id in reference_callers:
        caller = bundle.functions.get(caller_id)
        if caller is None or not _is_product_function(caller):
            continue
        if any(
            _CALLBACK_REGISTRATION_PATTERN.search(api.rsplit("::", 1)[-1])
            for api in caller.external_calls
        ):
            return True
    return False


def _boundary_subject_for_channel(channel: str) -> str:
    if channel.startswith("network"):
        return "network peer"
    if channel in {"file", "filesystem", "file_or_stdin", "file_or_device", "file_or_pipe"}:
        return "filesystem or stream owner"
    if channel == "stdin":
        return "process input provider"
    if channel == "environment":
        return "process launcher environment"
    if channel == "ipc":
        return "IPC peer"
    if channel == "device":
        return "device or kernel interface"
    return "external interface owner"


class EntryVerifierAgent:

    def _descriptor_origin_requests(self, candidate: Any, context: list[Any], has_socket_origin: Any) -> list[str]:
        """The next function to open when a socket read's descriptor origin is not shown.

        The functions adjacent to a shared reading helper (readline(fd), read_buffer(fd)) seldom
        create the descriptor: it is assigned to a connection field elsewhere (tinyproxy:
        connptr->client_fd after accept() in child.c, connptr->server_fd = opensock() in
        handle_connection, connect() inside opensock).  Without that source the socket-origin rule
        downgrades the Entry to UNRESOLVED (measured 2026-11-16: all three tinyproxy socket Entries,
        each called VERIFIED by the model).  So the descriptor fields named around the read are
        searched in the whole program: first a callee of an opened assigner that creates the
        socket, then an assigner that creates it itself, then any assigner.
        """
        functions = self.graph.bundle.functions
        opened = {item.function_id for item in context}
        texts = [item.source for item in context]
        texts += [caller.source for caller in self.graph.callers(candidate.function_id)]
        fields = set(re.findall(r"(?:->|\.)\s*(\w*fd\w*)\b", "\n".join(t or "" for t in texts)))
        if not fields:
            return []
        assign = re.compile(r"(?:->|\.)\s*(?:" + "|".join(sorted(map(re.escape, fields))) + r")\s*=(?!=)")
        opened_assigners = [item.function_id for item in context if assign.search(item.source or "")]
        via_callee = [callee.function_id for fid in opened_assigners for callee in self.graph.callees(fid)
                      if callee.function_id not in opened and has_socket_origin(callee.source or "")]
        assigners = [fid for fid, fn in sorted(functions.items(), key=lambda kv: (kv[1].file, kv[1].start_line))
                     if fid not in opened and assign.search(fn.source or "")]
        assigners.sort(key=lambda fid: not has_socket_origin(functions[fid].source or ""))
        return unique_strings([*via_callee, *assigners])[:1]

    def __init__(
        self,
        llm: LLMProvider,
        graph: GraphStore,
        *,
        depth: int = 3,
        budget: int = 0,
        targeted_depth_extensions: int = 1,
        selected_program: bool = False,
        source_root: Path | None = None,
        trace: TraceCallback | None = None,
    ):
        self.llm = llm
        self.graph = graph
        self.selected_program = selected_program
        self.source_root = Path(source_root) if source_root is not None else None
        self.declaration_index = DeclarationIndex(graph.bundle.declarations)
        self.depth = depth
        if budget < 0:
            raise ValueError("Entry Verifier work budget cannot be negative")
        self.budget = budget or len(graph.bundle.functions)
        # Historical configuration values remain accepted for callers, but
        # neither value limits the number of call-graph hops. A verifier may
        # follow a source-evidenced dependency for as long as its *function
        # turn* budget permits. Exhaustion remains UNRESOLVED, never REJECTED.
        self.targeted_depth_extensions = max(0, targeted_depth_extensions)
        self.trace = trace

    def _declaration_result(
        self, requested_name: str, matches: list[SourceDeclaration],
    ) -> dict[str, Any]:
        if len(matches) != 1:
            return {
                "kind": "declaration_lookup", "requested_name": requested_name,
                "reason": ("ambiguous; request file:NAME or file:line:NAME"
                           if matches else "name absent from static declaration index"),
                "candidates": [item.summary() for item in matches],
            }
        declaration = matches[0]
        result: dict[str, Any] = {
            **declaration.summary(), "source_excerpt": declaration.source,
            "conditional_source_is_build_proof": False,
        }
        if self.source_root is None:
            return result
        source_path = (self.source_root / declaration.file).resolve()
        if not source_path.is_relative_to(self.source_root.resolve()):
            return result
        try:
            lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return result
        start = max(0, declaration.start_line - 24)
        end = min(len(lines), declaration.end_line + 6)
        context = lines[start:end]
        result["surrounding_source"] = {
            "file": declaration.file, "start_line": start + 1,
            "source": "\n".join(context),
        }
        guards = set(re.findall(
            r"^[ \t]*#[ \t]*ifn?def[ \t]+([A-Za-z_]\w*)",
            "\n".join(context), re.MULTILINE,
        ))
        if guards:
            config_path = self.source_root / "config.h"
            try:
                config_lines = config_path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError:
                config_lines = []
            build_guards: dict[str, dict[str, Any]] = {}
            for guard in sorted(guards):
                defined = re.compile(r"^[ \t]*#[ \t]*define[ \t]+" + re.escape(guard) + r"\b")
                undefined = re.compile(
                    r"^[ \t]*/\*[ \t]*#[ \t]*undef[ \t]+"
                    + re.escape(guard) + r"\b"
                )
                for line_number, row in enumerate(config_lines, 1):
                    state = ("DEFINED" if defined.search(row) else
                             "UNDEFINED" if undefined.search(row) else "")
                    if state:
                        build_guards[guard] = {
                            "state": state, "file": "config.h",
                            "line": line_number, "source": row,
                        }
                        break
            result["selected_config_guard_states"] = build_guards
        return result

    async def run(self, candidate: EntryCandidate) -> EntryRecord:
        session_key = f"entry_verifier:{candidate.candidate_id}"
        function = self.graph.get(candidate.function_id)
        emit_trace(
            self.trace,
            "entry_verifier",
            "candidate_started",
            f"verify {function.name}::{candidate.source_api} at {function.file}:{candidate.line}",
            candidate=as_json(candidate),
            function=function_ref(function),
        )
        selected_function_ids = [candidate.function_id]
        discovery_by_id: dict[str, dict[str, Any]] = {
            candidate.function_id: {
                "depth": 0,
                "discovered_from": None,
                "relation": "root",
            }
        }
        response: dict[str, Any] = {}
        response_history: list[dict[str, Any]] = []
        previous_response: dict[str, Any] = {}
        declaration_result: dict[str, Any] | None = None
        opened_declarations: list[dict[str, Any]] = []
        declaration_queries_seen: set[tuple[str, str]] = set()
        context = []
        supplied_context_ids: set[str] = set()
        previous_context_ids: set[str] = set()
        stop_reason = "maximum context rounds reached"
        # ``depth`` is a graph-hop boundary, while ``budget`` is the number of
        # one-function turns.  Treating depth=4 as four total turns left most
        # callback lifecycle proofs unfinished even when a 24-function budget
        # was configured.
        # Declaration lookups do not consume the function-opening budget.
        # Repeated queries are rejected below, so this remains finite.
        max_rounds = max(1, self.budget + 2 * len(self.declaration_index) + 1)
        settle_asked = False
        for current_depth in range(1, max_rounds + 1):
            context = [
                self.graph.get(function_id)
                for function_id in selected_function_ids[: self.budget]
            ]
            walk = []
            for item in context:
                discovery = discovery_by_id[item.function_id]
                walk.append(
                    {
                        "function_id": item.function_id,
                        "name": item.name,
                        "file": item.file,
                        "start_line": item.start_line,
                        **discovery,
                    }
                )
            context_ids = {item.function_id for item in context}
            frontier = []
            graph_frontier = self.graph.frontier(selected_function_ids)
            known_frontier = {str(item["function_id"]) for item in graph_frontier}
            graph_frontier.extend(
                item for item in self.graph.shared_field_candidates(selected_function_ids)
                if str(item["function_id"]) not in known_frontier
            )
            for raw_choice in graph_frontier:
                raw_connections = raw_choice.get("connections", [])
                if isinstance(raw_connections, list) and raw_connections:
                    frontier.append(raw_choice)
            frontier_by_id = {
                str(item["function_id"]): item for item in frontier
            }
            supplied_context_ids.update(context_ids)
            added_ids = context_ids - previous_context_ids
            turn_context = [
                item for item in context if item.function_id in added_ids
            ]
            if not turn_context and context:
                # Defensive fallback for a resumed provider call.  Normal
                # stateful walks always add exactly one function per turn.
                turn_context = [context[-1]]
            removed_ids = previous_context_ids - context_ids
            added_names = [item.name for item in context if item.function_id in added_ids]
            removed_names = [self.graph.get(item).name for item in sorted(removed_ids)]
            context_names = {item.function_id: item.name for item in context}
            walk_summary = [
                (
                    f"root:{item['name']}"
                    if item["relation"] == "root"
                    else (
                        f"{item['relation']}:{item['name']}<-"
                        f"{context_names.get(str(item['discovered_from']), item['discovered_from'])}"
                    )
                )
                for item in walk
            ]
            emit_trace(
                self.trace,
                "entry_verifier",
                "context_expanded",
                (
                    f"{candidate.candidate_id} round {current_depth}: "
                    f"{len(context)} functions; added={added_names or ['none']}; "
                    f"removed={removed_names or ['none']}; walk={walk_summary}"
                ),
                candidate_id=candidate.candidate_id,
                round=current_depth,
                expansion_mode="model_requested_only",
                selected_function_ids=list(selected_function_ids),
                functions=[function_ref(item) for item in context],
                available_context_functions=frontier,
                walk=walk,
                walk_summary=walk_summary,
                graph_edges=self.graph.induced_edges(context_ids),
                added_function_ids=sorted(added_ids),
                removed_function_ids=sorted(removed_ids),
            )
            response = await self.llm.complete_json(
                role="entry_verifier",
                instructions=(
                    "Verify provenance and the exact first DATA-acquisition boundary, not merely API spelling. Expand reasoning "
                    "through the supplied callers and callees. VERIFIED requires evidence that data originates from a "
                    "program-external subject/interface and FIRST enters a program-owned buffer, string, argument, object "
                    "field, or other data-bearing storage at this "
                    "candidate site. A parser, decoder, VM stack getter, dispatcher, downstream accessor, or caller of a "
                    "program-defined input wrapper is not another Entry even when it handles attacker-controlled data. For "
                    "such downstream sites set first_acquisition_confirmed=false and REJECTED when affirmative evidence exists. "
                    "accept/accept4, socket creation, connection setup, readiness notification, status/error returns, and "
                    "resource handles do not qualify: they are context needed to reach the later data receive/read Entry. "
                    "For socket input, distinguish the address family and transport using opened socket creation, "
                    "accepted-listener, or connected-peer source. recv and recvfrom alone do not mean TCP or UDP; "
                    "AF_UNIX also supports stream and datagram sockets. If this provenance is missing, record "
                    "channel_kind as ambiguous network/socket input and keep the transport question in unknowns; "
                    "do not invent an Internet executor. This transport classification is separate from whether "
                    "the site is the first external data acquisition. "
                    "REJECTED otherwise requires affirmative contrary evidence. Use UNRESOLVED for incomplete fd, callback, "
                    "indirect-call, build, or ownership provenance. Identify downstream consumers but do not confuse an "
                    "input-source entry with the best harness anchor. VERIFIED answers external-data provenance plus "
                    "exact first-acquisition identity. Record attacker control as downstream prioritization evidence, "
                    "but do not use it to redefine or reject a real data Entry. "
                    "There is no confidence score: do not hedge. When a fact that decides whether this site is "
                    "the first external data acquisition is not yet shown, set context_complete=false and request "
                    "the source that settles it. For a read from a socket descriptor, where the descriptor comes "
                    "from (the accept, connect or socket+bind that creates it) is such a fact: VERIFIED needs "
                    "that source opened, so request the function that creates or assigns the descriptor. "
                    "Facts that do not decide it -- address family, IPv4 or IPv6, ACLs, authentication, who "
                    "controls the peer, configuration -- go into channel_kind, attacker_control or rationale, "
                    "never into unknowns. "
                    "Function claims must cite supplied function IDs and lines; "
                    "declaration claims must cite the supplied declaration file and line. "
                    "A frontier connection marked possible_indirect_target or edge kind indirect_possible is an "
                    "SVF points-to POSSIBILITY, not proof that this target executes in the selected build or path. "
                    "A callback_registration_candidate with edge_lines identifies a source registration/reference site; "
                    "open that assignment/registration and lifecycle source, retain every legal target, and keep "
                    "the verdict UNRESOLVED until build selection and external-data provenance are established. "
                    "Only source in context has been newly opened this turn. Earlier opened source remains in this "
                    "same stateful session and opened_context_functions lists it without repeating source text. "
                    "A macro, struct, union, enum, or class is not a function-graph node. "
                    "Request its exact name in requested_declaration_name to open its indexed source, "
                    "or set list_declarations to list names with an optional declaration_name_filter. "
                    "This lookup is independent of the function frontier. Lexical definitions under "
                    "conditional compilation are not build proof unless the selected build condition is shown. "
                    "If a concrete unknown names an uninspected declaration, request it before marking "
                    "the context complete. "
                    "available_context_functions is a source-free list of "
                    "direct callers/callees and lexical shared-field writer candidates; shared fields are navigation hints, not proof of the same object or data flow. Open the source to verify queue and object identity. Set context_complete=false and request the smallest "
                    "necessary set of IDs from that list when another round could resolve a concrete missing fact. "
                    "Do not request already supplied functions or context speculatively."
                ),
                payload={
                    "candidate": {
                        "candidate_id": candidate.candidate_id,
                        "function_id": candidate.function_id,
                        "source_api": candidate.source_api,
                        "line": candidate.line,
                        "channel_hint": candidate.channel_hint,
                        "site_kind": str(candidate.site_kind),
                        "boundary_subject": candidate.boundary_subject,
                        "rationale": candidate.rationale,
                    },
                    "context": [
                        function_payload(
                            item, source_limit=max(1, len(item.source) + 1),
                        )
                        for item in turn_context
                    ],
                    "opened_context_functions": [
                        function_ref(item) for item in context
                    ],
                    "previously_opened_context_functions": [
                        function_ref(item)
                        for item in context
                        if item.function_id not in added_ids
                    ],
                    "available_context_functions": frontier,
                    "declaration_result": declaration_result,
                    "opened_declarations": opened_declarations,
                    "declaration_lookup_available": bool(self.declaration_index),
                    "context_round": current_depth,
                    "context_limits": {
                        # Work limits are a scheduler concern, not evidence
                        # that the source walk is semantically complete. Keep
                        # this payload independent of an operator's budget so
                        # --resume-from can replay the exact earlier turns
                        # when the operator raises that budget.
                        "max_rounds": None,
                        "max_graph_depth": None,
                        "graph_expansion": "evidence_requested_without_hop_limit",
                        "max_functions": None,
                        "max_new_functions_per_round": (
                            MAX_TARGETED_CONTEXT_ADDITIONS_PER_ROUND
                        ),
                        "expansion_mode": "model_requested_only",
                    },
                    "previous_round": previous_response,
                },
                output_schema=ENTRY_VERIFIER_SCHEMA,
                session_key=session_key,
            )
            response_history.append(response)
            declaration_result = None
            declaration_request = str(response.get("requested_declaration_name") or "").strip()
            list_declarations = bool(response.get("list_declarations"))
            if not declaration_request and not list_declarations and (
                response.get("status") == "UNRESOLVED"
                and response.get("context_complete")
                and not response.get("requested_function_ids")
            ):
                # A completed walk must not silently miss an already indexed
                # macro named in its own unresolved question. This is a
                # source-index lookup, never an inferred macro definition.
                for unknown in string_list(response.get("unknowns")):
                    for symbol in re.findall(r"\b[A-Za-z_]\w*\b", unknown):
                        if ("open", symbol) in declaration_queries_seen:
                            continue
                        if any(item.kind == "macro"
                               for item in self.declaration_index.lookup(symbol)):
                            declaration_request = symbol
                            break
                    if declaration_request:
                        break
            if declaration_request or list_declarations:
                if declaration_request:
                    key = ("open", declaration_request)
                    if key in declaration_queries_seen:
                        declaration_result = {
                            "kind": "declaration_lookup", "requested_name": declaration_request,
                            "reason": "declaration already opened",
                        }
                    else:
                        declaration_queries_seen.add(key)
                        matches = self.declaration_index.lookup(declaration_request)
                        declaration_result = self._declaration_result(
                            declaration_request, matches
                        )
                        if "source_excerpt" in declaration_result:
                            opened_declarations.append(declaration_result)
                else:
                    query = str(response.get("declaration_name_filter") or "")
                    key = ("list", query)
                    if key in declaration_queries_seen:
                        declaration_result = {
                            "kind": "declaration_catalog", "name_filter": query,
                            "reason": "catalog query already returned",
                        }
                    else:
                        declaration_queries_seen.add(key)
                        declaration_result = {
                            "kind": "declaration_catalog", "name_filter": query,
                            "names": self.declaration_index.names(query),
                        }
                emit_trace(self.trace, "entry_verifier", "declaration_opened",
                           f"{candidate.candidate_id}: {declaration_request or 'catalog'}",
                           candidate_id=candidate.candidate_id,
                           declaration_result=declaration_result)
                previous_response = response
                continue
            requested_raw = string_list(response.get("requested_function_ids"))
            resolved_requests = unique_strings(
                identifier for identifier in requested_raw
                if identifier in self.graph.bundle.functions
            )
            model_eligible_requests = [
                identifier for identifier in resolved_requests
                if identifier in frontier_by_id and identifier not in context_ids
            ]
            context_complete = bool(response.get("context_complete", True))
            # A source-located function reference to the acquisition wrapper
            # is the concrete callback-registration evidence the verifier
            # needs.  Open it before speculative neighbours even if the model
            # prematurely says the current context is complete.
            registration_requests = []
            if candidate.site_kind is EntrySiteKind.DIRECT_ACQUISITION:
                for identifier, choice in frontier_by_id.items():
                    if identifier in context_ids:
                        continue
                    connections = choice.get("connections", [])
                    if not isinstance(connections, list):
                        continue
                    if any(
                        connection.get("relation") == "caller_of"
                        and str(connection.get("connected_function_id", ""))
                        == candidate.function_id
                        and "function_reference" in connection.get("edge_kinds", [])
                        and bool(connection.get("edge_lines"))
                        for connection in connections
                    ):
                        registration_requests.append(identifier)
            callback_invocation_candidates = [
                item.function_id
                for item in self.graph.callback_invocation_callers(
                    candidate.function_id,
                    registration_function_ids=context_ids,
                )
                if item.function_id in frontier_by_id
                and item.function_id not in context_ids
            ]
            opened_callback_invocation = any(
                item.function_id in context_ids
                for item in self.graph.callback_invocation_callers(
                    candidate.function_id,
                    registration_function_ids=context_ids,
                )
            )
            # One exact-slot invocation is sufficient to continue the
            # provenance proof.  Opening every legal reuse of a generic member
            # callback (logging close probes, crawler clients, normal network
            # reads, and so on) repeated the same expensive verifier turn even
            # after the lifecycle was established. Prefer the model's explicit
            # choice; otherwise open one same-component caller as a safe
            # fallback.  The deterministic same-component caller precedes a
            # model-selected alternative: a generic slot such as ``c->read``
            # can be used by both the request loop and unrelated logger/crawler
            # probes, and accepting the latter first stranded the real TCP
            # lifecycle within the context budget. Remaining legal callers
            # stay visible in the frontier and can still be requested when a
            # concrete unknown requires them.
            model_callback_requests = [
                identifier for identifier in model_eligible_requests
                if identifier in callback_invocation_candidates
            ]
            fallback_callback_requests = sorted(
                callback_invocation_candidates,
                key=lambda identifier: (
                    self.graph.get(identifier).file != function.file,
                    self.graph.get(identifier).file,
                    self.graph.get(identifier).start_line,
                    self.graph.get(identifier).name,
                ),
            )
            callback_invocation_requests = (
                []
                if opened_callback_invocation
                else unique_strings([
                    *fallback_callback_requests[:1],
                    *model_callback_requests,
                ])
            )
            # Lifecycle evidence has a strict order: first locate the callback
            # registration, then open one invocation of that exact slot.  A
            # model-requested adjacent function must not displace the exact
            # invocation when only one context addition is permitted per
            # round; doing so left real TCP readers unresolved while walking
            # unrelated logging and cleanup code.
            # A socket-like label or getpeername alone does not prove where
            # a descriptor came from. Search for source-level socket creation
            # before accepting a socket provenance verdict. Shared-field hits
            # are only navigation candidates; the opened source is evidence.
            socket_claim = candidate.source_api.rsplit("::", 1)[-1].casefold() in {"read", "readv", "recv", "recvfrom", "recvmsg"} and any(
                word in (candidate.channel_hint + " " + candidate.boundary_subject).casefold()
                for word in ("socket", "tcp", "network", "udp")
            )
            socket_origin_pattern = r"(?<![.>])\b(?:accept4?|connect|socketpair)\s*\("
            socket_bind_pattern = r"(?<![.>])\bsocket\s*\("
            bound_socket_pattern = r"(?<![.>])\bbind\s*\("

            def has_socket_origin(source: str) -> bool:
                return bool(
                    re.search(socket_origin_pattern, source)
                    or (re.search(socket_bind_pattern, source)
                        and re.search(bound_socket_pattern, source))
                )

            origin_opened = any(has_socket_origin(item.source) for item in context)
            lifecycle_requests = []
            if socket_claim and not origin_opened:
                queue_pattern = r"\b\w*(?:pop|dequeue)\w*\s*\("
                opened_queue = {item.function_id for item in context
                                if re.search(queue_pattern, item.source, re.IGNORECASE)}
                direct_origins = [identifier for identifier, choice in frontier_by_id.items()
                                  if has_socket_origin(self.graph.get(identifier).source)
                                  and any(c.get("relation") in {"caller_of", "callee_of"}
                                          for c in choice.get("connections", []))]
                shared_writers = [identifier for identifier, choice in frontier_by_id.items()
                                  if any(c.get("relation") == "shared_typed_field_candidate"
                                         and c.get("connected_function_id") in opened_queue
                                         for c in choice.get("connections", []))]
                queue_consumers = [identifier for identifier in frontier_by_id
                                   if not opened_queue
                                   and re.search(queue_pattern, self.graph.get(identifier).source, re.IGNORECASE)
                                   and self.graph.shared_field_candidates([identifier])]
                lifecycle_requests = unique_strings([*direct_origins, *queue_consumers, *shared_writers])[:1]
                if not lifecycle_requests:
                    lifecycle_requests = self._descriptor_origin_requests(candidate, context, has_socket_origin)
            remaining_model_requests = [
                identifier for identifier in model_eligible_requests
                if identifier not in registration_requests
                and identifier not in callback_invocation_requests
            ]
            eligible_requests = unique_strings([
                *registration_requests,
                *callback_invocation_requests,
                *lifecycle_requests,
                *remaining_model_requests,
            ])
            remaining_budget = max(0, self.budget - len(selected_function_ids))
            addition_limit = min(
                remaining_budget,
                MAX_TARGETED_CONTEXT_ADDITIONS_PER_ROUND,
            )
            requested = eligible_requests[:addition_limit]
            deferred_requests = eligible_requests[addition_limit:]
            rejected_requests = unique_strings([
                *(
                    identifier for identifier in requested_raw
                    if identifier not in self.graph.bundle.functions
                ),
                *(
                    identifier for identifier in resolved_requests
                    if identifier not in frontier_by_id and identifier not in context_ids
                ),
            ])
            already_supplied_requests = [
                identifier for identifier in resolved_requests if identifier in context_ids
            ]
            context_unchanged = bool(previous_context_ids) and context_ids == previous_context_ids
            if (current_depth >= max_rounds or not remaining_budget) and eligible_requests:
                stop_reason = "context function budget exhausted"
            elif requested:
                stop_reason = "open only the explicitly requested adjacent functions"
            elif context_complete and not eligible_requests:
                stop_reason = "model marked context complete"
            elif not frontier:
                stop_reason = "no adjacent graph context is available"
            else:
                stop_reason = "model requested no eligible adjacent function"
            requested_names = [self.graph.get(item).name for item in requested]
            rationale = str(response.get("rationale", ""))
            emit_trace(
                self.trace,
                "entry_verifier",
                "round_decision",
                (
                    f"{candidate.candidate_id} round {current_depth}: "
                    f"{response.get('status', 'UNRESOLVED')}; "
                    f"requests={requested_names or ['none']}; {stop_reason}; "
                    f"reason={rationale[:240] or 'none'}"
                ),
                candidate_id=candidate.candidate_id,
                round=current_depth,
                model_status=str(response.get("status", "UNRESOLVED")),
                channel_kind=str(response.get("channel_kind", candidate.channel_hint)),
                attacker_control=str(response.get("attacker_control", "unknown")),
                rationale=rationale,
                first_acquisition_confirmed=bool(
                    response.get("first_acquisition_confirmed", False)
                ),
                unknowns=string_list(response.get("unknowns")),
                provenance_path=object_list(response.get("provenance_path")),
                evidence=object_list(response.get("evidence")),
                consumer_hints=string_list(response.get("consumer_hints")),
                context_complete=context_complete,
                requested_function_ids=requested_raw,
                accepted_requested_function_ids=requested,
                forced_registration_function_ids=registration_requests,
                forced_callback_invocation_function_ids=(
                    callback_invocation_requests
                ),
                accepted_requested_functions=[
                    function_ref(self.graph.get(item)) for item in requested
                ],
                deferred_requested_function_ids=deferred_requests,
                already_supplied_requested_function_ids=already_supplied_requests,
                rejected_requested_function_ids=rejected_requests,
                context_unchanged=context_unchanged,
                stop_reason=stop_reason,
                graph_hop_limit_applied=False,
                model_response=response,
            )
            previous_context_ids = context_ids
            previous_response = {
                **response,
                "accepted_requested_function_ids": requested,
                "forced_registration_function_ids": registration_requests,
                "forced_callback_invocation_function_ids": (
                    callback_invocation_requests
                ),
                "deferred_requested_function_ids": deferred_requests,
                "rejected_requested_function_ids": rejected_requests,
            }
            if current_depth >= max_rounds or not remaining_budget:
                break
            if (not requested and not settle_asked and frontier
                    and str(response.get("status", "UNRESOLVED")) == "UNRESOLVED"):
                # An UNRESOLVED answer that asks for nothing used to end the walk there.  Analyse
                # once more instead: name the deciding fact and open the source for it, or decide
                # on what is already shown.  (Replaces the old confidence threshold, which turned
                # tinyproxy's real socket Entry -- readline's recv, called "the exact first DATA
                # acquisition" by the verifier itself -- into UNRESOLVED over its IPv4/IPv6 and
                # ACL doubts, which do not decide whether a site is an Entry.)
                settle_asked = True
                previous_response["follow_up"] = SETTLE_FOLLOW_UP
                emit_trace(self.trace, "entry_verifier", "settle_round",
                           f"{candidate.candidate_id}: UNRESOLVED without a request; analysing once more",
                           candidate_id=candidate.candidate_id, round=current_depth)
                continue
            if not requested:
                break
            for function_id in requested:
                # A descriptor-origin function found by source search need not be adjacent.
                choice = frontier_by_id.get(function_id) or {"connections": [{
                    "connected_function_id": candidate.function_id, "relation": "descriptor_origin_search"}]}
                connections = choice.get("connections", [])
                connection = connections[0] if isinstance(connections, list) and connections else {}
                parent_id = str(connection.get("connected_function_id", candidate.function_id))
                parent_depth = int(discovery_by_id.get(parent_id, {}).get("depth", 0))
                discovery_by_id[function_id] = {
                    "depth": parent_depth + 1,
                    "discovered_from": parent_id,
                    "relation": str(connection.get("relation", "requested_adjacent")),
                }
                selected_function_ids.append(function_id)
        pending_function_ids = (
            unique_strings([*requested, *deferred_requests])
            if stop_reason == "context function budget exhausted"
            else []
        )
        try:
            status = Verdict(str(response.get("status", "UNRESOLVED")))
        except ValueError:
            status = Verdict.UNRESOLVED
        # Every ID in this union was backed by source shown in a verifier turn.
        # Limiting validation to only the final rotating window discarded valid
        # provenance/evidence gathered immediately before a requested expansion.
        allowed_ids = supplied_context_ids
        provenance: list[dict[str, str]] = []
        dropped_provenance: list[dict[str, Any]] = []
        provenance_seen: set[tuple[str, str]] = set()
        for historical_response in response_history:
            for raw_path_item in object_list(
                historical_response.get("provenance_path")
            ):
                identifier = str(raw_path_item.get("function_id", ""))
                relation = str(raw_path_item.get("relation", ""))
                key = (identifier, relation)
                if identifier in allowed_ids:
                    if key not in provenance_seen:
                        provenance_seen.add(key)
                        provenance.append({
                            "function_id": identifier,
                            "relation": relation,
                        })
                else:
                    dropped_provenance.append({
                        "item": raw_path_item,
                        "reason": "function was outside all supplied source context",
                    })
        evidence: list[Evidence] = []
        dropped_evidence: list[dict[str, Any]] = []
        evidence_seen: set[tuple[str, str, int | None, str, str]] = set()
        for historical_response in response_history:
            for raw_evidence_item in object_list(
                historical_response.get("evidence")
            ):
                evidence_function = self.graph.bundle.functions.get(
                    str(raw_evidence_item.get(
                        "function_id", function.function_id
                    ))
                )
                if (
                    evidence_function is None
                    or evidence_function.function_id not in allowed_ids
                ):
                    dropped_evidence.append({
                        "item": raw_evidence_item,
                        "reason": (
                            "function was missing or outside all supplied source context"
                        ),
                    })
                    continue
                parsed = evidence_from_dict(
                    raw_evidence_item, evidence_function
                )
                if parsed.file != evidence_function.file:
                    dropped_evidence.append({
                        "item": raw_evidence_item,
                        "reason": "evidence file did not match metadata",
                    })
                    continue
                if parsed.line is not None and not (
                    evidence_function.start_line
                    <= parsed.line
                    <= evidence_function.end_line
                ):
                    dropped_evidence.append({
                        "item": raw_evidence_item,
                        "reason": "evidence line was outside function range",
                    })
                    continue
                evidence_key = (
                    parsed.function_id, parsed.file, parsed.line,
                    parsed.kind, parsed.detail,
                )
                if evidence_key not in evidence_seen:
                    evidence_seen.add(evidence_key)
                    evidence.append(parsed)
        evidence_fallback = False
        if not evidence:
            evidence = list(candidate.evidence)
            evidence_fallback = True
        unknowns = unique_strings(string_list(response.get("unknowns")))
        downgrade_reasons: list[str] = []
        first_acquisition_confirmed = response.get("first_acquisition_confirmed") is True
        compiler_site = _compiler_external_call_site(
            function, candidate.source_api, candidate.line,
        )
        if (status in {Verdict.VERIFIED, Verdict.REJECTED}
            and compiler_site is not None
            and not compiler_site.get("compile_command_available", False)):
            claimed = status
            status = Verdict.UNRESOLVED
            unknowns.append(
                "compiler-resolved input call was parsed without the product's "
                "confirmed compilation command"
            )
            downgrade_reasons.append(
                f"{claimed} deferred because the resolved call may differ "
                "in the selected product build"
            )
        if pending_function_ids and status is not Verdict.UNRESOLVED:
            status = Verdict.UNRESOLVED
            unknowns.append(
                "source-linked context remains unopened after the selected work budget"
            )
            downgrade_reasons.append(
                "definite verdict deferred because requested source remains unopened"
            )
        if status is Verdict.VERIFIED and not context_complete:
            status = Verdict.UNRESOLVED
            unknowns.append("model marked context incomplete")
            downgrade_reasons.append(
                "VERIFIED was downgraded because source context is incomplete"
            )
        if status is Verdict.VERIFIED and not first_acquisition_confirmed:
            status = Verdict.REJECTED
            unknowns.append("candidate was not confirmed as the first external acquisition site")
            downgrade_reasons.append(
                "VERIFIED was rejected because the site only consumes or forwards an already acquired value"
            )
        if (status is Verdict.VERIFIED and self.selected_program
            and candidate.site_kind is EntrySiteKind.EXPORTED_API):
            # A callable C/C++ function in an executable is not an external
            # input boundary merely because its signature accepts pointers.
            # A separately evidenced host/plugin invocation can be revisited,
            # but a public declaration alone cannot establish that caller.
            status = Verdict.UNRESOLVED
            unknowns.append(
                "public API arguments do not prove an external caller of the selected executable"
            )
            downgrade_reasons.append(
                "VERIFIED was downgraded because executable external-caller provenance is absent"
            )
        if status is Verdict.VERIFIED and not provenance:
            status = Verdict.UNRESOLVED
            unknowns.append("verifier supplied no source-to-entry provenance path")
            downgrade_reasons.append("VERIFIED was downgraded because no valid provenance path remained")
        elif status is Verdict.VERIFIED and candidate.function_id not in {
            item["function_id"] for item in provenance
        }:
            status = Verdict.UNRESOLVED
            unknowns.append("provenance path did not reach the candidate Entry Function")
            downgrade_reasons.append(
                "VERIFIED was downgraded because provenance did not reach the candidate"
            )
        if status is Verdict.VERIFIED and evidence_fallback:
            status = Verdict.UNRESOLVED
            unknowns.append("verifier supplied no valid line-level evidence")
            downgrade_reasons.append(
                "VERIFIED was downgraded because only generator candidate evidence remained"
            )
        if status is Verdict.REJECTED and evidence_fallback:
            status = Verdict.UNRESOLVED
            unknowns.append("rejection had no valid affirmative contrary evidence")
            downgrade_reasons.append(
                "REJECTED was downgraded because only generator candidate evidence remained"
            )
        # Apply socket-fd provenance after independent evidence/first-read
        # checks. Earlier short-circuiting suppressed the real error reason.
        if status is Verdict.VERIFIED and socket_claim and not origin_opened:
            status = Verdict.UNRESOLVED
            unknowns.append(
                "No opened source establishes socket origin; candidate labels and getpeername are not provenance proof."
            )
            downgrade_reasons.append(
                "VERIFIED was downgraded because socket creation or accept provenance is missing"
            )
        consumer_hints = unique_strings(
            identifier
            for historical_response in response_history
            for identifier in string_list(
                historical_response.get("consumer_hints")
            )
            if identifier in allowed_ids
        )
        # A model may prove the callback lifecycle but omit the already-opened
        # invocation body from ``consumer_hints`` in its final JSON.  Preserve
        # that source-proven next-use relation deterministically.  The graph
        # helper requires an exact registered slot (for example ``c->read``),
        # so this does not promote arbitrary line-less SVF targets.
        registration_ids = {
            edge.caller_id
            for edge in self.graph.bundle.edges
            if edge.kind == "function_reference"
            and edge.line is not None
            and edge.callee_id == candidate.function_id
            and edge.caller_id in allowed_ids
        }
        callback_consumers = [
            item.function_id
            for item in self.graph.callback_invocation_callers(
                candidate.function_id,
                registration_function_ids=registration_ids,
            )
            if item.function_id in allowed_ids
        ]
        # Prefer source-valid consumers selected by the verifier: one callback
        # (for example a generic socket reader) can also be reused by logging
        # or close-probe paths that are valid invocations but irrelevant to the
        # primary request flow.  If the model omitted every consumer, retain
        # all exact-slot invocations as a completeness fallback.
        consumer_hints = unique_strings(
            consumer_hints or callback_consumers
        )
        record = EntryRecord(
            entry_id=stable_id("entry", candidate.candidate_id, status),
            candidate_id=candidate.candidate_id,
            status=status,
            entry_function_id=candidate.function_id,
            source_api=candidate.source_api,
            channel_kind=str(response.get("channel_kind", candidate.channel_hint)),
            attacker_control=str(response.get("attacker_control", "unknown")),
            provenance_path=provenance,
            consumer_hints=consumer_hints,
            evidence=evidence,
            unknowns=unknowns,
            # Not a model score any more (the verifier gives none): 1.0 for a decided verdict,
            # 0.0 for UNRESOLVED.  Kept because merging and feature selection still order by it.
            verifier_confidence=0.0 if status is Verdict.UNRESOLVED else 1.0,
            entry_line=candidate.line,
            rationale=str(response.get("rationale", "")),
            site_kind=candidate.site_kind,
            boundary_subject=candidate.boundary_subject,
            first_acquisition_confirmed=(
                first_acquisition_confirmed and status is Verdict.VERIFIED
            ),
            inspected_function_ids=[
                function_id for function_id in selected_function_ids
                if function_id in supplied_context_ids
            ],
            verification_rounds=current_depth,
            pending_function_ids=pending_function_ids,
            analysis_disposition=(
                AnalysisDisposition.DEFERRED
                if pending_function_ids else AnalysisDisposition.COMPLETE
            ),
            analysis_blocker=(
                stop_reason if pending_function_ids else ""
            ),
        )
        record.validate()
        emit_trace(
            self.trace,
            "entry_verifier",
            "final_verdict",
            (
                f"{candidate.candidate_id}: {record.status}; "
                f"channel={record.channel_kind}; attacker_control={record.attacker_control}; "
                f"{record.rationale or 'no rationale'}"
            ),
            candidate_id=candidate.candidate_id,
            entry_id=record.entry_id,
            function=function_ref(function),
            model_status=str(response.get("status", "UNRESOLVED")),
            final_status=str(record.status),
            stop_reason=stop_reason,
            pending_function_ids=pending_function_ids,
            downgrade_reasons=downgrade_reasons,
            accepted_provenance=provenance,
            dropped_provenance=dropped_provenance,
            accepted_evidence=[as_json(item) for item in evidence],
            dropped_evidence=dropped_evidence,
            evidence_fallback_to_candidate=evidence_fallback,
            record=as_json(record),
        )
        await close_llm_session(self.llm, session_key)
        return record


def _confidence(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0
