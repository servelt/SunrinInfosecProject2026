from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from ..analysis.graph import GraphStore
from ..llm.base import LLMProvider, close_llm_session
from ..models import (
    AnalysisBundle,
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
from .common import (
    concurrent_map,
    function_payload,
    function_payload_excerpts,
    function_ref,
    is_non_product_build_target,
    object_list,
    string_list,
)


SOURCE_APIS: dict[str, str] = {
    "recv": "network",
    "recvfrom": "network",
    "recvmsg": "network",
    "SSL_read": "network",
    "BIO_read": "network",
    "read": "fd_or_stream",
    "pread": "file_or_device",
    "readv": "fd_or_stream",
    "preadv": "file_or_device",
    "fread": "file",
    "fread_unlocked": "file",
    "fgets": "file_or_stdin",
    "getc": "file_or_stdin",
    "getchar": "stdin",
    "getchar_unlocked": "stdin",
    "scanf": "stdin",
    "getline": "file_or_stdin",
    "getdelim": "file_or_stdin",
    "readlink": "filesystem",
    "ioctl": "device",
    "ReadFile": "file_or_pipe",
    "WSARecv": "network",
    "WSARecvFrom": "network",
    "SSL_read_ex": "network",
    "gnutls_record_recv": "network",
    "getenv": "environment",
    "mq_receive": "ipc",
    "msgrcv": "ipc",
}

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

MIN_VERIFIED_CONFIDENCE = 0.80
MAX_TARGETED_CONTEXT_ADDITIONS_PER_ROUND = 3


ENTRY_GENERATOR_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["candidates"],
    "properties": {
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


ENTRY_VERIFIER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "status", "channel_kind", "attacker_control", "provenance_path", "consumer_hints",
        "evidence", "unknowns", "confidence", "rationale", "first_acquisition_confirmed",
        "context_complete", "requested_function_ids",
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
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "rationale": {"type": "string"},
        "first_acquisition_confirmed": {"type": "boolean"},
        "context_complete": {"type": "boolean"},
        "requested_function_ids": {"type": "array", "items": {"type": "string"}},
    },
}


class EntryGeneratorAgent:
    def __init__(
        self,
        llm: LLMProvider,
        *,
        chunk_size: int = 32,
        max_batch_chars: int = 120_000,
        trace: TraceCallback | None = None,
    ):
        self.llm = llm
        self.chunk_size = chunk_size
        self.max_batch_chars = max_batch_chars
        self.trace = trace

    def batches(
        self, bundle: AnalysisBundle
    ) -> list[list[tuple[FunctionMetadata, dict[str, Any]]]]:
        """Use the CLI batch size as a ceiling, with a prompt-size safety cap."""

        result: list[list[tuple[FunctionMetadata, dict[str, Any]]]] = []
        current: list[tuple[FunctionMetadata, dict[str, Any]]] = []
        current_chars = 0
        for function in bundle.function_list():
            if not _is_product_function(function):
                continue
            for payload in function_payload_excerpts(function):
                weight = len(str(payload.get("source", ""))) + 1_500
                if current and (
                    len(current) >= self.chunk_size
                    or current_chars + weight > self.max_batch_chars
                ):
                    result.append(current)
                    current = []
                    current_chars = 0
                current.append((function, payload))
                current_chars += weight
        if current:
            result.append(current)
        return result

    async def run(self, bundle: AnalysisBundle) -> list[EntryCandidate]:
        candidates = self._deterministic_candidates(bundle)
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
            if not _is_product_function(function)
        ]
        emit_trace(
            self.trace,
            "entry_generator",
            "function_prefilter",
            (
                f"kept {len(bundle.functions) - len(excluded_functions)} product functions; "
                f"excluded {len(excluded_functions)} test/fuzz/benchmark functions"
            ),
            excluded_functions=excluded_functions,
        )
        batches = self.batches(bundle)

        async def analyze_batch(
            batch: list[tuple[FunctionMetadata, dict[str, Any]]]
        ) -> tuple[list[tuple[FunctionMetadata, dict[str, Any]]], dict[str, Any]]:
            batch_functions = list({item.function_id: item for item, _ in batch}.values())
            emit_trace(
                self.trace,
                "entry_generator",
                "batch_started",
                f"inspect {len(batch_functions)} functions across {len(batch)} source excerpts",
                functions=[function_ref(item) for item in batch_functions],
                excerpt_count=len(batch),
            )
            response = await self.llm.complete_json(
                role="entry_generator",
                instructions=(
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
                payload={"functions": [payload for _, payload in batch]},
                output_schema=ENTRY_GENERATOR_SCHEMA,
            )
            return batch, response

        analyzed = await concurrent_map(
            batches,
            analyze_batch,
            getattr(self.llm, "max_concurrency", 1),
        )
        for batch, response in analyzed:
            known = {item.function_id: item for item, _ in batch}
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
        deduplicated: dict[tuple[str, str, int | None], EntryCandidate] = {}
        for item in candidates:
            key = (item.function_id, item.source_api.casefold(), item.line)
            previous = deduplicated.get(key)
            if previous is None or item.confidence > previous.confidence:
                deduplicated[key] = item
        result = sorted(deduplicated.values(), key=lambda item: item.candidate_id)
        emit_trace(
            self.trace,
            "entry_generator",
            "completed",
            f"produced {len(result)} deduplicated entry candidates",
            proposed_count=len(candidates),
            deduplicated_count=len(result),
        )
        return result

    def _deterministic_candidates(self, bundle: AnalysisBundle) -> list[EntryCandidate]:
        result: list[EntryCandidate] = []
        for function in bundle.functions.values():
            if not _is_product_function(function):
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
                matches = _direct_external_call_matches(function.source, short)
                # Entry identity is a concrete source line.  Metadata without
                # a direct call expression is insufficient and commonly comes
                # from member callbacks such as ``c->read``.
                call_sites: list[re.Match[str]] = matches
                for call_match in call_sites:
                    line = function.start_line + function.source.count(
                        "\n", 0, call_match.start()
                    )
                    channel = SOURCE_APIS[short]
                    evidence = Evidence(
                        kind="source",
                        function_id=function.function_id,
                        file=function.file,
                        line=line,
                        detail=f"known input-source API {api}",
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
                            rationale="deterministic input-source API match",
                            confidence=0.88 if short != "read" else 0.55,
                            evidence=[evidence],
                            site_kind=EntrySiteKind.DIRECT_ACQUISITION,
                            boundary_subject=_boundary_subject_for_channel(channel),
                        )
                    )
        return result


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
    spelling = canonical_api.rsplit("::", 1)[-1]
    lines = sorted({
        function.start_line + function.source.count("\n", 0, match.start())
        for match in _direct_external_call_matches(function.source, spelling)
    })
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


def _is_product_function(function: FunctionMetadata) -> bool:
    normalized = function.file.replace("\\", "/")
    path_parts = {part.casefold() for part in PurePosixPath(normalized).parts}
    if path_parts & _NON_PRODUCT_PATH_PARTS:
        return False
    lowered_name = function.name.casefold()
    if lowered_name.startswith(("llvmfuzzertestoneinput", "afl_test_one_input")):
        return False
    if function.build_targets and all(
        is_non_product_build_target(target) for target in function.build_targets
    ):
        return False
    return True


def _matching_external_api(function: FunctionMetadata, source_api: str) -> str | None:
    requested = source_api.rsplit("::", 1)[-1].casefold()
    matches = [
        api for api in function.external_calls
        if api.rsplit("::", 1)[-1].casefold() == requested
    ]
    return sorted(matches, key=lambda item: (len(item), item))[0] if matches else None


def _external_call_lines(function: FunctionMetadata, source_api: str) -> list[int]:
    spelling = source_api.rsplit("::", 1)[-1]
    return sorted({
        function.start_line + function.source.count("\n", 0, match.start())
        for match in _direct_external_call_matches(function.source, spelling)
    })


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
    for match in re.finditer(rf"\b{re.escape(spelling)}\s*\(", source):
        prefix = source[max(0, match.start() - 64):match.start()]
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
    def __init__(
        self,
        llm: LLMProvider,
        graph: GraphStore,
        *,
        depth: int = 3,
        budget: int = 16,
        trace: TraceCallback | None = None,
    ):
        self.llm = llm
        self.graph = graph
        self.depth = depth
        self.budget = budget
        self.trace = trace

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
        previous_response: dict[str, Any] = {}
        context = []
        supplied_context_ids: set[str] = set()
        previous_context_ids: set[str] = set()
        stop_reason = "maximum context rounds reached"
        for current_depth in range(1, max(1, self.depth) + 1):
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
            frontier = self.graph.frontier(selected_function_ids)
            frontier_by_id = {
                str(item["function_id"]): item for item in frontier
            }
            supplied_context_ids.update(context_ids)
            added_ids = context_ids - previous_context_ids
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
                    "REJECTED otherwise requires affirmative contrary evidence. Use UNRESOLVED for incomplete fd, callback, "
                    "indirect-call, build, or ownership provenance. Identify downstream consumers but do not confuse an "
                    "input-source entry with the best harness anchor. VERIFIED answers external-data provenance plus "
                    "exact first-acquisition identity. Record attacker control as downstream prioritization evidence, "
                    "but do not use it to redefine or reject a real data Entry. "
                    "Every claim must cite supplied function IDs and lines. "
                    "Only source in context has been opened. available_context_functions is a source-free list of "
                    "direct callers/callees; it is not evidence. Set context_complete=false and request the smallest "
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
                            item,
                            focus_line=(
                                candidate.line
                                if item.function_id == candidate.function_id
                                else None
                            ),
                        )
                        for item in context
                    ],
                    "available_context_functions": frontier,
                    "context_round": current_depth,
                    "context_limits": {
                        "max_rounds": self.depth,
                        "max_functions": self.budget,
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
            requested_raw = string_list(response.get("requested_function_ids"))
            resolved_requests = unique_strings(
                identifier for identifier in requested_raw
                if identifier in self.graph.bundle.functions
            )
            eligible_requests = [
                identifier for identifier in resolved_requests
                if identifier in frontier_by_id and identifier not in context_ids
            ]
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
            context_complete = bool(response.get("context_complete", True))
            context_unchanged = bool(previous_context_ids) and context_ids == previous_context_ids
            if current_depth >= self.depth:
                stop_reason = "maximum context rounds reached"
            elif not remaining_budget:
                stop_reason = "context function budget exhausted"
            elif requested:
                stop_reason = "open only the explicitly requested adjacent functions"
            elif context_complete:
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
                    f"{response.get('status', 'UNRESOLVED')} confidence={_confidence(response.get('confidence')):.2f}; "
                    f"requests={requested_names or ['none']}; {stop_reason}; "
                    f"reason={rationale[:240] or 'none'}"
                ),
                candidate_id=candidate.candidate_id,
                round=current_depth,
                model_status=str(response.get("status", "UNRESOLVED")),
                confidence=_confidence(response.get("confidence")),
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
                accepted_requested_functions=[
                    function_ref(self.graph.get(item)) for item in requested
                ],
                deferred_requested_function_ids=deferred_requests,
                already_supplied_requested_function_ids=already_supplied_requests,
                rejected_requested_function_ids=rejected_requests,
                context_unchanged=context_unchanged,
                stop_reason=stop_reason,
                model_response=response,
            )
            previous_context_ids = context_ids
            previous_response = {
                **response,
                "accepted_requested_function_ids": requested,
                "deferred_requested_function_ids": deferred_requests,
                "rejected_requested_function_ids": rejected_requests,
            }
            if current_depth >= self.depth or not remaining_budget:
                break
            if not requested:
                break
            for function_id in requested:
                choice = frontier_by_id[function_id]
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
        for raw_path_item in object_list(response.get("provenance_path")):
            identifier = str(raw_path_item.get("function_id", ""))
            if identifier in allowed_ids:
                provenance.append({"function_id": identifier, "relation": str(raw_path_item.get("relation", ""))})
            else:
                dropped_provenance.append(
                    {"item": raw_path_item, "reason": "function was outside the final supplied context"}
                )
        evidence: list[Evidence] = []
        dropped_evidence: list[dict[str, Any]] = []
        for raw_evidence_item in object_list(response.get("evidence")):
            evidence_function = self.graph.bundle.functions.get(
                str(raw_evidence_item.get("function_id", function.function_id))
            )
            if evidence_function is None or evidence_function.function_id not in allowed_ids:
                dropped_evidence.append(
                    {"item": raw_evidence_item, "reason": "function was missing or outside final context"}
                )
                continue
            parsed = evidence_from_dict(raw_evidence_item, evidence_function)
            if parsed.file != evidence_function.file:
                dropped_evidence.append({"item": raw_evidence_item, "reason": "evidence file did not match metadata"})
                continue
            if parsed.line is not None and not (
                evidence_function.start_line <= parsed.line <= evidence_function.end_line
            ):
                dropped_evidence.append({"item": item, "reason": "evidence line was outside function range"})
                continue
            evidence.append(parsed)
        evidence_fallback = False
        if not evidence:
            evidence = list(candidate.evidence)
            evidence_fallback = True
        unknowns = unique_strings(string_list(response.get("unknowns")))
        downgrade_reasons: list[str] = []
        verifier_confidence = _confidence(response.get("confidence"))
        first_acquisition_confirmed = response.get("first_acquisition_confirmed") is True
        if status is Verdict.VERIFIED and not first_acquisition_confirmed:
            status = Verdict.REJECTED
            unknowns.append("candidate was not confirmed as the first external acquisition site")
            downgrade_reasons.append(
                "VERIFIED was rejected because the site only consumes or forwards an already acquired value"
            )
        if status is Verdict.VERIFIED and verifier_confidence < MIN_VERIFIED_CONFIDENCE:
            status = Verdict.UNRESOLVED
            unknowns.append(
                f"verifier confidence {verifier_confidence:.2f} is below the definite-Entry threshold"
            )
            downgrade_reasons.append(
                "VERIFIED was downgraded because confidence was below the definite-Entry threshold"
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
        consumer_hints = unique_strings(
            identifier for identifier in string_list(response.get("consumer_hints"))
            if identifier in allowed_ids
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
            verifier_confidence=verifier_confidence,
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
        )
        record.validate()
        emit_trace(
            self.trace,
            "entry_verifier",
            "final_verdict",
            (
                f"{candidate.candidate_id}: {record.status} confidence={record.verifier_confidence:.2f}; "
                f"channel={record.channel_kind}; attacker_control={record.attacker_control}; "
                f"{record.rationale or 'no rationale'}"
            ),
            candidate_id=candidate.candidate_id,
            entry_id=record.entry_id,
            function=function_ref(function),
            model_status=str(response.get("status", "UNRESOLVED")),
            final_status=str(record.status),
            stop_reason=stop_reason,
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
