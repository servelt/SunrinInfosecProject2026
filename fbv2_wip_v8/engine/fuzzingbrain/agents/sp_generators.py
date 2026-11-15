"""
SP Generators

Agents for generating Suspicious Points (SP) in different scan modes:
- FullSPGenerator: Full-scan mode, analyzes individual functions
- LargeFullSPGenerator: Full-scan for large functions with sliding window
- DeltaSPGenerator: Delta-scan mode, analyzes code changes/diffs
"""

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastmcp import Client

from .base import BaseAgent
from .prompts import (
    FUNCTION_ANALYSIS_PROMPT,
    FIND_SUSPICIOUS_POINTS_PROMPT,
    SANITIZER_PATTERNS,
    ADDRESS_SANITIZER_GUIDANCE,
    MEMORY_SANITIZER_GUIDANCE,
    UNDEFINED_SANITIZER_GUIDANCE,
    GENERAL_SANITIZER_GUIDANCE,
)
from ..llms import LLMClient, ModelInfo
from ..core.models.agent import AgentType


_SECURITY_INVARIANT_ORDER = (
    "BOUNDS_EXTENT",
    "LIFETIME_OWNERSHIP",
    "ARITHMETIC_RANGE",
    "INITIALIZATION",
    "NULLABILITY",
    "STATE_CONSISTENCY",
)

# Public, target-independent campaign taxonomy.  Live admission may pin one
# family to measure (for example bounds first, lifetime in a later run) without
# pinning a function, source location, input, or known vulnerability.
SECURITY_INVARIANT_FAMILIES = _SECURITY_INVARIANT_ORDER


def _source_without_comments_and_literals(source: str) -> str:
    """Return a same-shape lexical view for generic risk classification."""
    value = source or ""
    output = []
    index = 0
    state = "code"
    while index < len(value):
        char = value[index]
        next_char = value[index + 1] if index + 1 < len(value) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                output.extend("  ")
                state = "line_comment"
                index += 2
                continue
            if char == "/" and next_char == "*":
                output.extend("  ")
                state = "block_comment"
                index += 2
                continue
            if char in ('"', "'"):
                output.append(" ")
                state = char
            else:
                output.append(char)
        elif state == "line_comment":
            output.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and next_char == "/":
                output.extend("  ")
                state = "code"
                index += 2
                continue
            output.append("\n" if char == "\n" else " ")
        else:
            if char == "\\" and next_char:
                output.extend((" ", "\n" if next_char == "\n" else " "))
                index += 2
                continue
            output.append("\n" if char == "\n" else " ")
            if char == state:
                state = "code"
        index += 1
    return "".join(output)


def _generic_security_surface(source: str, sanitizer: str) -> Dict[str, Any]:
    """Mechanically inventory sanitizer-relevant source features.

    This is deliberately target-agnostic.  It does not contain function names,
    source locations, known inputs, or vulnerability answers, and it is not a
    finding classifier.  Both scheduling and negative-analysis admission use
    the same inventory so breadth priority cannot silently diverge from the
    evidence contract.
    """
    lexical = _source_without_comments_and_literals(source)
    brace = lexical.find("{")
    signature = lexical[:brace] if brace >= 0 else lexical
    body = lexical[brace + 1:] if brace >= 0 else ""
    sanitizer_name = (sanitizer or "").lower()

    has_pointer_parameter = bool(re.search(
        r"\([^)]*\*[^)]*\)", signature, flags=re.S))
    indexed_accesses = re.findall(
        r"\b[A-Za-z_]\w*(?:\s*(?:->|\.)\s*[A-Za-z_]\w*)*\s*\[[^\]]+\]",
        body,
    )
    buffer_operations = re.findall(
        r"\b(?:memcpy|memmove|memset|memcmp|strcpy|strncpy|strcat|"
        r"strncat|snprintf|read|recv|send)\s*\(", body,
    )
    lifecycle_operations = re.findall(
        r"\b(?:malloc|calloc|realloc|free|new|delete)\b", body,
    )
    member_references = re.findall(
        r"\b([A-Za-z_]\w*)\s*(?:->|\.)\s*([A-Za-z_]\w*)", body)
    fields_by_root: Dict[str, set[str]] = {}
    for root, field in member_references:
        fields_by_root.setdefault(root, set()).add(field)
    # One member access is a pointer/nullability surface, but not by itself a
    # cross-field state invariant.  Requiring a repository-wide writer search
    # for every trivial getter was the dominant cost in the first live run.
    state_relationships = sum(
        max(0, len(fields) - 1) for fields in fields_by_root.values())

    indexed_expressions = re.findall(r"\[([^\]]+)\]", body)
    has_index_math = any(re.search(
        r"(?:\+|-|\*|/|%|<<|>>)", expression.replace("->", ""))
        for expression in indexed_expressions)
    size_math = re.findall(
        r"\b(?:malloc|calloc|realloc|memcpy|memmove|memset|read|recv|send)"
        r"\s*\([^;\n]*(?:\+|-|\*|/|%|<<|>>)[^;\n]*\)", body,
    )
    arithmetic_operations = re.findall(
        r"(?:\+\+|--|<<|>>|(?<![+])\+(?![+=])|(?<!-)\-(?![-=>])|"
        r"(?<!/)\/(?![=*/])|%(?!=))",
        body,
    )
    # A bare ``*`` is ambiguous in C: it can be multiplication, a pointer
    # declarator, or unary dereference.  Requiring a left operand keeps the
    # inexpensive lexical scheduler from classifying ``return *p;`` as an
    # ARITHMETIC_RANGE surface.  This remains a ranking hint, not a parser or
    # vulnerability judgment.
    multiplication_matches = re.finditer(
        r"(?P<left>\b(?:[A-Za-z_]\w*|\d+)|[)\]])\s*\*(?![=/])\s*"
        r"(?=(?:[A-Za-z_(]|\d))",
        body,
    )
    non_operands = {
        "return", "sizeof", "alignof", "_Alignof", "case",
        "char", "short", "int", "long", "float", "double", "void",
        "signed", "unsigned", "const", "volatile", "struct", "union",
        "enum", "auto", "register", "static", "extern", "typedef",
    }
    def cast_precedes_star(match: re.Match[str]) -> bool:
        """Recognize common C casts so ``(int) *p`` stays unary.

        Parenthesized expressions such as ``(a) * b`` deliberately do not
        match this type-shaped grammar and remain multiplication surfaces.
        """
        star_at = body.find("*", match.start(), match.end())
        cursor = star_at - 1
        while cursor >= 0 and body[cursor].isspace():
            cursor -= 1
        if cursor < 0 or body[cursor] != ")":
            return False
        close_at = cursor
        depth = 1
        cursor -= 1
        while cursor >= 0 and depth:
            if body[cursor] == ")":
                depth += 1
            elif body[cursor] == "(":
                depth -= 1
            cursor -= 1
        if depth:
            return False
        cast_text = body[cursor + 2:close_at].strip()
        tokens = re.findall(r"[A-Za-z_]\w*|\*", cast_text)
        if not tokens or "".join(tokens) != re.sub(r"\s+", "", cast_text):
            return False
        words = [token for token in tokens if token != "*"]
        cv_qualifiers = {"const", "volatile", "restrict", "_Atomic"}
        builtin_specifiers = {
            "void", "char", "short", "int", "long", "float", "double",
            "signed", "unsigned", "_Bool", "_Complex", "_Imaginary",
            "__int128",
        }
        if (any(word in builtin_specifiers for word in words) and
                all(word in builtin_specifiers | cv_qualifiers
                    for word in words)):
            return True
        significant = [word for word in words if word not in cv_qualifiers]
        if (len(significant) == 2 and
                significant[0] in {"struct", "union", "enum"}):
            return True
        if len(significant) == 1:
            typedef_name = significant[0]
            return (len(words) > 1 or
                    typedef_name in {"size_t", "ssize_t"} or
                    re.fullmatch(r"u?int(?:8|16|32|64)_t", typedef_name)
                    is not None or
                    typedef_name.endswith("_t") or
                    typedef_name[:1].isupper())
        return False

    multiplication_operations = [
        match.group(0) for match in multiplication_matches
        if (match.group("left") not in non_operands and
            not cast_precedes_star(match))
    ]
    arithmetic_operations.extend(multiplication_operations)
    possible_uninitialized_locals = re.findall(
        r"(?:^|[;{}])\s*(?:unsigned\s+|signed\s+|const\s+|volatile\s+)*"
        r"(?:char|short|int|long|float|double|size_t|[A-Z][A-Z0-9_]*)"
        r"(?:\s*\*?\s*)[A-Za-z_]\w*\s*;",
        body,
        flags=re.M,
    )

    has_member_access = bool(member_references)
    has_indexed_access = bool(indexed_accesses)
    has_buffer_operation = bool(buffer_operations)
    has_lifecycle_operation = bool(lifecycle_operations)
    has_pointer_surface = (
        has_pointer_parameter or has_member_access or has_indexed_access or
        has_buffer_operation or has_lifecycle_operation
    )
    has_general_arithmetic = bool(arithmetic_operations)

    kinds: List[str] = []
    if has_indexed_access or has_buffer_operation:
        kinds.append("BOUNDS_EXTENT")
    if "address" in sanitizer_name and has_pointer_surface:
        kinds.append("LIFETIME_OWNERSHIP")
    if (("undefined" in sanitizer_name and has_general_arithmetic) or
            has_index_math or size_math):
        kinds.append("ARITHMETIC_RANGE")
    if "memory" in sanitizer_name:
        kinds.append("INITIALIZATION")
    if (("address" in sanitizer_name or "undefined" in sanitizer_name) and
            has_pointer_surface):
        kinds.append("NULLABILITY")
    if state_relationships:
        kinds.append("STATE_CONSISTENCY")

    return {
        "kinds": [kind for kind in _SECURITY_INVARIANT_ORDER if kind in kinds],
        "indexed_accesses": len(indexed_accesses),
        "buffer_operations": len(buffer_operations),
        "lifecycle_operations": len(lifecycle_operations),
        "arithmetic_operations": len(arithmetic_operations),
        "possible_uninitialized_locals": len(possible_uninitialized_locals),
        "state_relationships": state_relationships,
        "pointer_parameter": has_pointer_parameter,
    }


def generic_security_risk_priority(source: str, sanitizer: str) -> Dict[str, Any]:
    """Return an auditable, target-independent breadth-scheduling priority."""
    surface = _generic_security_surface(source, sanitizer)
    kind_weights = {
        "BOUNDS_EXTENT": 8,
        "LIFETIME_OWNERSHIP": 8,
        "ARITHMETIC_RANGE": 7,
        "INITIALIZATION": 8,
        "NULLABILITY": 3,
        "STATE_CONSISTENCY": 6,
    }
    score = sum(kind_weights[kind] for kind in surface["kinds"])
    score += min(surface["indexed_accesses"], 8) * 3
    score += min(surface["buffer_operations"], 4) * 4
    score += min(surface["lifecycle_operations"], 4) * 4
    score += min(surface["arithmetic_operations"], 8)
    score += min(surface["possible_uninitialized_locals"], 4) * 4
    score += min(surface["state_relationships"], 6) * 2
    if surface["pointer_parameter"]:
        score += 1
    return {**surface, "score": score}


def generic_security_family_priority(
    source: str, sanitizer: str, family: str,
) -> Dict[str, Any]:
    """Rank source for one pre-registered invariant family.

    The score is only a breadth scheduler.  It cannot create, verify, or
    credit a Suspicious Point.  Keeping the family explicit also permits
    comparable later campaigns for lifetime, arithmetic, or initialization
    bugs without changing target-specific code.
    """
    if family not in SECURITY_INVARIANT_FAMILIES:
        raise ValueError("unknown security invariant family")
    surface = _generic_security_surface(source, sanitizer)
    present = family in surface["kinds"]
    if family == "BOUNDS_EXTENT":
        score = (12 if present else 0)
        score += min(surface["indexed_accesses"], 12) * 4
        score += min(surface["buffer_operations"], 6) * 5
        score += min(surface["arithmetic_operations"], 8)
    elif family == "LIFETIME_OWNERSHIP":
        score = (12 if present else 0)
        score += min(surface["lifecycle_operations"], 8) * 6
        score += min(surface["state_relationships"], 4) * 2
        score += 2 if surface["pointer_parameter"] else 0
    elif family == "ARITHMETIC_RANGE":
        score = (12 if present else 0)
        score += min(surface["arithmetic_operations"], 16) * 2
        score += min(surface["indexed_accesses"], 6) * 2
        score += min(surface["buffer_operations"], 4) * 2
    elif family == "INITIALIZATION":
        score = (12 if present else 0)
        score += min(surface["possible_uninitialized_locals"], 12) * 6
        score += min(surface["state_relationships"], 4)
    elif family == "NULLABILITY":
        score = (12 if present else 0)
        score += 4 if surface["pointer_parameter"] else 0
        score += min(surface["indexed_accesses"], 6) * 2
        score += min(surface["buffer_operations"], 4) * 2
        score += min(surface["lifecycle_operations"], 4) * 2
    else:  # STATE_CONSISTENCY
        score = (12 if present else 0)
        score += min(surface["state_relationships"], 12) * 5
        score += min(surface["arithmetic_operations"], 6)
    return {**surface, "family": family, "family_score": score}


class SPGeneratorBase(BaseAgent):
    """
    Base class for SP generation agents.

    Provides common functionality:
    - Sanitizer pattern detection
    - SP creation tracking
    - Tool filtering for generation mode
    """

    # Tool names
    TOOL_CREATE_SUSPICIOUS_POINT = "create_suspicious_point"
    TOOL_GET_FUNCTION_SOURCE = "get_function_source"

    # Lower temperature for focused analysis
    default_temperature: float = 0.5

    @property
    def agent_type(self) -> str:
        """SP Generator type."""
        return "spg"

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "address",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 5,
        verbose: bool = True,
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        index: int = 0,
        target_name: str = "",
    ):
        super().__init__(
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=verbose,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
            index=index,
            target_name=target_name,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
        )

        # Track results
        self.sp_created = False
        self.sp_details: Optional[Dict] = None
        self.created_sp_ids: set[str] = set()
        self.sp_create_attempted = False
        self.sp_persistence_failed = False
        self.sp_persistence_error: Optional[str] = None

    async def _execute_audited_tool(
        self, client, response, tool_call, tool_name, tool_args,
    ):
        """Fail only after the campaign gate has settled the tool result.

        A failed candidate write is not a valid negative security result.  It
        must stop the function immediately, but raising inside ``_execute_tool``
        would incorrectly audit the already-returned MCP result as a transport
        error.  The shared audited wrapper records the completed result first;
        this outer hook then turns the persistence failure into an explicit
        campaign-incomplete reason.
        """
        result = await super()._execute_audited_tool(
            client, response, tool_call, tool_name, tool_args)
        if (tool_name == self.TOOL_CREATE_SUSPICIOUS_POINT and
                self.sp_persistence_failed):
            self.stop_reason = "sp_persistence_failure"
            exc = RuntimeError(
                self.sp_persistence_error or
                "suspicious point persistence failed")
            exc.fbv2_stop_reason = "sp_persistence_failure"
            raise exc
        return result

    def _is_address_sanitizer(self) -> bool:
        """Check if current sanitizer is AddressSanitizer."""
        return "address" in self.sanitizer.lower()

    def _is_memory_sanitizer(self) -> bool:
        """Check if current sanitizer is MemorySanitizer."""
        return "memory" in self.sanitizer.lower()

    def _is_undefined_sanitizer(self) -> bool:
        """Check if current sanitizer is UndefinedBehaviorSanitizer."""
        return "undefined" in self.sanitizer.lower()

    def _get_sanitizer_vuln_types(self) -> str:
        """Get vulnerability types detectable by current sanitizer."""
        if self._is_address_sanitizer():
            return "Buffer overflows, OOB access, use-after-free, double-free"
        elif self._is_memory_sanitizer():
            return "Uninitialized memory reads"
        elif self._is_undefined_sanitizer():
            return "Integer overflow, null deref, div-by-zero"
        return "General memory corruption issues"

    def _get_sanitizer_guidance(self) -> str:
        """Get sanitizer-specific vulnerability patterns guidance."""
        if self._is_address_sanitizer():
            return ADDRESS_SANITIZER_GUIDANCE
        elif self._is_memory_sanitizer():
            return MEMORY_SANITIZER_GUIDANCE
        elif self._is_undefined_sanitizer():
            return UNDEFINED_SANITIZER_GUIDANCE
        else:
            return GENERAL_SANITIZER_GUIDANCE

    def _get_sanitizer_patterns(self) -> str:
        """Get sanitizer-specific patterns for prompts."""
        sanitizer_lower = self.sanitizer.lower()
        for key, patterns in SANITIZER_PATTERNS.items():
            if key in sanitizer_lower:
                return patterns
        return SANITIZER_PATTERNS["address"]

    def _filter_tools_for_mode(
        self, tools: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Filter tools for SP generation mode.

        Allow:
        - create_suspicious_point: main output
        - get_function_source: read code
        - get_callers/get_callees: call graph exploration
        - search_code: find shared-state writers outside the caller chain
        - get_diff: for delta mode

        Exclude:
        - update_suspicious_point: verification only
        - find_all_paths, check_reachability: too slow
        """
        allowed = {
            "create_suspicious_point",
            "get_function_source",
            "get_callers",
            "get_callees",
            "search_code",
            "get_diff",
        }
        return [t for t in tools if t.get("function", {}).get("name") in allowed]

    async def _get_tools(self, client) -> List[Dict[str, Any]]:
        """Get tools from MCP server, filtered for generation mode."""
        all_tools = await super()._get_tools(client)
        return self._filter_tools_for_mode(all_tools)

    async def _execute_tool(
        self,
        client: Client,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        """Execute tool and track SP creation."""
        result = await super()._execute_tool(client, tool_name, tool_args)

        if tool_name == self.TOOL_CREATE_SUSPICIOUS_POINT:
            self.sp_create_attempted = True
            try:
                data = json.loads(result)
                if not isinstance(data, dict):
                    raise TypeError("persistence receipt must be a JSON object")
                created_id = data.get("suspicious_point_id") or data.get("id")
                persisted = bool(
                    data.get("success") is True and
                    isinstance(created_id, str) and created_id and
                    ((data.get("created") is True and
                      data.get("merged") is not True) or
                     (data.get("merged") is True and
                      data.get("created") is not True))
                )
                if persisted:
                    self.sp_created = True
                    self.created_sp_ids.add(created_id)
                    self.sp_details = {
                        "function_name": tool_args.get("function_name", ""),
                        "vuln_type": tool_args.get("vuln_type", "unknown"),
                        "score": tool_args.get("score", 0.5),
                        "description": tool_args.get("description", ""),
                        # The create tool returns ``id``; keep the legacy key
                        # for adapters that still expose it.
                        "sp_id": created_id,
                    }
                    self._log(
                        f"SP created: {self.sp_details['function_name']}", level="INFO"
                    )

                    # Update context if available
                    if self._context:
                        self._context.sp_created = True
                        self._context.sp_details = self.sp_details
                else:
                    self.sp_persistence_failed = True
                    error = (data.get("error") if isinstance(data, dict)
                             else None)
                    self.sp_persistence_error = (
                        error if isinstance(error, str) and error else
                        "create_suspicious_point returned no persistence receipt")
            except (json.JSONDecodeError, TypeError) as exc:
                self.sp_persistence_failed = True
                self.sp_persistence_error = (
                    "create_suspicious_point returned invalid persistence "
                    f"receipt: {type(exc).__name__}")

        return result

    def _get_compression_criteria(self) -> str:
        return (
            "Preserve the host-validated local risk inventory, its exact "
            "target-source quotes, every caller relationship, and the cumulative bounds, "
            "lifetime, arithmetic, initialization, nullability, ownership, "
            "and shared-state provenance established so far. Preserve every "
            "invariant-ledger row, the current unresolved frontier, and exact "
            "function names. Never turn missing evidence into a negative "
            "safety conclusion."
        )

    def _durable_analysis_index(self) -> str:
        """Build a deterministic query index that lossy compression cannot erase."""
        seen: set[tuple[str, str]] = set()
        entries: List[str] = []
        for item in self.analysis_tool_history:
            if item.get("successful") is not True:
                continue
            name = item.get("name")
            arguments = item.get("arguments", {})
            if name == "search_code":
                query = arguments.get("pattern") or arguments.get("query")
                if not isinstance(query, str) or not query:
                    continue
                key = (name, query)
                if key in seen:
                    continue
                seen.add(key)
                entry = f"- search_code({query})"
                if item.get("result_search_truncated") is True:
                    entry += " (TRUNCATED)"
                evidence_rows = item.get("result_search_evidence")
                if isinstance(evidence_rows, list):
                    entry += f" [EVIDENCE_ROWS={len(evidence_rows)}]"
                entries.append(entry)
                continue
            function_name = arguments.get("function_name")
            if name not in {"get_callers", "get_callees", "get_function_source"}:
                continue
            if not isinstance(function_name, str) or not function_name:
                continue
            key = (name, function_name)
            if key in seen:
                continue
            seen.add(key)
            entry = f"- {name}({function_name})"
            if name == "get_callers" and isinstance(
                    item.get("result_callers"), list):
                entry += " => [" + ", ".join(item["result_callers"]) + "]"
                if item.get("result_callers_truncated") is True:
                    entry += " (TRUNCATED)"
            entries.append(entry)
        return (
            "FBV2_DURABLE_ANALYSIS_INDEX\n"
            "These exact read-only queries already completed. Do not request "
            "them again. Use the retained evidence summary and continue from "
            "the unresolved security-invariant frontier.\n" +
            ("\n".join(entries) if entries else "- (none)")
        )

    async def _compress_context(self) -> None:
        """Preserve exact evidence whenever it fits the existing bridge cap."""
        payload_cap = getattr(self.llm_client, "max_payload_chars", None)
        if self.require_context_sufficiency and type(payload_cap) is int:
            projected = {
                "history": [row for row in self.messages
                            if row.get("role") != "system"],
                # The bridge's converted tool representation is smaller; this
                # source representation therefore gives a conservative bound.
                "tools": self._tools,
                "tool_choice": "auto",
            }
            if len(json.dumps(projected, ensure_ascii=False)) <= payload_cap:
                self._log(
                    "Skipping lossy compression: exact evidence fits payload cap",
                    level="INFO",
                )
                return
        await super()._compress_context()
        if self.require_context_sufficiency and self.analysis_tool_history:
            inventory = json.dumps(
                self.local_risk_inventory,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            self.messages.append({
                "role": "user",
                "content": (
                    "FBV2_HOST_EVIDENCE_CHECKPOINT\n"
                    "Exact host-validated local risk inventory:\n" +
                    inventory + "\n" + self._durable_analysis_index() +
                    "\nLossy compression occurred. Treat evidence absent "
                    "from the retained transcript as unresolved; never infer "
                    "a negative conclusion from its absence."
                ),
            })


class FullSPGenerator(SPGeneratorBase):
    """
    Full-scan SP Generator.

    Analyzes individual functions to find suspicious points.
    Each function gets its own agent session with minimal context.

    Design:
    - One function = one agent session
    - Minimal context: function source + caller/callee info
    - Token efficient: no historical context between functions
    - Parallelizable: multiple instances can run simultaneously
    """

    TOOL_RECORD_LOCAL_RISK_INVENTORY = "record_local_risk_inventory"
    _LOCAL_RISK_STATUSES = {
        "SUSPICIOUS", "REQUIRES_CONTEXT", "LOCALLY_GUARDED",
    }

    def __init__(
        self,
        # Target function info
        function_name: str,
        function_source: str,
        function_file: str = "",
        function_lines: tuple = (0, 0),
        # Context - pre-extracted for efficiency
        callers: List[str] = None,
        callees: List[str] = None,
        fuzzer_source: str = "",
        caller_sources: Dict[str, str] = None,
        # Analysis settings
        fuzzer: str = "",
        sanitizer: str = "address",
        direction_id: str = "",
        # Agent config
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 5,
        verbose: bool = True,
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        index: int = 0,
        require_context_sufficiency: bool = False,
    ):
        """
        Initialize Full SP Generator.

        Args:
            function_name: Name of function to analyze
            function_source: Full source code of the function
            function_file: File path containing the function
            function_lines: (start_line, end_line) tuple
            callers: List of caller function names
            callees: List of callee function names
            fuzzer_source: Pre-extracted fuzzer source code
            caller_sources: Dict mapping caller name to source code
            fuzzer: Fuzzer name
            sanitizer: Sanitizer type
            direction_id: Direction ID (for tracking)
        """
        super().__init__(
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=verbose,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
            index=index,
            target_name=function_name,
        )

        self.function_name = function_name
        self.function_source = function_source
        self.function_file = function_file
        self.function_lines = function_lines
        self.callers = callers or []
        self.callees = callees or []
        self.fuzzer_source = fuzzer_source
        self.caller_sources = caller_sources or {}
        # The user message renders at most 1,500 bytes per preloaded caller.
        # A longer body may help orient the model, but it is not evidence that
        # the complete function was inspected.  Keep the two concepts separate
        # so negative-completion accounting cannot credit bytes never shown.
        self._complete_preloaded_caller_sources = {
            name: source for name, source in self.caller_sources.items()
            if isinstance(source, str) and 0 < len(source) <= 1500
        }
        self.direction_id = direction_id
        self.require_context_sufficiency = require_context_sufficiency
        self.analysis_tool_history: List[Dict[str, Any]] = []
        self.local_risk_inventory: List[Dict[str, Any]] = []
        self.local_risk_inventory_valid = not require_context_sufficiency
        self.analysis_completion: Dict[str, Any] = {
            "analysis_result": "UNKNOWN",
            "context_sufficiency": "UNKNOWN",
            "pointer_length_provenance": "UNKNOWN",
            "shared_state_writer_search": "UNKNOWN",
            "security_invariants": [],
            "shared_storage_helpers": [],
            "evidence_functions": [],
            "writer_evidence_functions": [],
            "unresolved_preconditions": [],
            "valid": not require_context_sufficiency,
        }

        # Log buffer for batch writing
        self._log_buffer: List[str] = []
        self._log_to_buffer = True

    async def _get_tools(self, client) -> List[Dict[str, Any]]:
        """Add a host-only local-analysis checkpoint to strict SP runs."""
        tools = await super()._get_tools(client)
        if not self.require_context_sufficiency:
            return tools
        tools.append({
            "type": "function",
            "function": {
                "name": self.TOOL_RECORD_LOCAL_RISK_INVENTORY,
                "description": (
                    "Record concrete sanitizer-relevant operations found in "
                    "the target function before requesting caller/callee "
                    "context. This is an analysis checkpoint, not a finding."
                ),
                "parameters": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "target_function": {"type": "string"},
                        "operations": {
                            "type": "array",
                            "minItems": 0,
                            "maxItems": 24,
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {
                                    "kind": {
                                        "type": "string",
                                        "enum": list(SECURITY_INVARIANT_FAMILIES),
                                    },
                                    "subject": {"type": "string"},
                                    "source_quote": {"type": "string"},
                                    "local_status": {
                                        "type": "string",
                                        "enum": sorted(self._LOCAL_RISK_STATUSES),
                                    },
                                    "missing_preconditions": {
                                        "type": "array",
                                        "items": {"type": "string"},
                                    },
                                },
                                "required": [
                                    "kind", "subject", "source_quote",
                                    "local_status", "missing_preconditions",
                                ],
                            },
                        },
                    },
                    "required": ["target_function", "operations"],
                },
            },
        })
        return tools

    @staticmethod
    def _normalized_source_fragment(value: str) -> str:
        return " ".join((value or "").split())

    def _record_local_risk_inventory(
        self, tool_args: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate and retain the target-local risk ledger.

        The host checks only identity, source binding, and coverage of the
        mechanically derived invariant families. It does not manufacture or
        approve a vulnerability finding.
        """
        if tool_args.get("target_function") != self.function_name:
            return {"success": False, "error": "target_function mismatch"}
        operations = tool_args.get("operations")
        if not isinstance(operations, list) or len(operations) > 24:
            return {"success": False, "error": "operations must contain 0..24 rows"}
        normalized_source = self._normalized_source_fragment(self.function_source)
        required = set(self._required_security_invariant_kinds())
        if required and not operations:
            return {"success": False,
                    "error": "operations cannot be empty for required kinds"}
        seen: set[str] = set()
        retained: List[Dict[str, Any]] = []
        for row in operations:
            if not isinstance(row, dict):
                return {"success": False, "error": "operation row must be an object"}
            kind = row.get("kind")
            subject = row.get("subject")
            quote = row.get("source_quote")
            local_status = row.get("local_status")
            missing = row.get("missing_preconditions")
            if kind not in SECURITY_INVARIANT_FAMILIES:
                return {"success": False, "error": "unknown invariant kind"}
            if not isinstance(subject, str) or not subject.strip():
                return {"success": False, "error": "subject is required"}
            if not isinstance(quote, str) or not quote.strip():
                return {"success": False, "error": "source_quote is required"}
            normalized_quote = self._normalized_source_fragment(quote)
            if normalized_quote not in normalized_source:
                return {"success": False, "error": "source_quote is not in target source"}
            if local_status not in self._LOCAL_RISK_STATUSES:
                return {"success": False, "error": "invalid local_status"}
            if (not isinstance(missing, list) or
                    not all(isinstance(item, str) and item.strip()
                            for item in missing)):
                return {"success": False,
                        "error": "missing_preconditions must be non-empty strings"}
            retained.append({
                "kind": kind,
                "subject": subject.strip(),
                "source_quote": quote.strip(),
                "local_status": local_status,
                "missing_preconditions": [item.strip() for item in missing],
            })
            seen.add(kind)
        missing_kinds = sorted(required - seen)
        if missing_kinds:
            return {
                "success": False,
                "error": "required invariant kinds are missing",
                "missing_kinds": missing_kinds,
            }
        self.local_risk_inventory = retained
        self.local_risk_inventory_valid = True
        suspicious_count = sum(
            row["local_status"] == "SUSPICIOUS" for row in retained)
        return {
            "success": True,
            "recorded": True,
            "required_kinds": sorted(required),
            "operation_count": len(retained),
            "suspicious_count": suspicious_count,
            "next_step": (
                "Create a suspicious point now for each source-bound "
                "SUSPICIOUS operation. Reachability and external-precondition "
                "certainty belong to the verifier; use a lower score when "
                "they are uncertain."
                if suspicious_count else
                "Create a suspicious point for a concrete local risk, or use "
                "the remaining evidence turns only for a listed precondition."
            ),
        }

    def _has_unemitted_suspicious_local_risk(self) -> bool:
        """Return whether discovery found a risk that must reach verification.

        The inventory is source-bound by the host. Once the discovery model
        labels one of those exact operations SUSPICIOUS, requiring that same
        model to prove caller reachability, ownership, or global writer
        invariants before it may emit a candidate duplicates the verifier and
        defeats the high-recall funnel. This predicate never manufactures a
        finding from REQUIRES_CONTEXT alone.
        """
        anchors = {
            (self._normalized_source_fragment(row.get("source_quote", "")),
             self._normalized_source_fragment(row.get("subject", "")))
            for row in self.local_risk_inventory
            if row.get("local_status") == "SUSPICIOUS"
        }
        return len(self.created_sp_ids) < len(anchors)

    def _tools_for_iteration(
        self,
        iteration: int,
        remaining: int,
    ) -> List[Dict[str, Any]]:
        """Reserve the first turn for local analysis and the last for decision."""
        tools = super()._tools_for_iteration(iteration, remaining)
        if not self.require_context_sufficiency:
            return tools
        if not self.local_risk_inventory_valid:
            allowed = {
                self.TOOL_RECORD_LOCAL_RISK_INVENTORY,
                self.TOOL_CREATE_SUSPICIOUS_POINT,
            }
            return [row for row in tools
                    if row.get("function", {}).get("name") in allowed]
        if self._has_unemitted_suspicious_local_risk():
            # Candidate discovery stops doing verifier work at this boundary.
            # The model still authors the candidate; the host only restricts
            # the next action to the existing, source-bound creation tool.
            return [row for row in tools if row.get("function", {}).get("name") ==
                    self.TOOL_CREATE_SUSPICIOUS_POINT]
        # This agent is the high-recall discovery stage, not a second
        # verifier.  Once the complete target body has been inventoried, do
        # not spend the remaining campaign on proving a negative through
        # callers, ownership, or repository-wide writers.  The next response
        # must either author a concrete candidate or settle the local screen
        # honestly (normally INSUFFICIENT when an external fact is missing).
        # Initial caller/fuzzer context remains available in the prompt; only
        # additional read-only exploration is closed here.
        return [row for row in tools if row.get("function", {}).get("name") ==
                self.TOOL_CREATE_SUSPICIOUS_POINT]

    def _get_urgency_message(self, iteration: int, remaining: int) -> Optional[str]:
        if not self.require_context_sufficiency:
            return super()._get_urgency_message(iteration, remaining)
        if self._has_unemitted_suspicious_local_risk():
            return (
                "CANDIDATE-FIRST HANDOFF. The host-validated local inventory "
                "contains a SUSPICIOUS source-bound operation. Create the "
                "suspicious point now. Do not require proof of reachability, "
                "caller provenance, ownership, or repository-wide writer "
                "closure here; the Verifier evaluates those facts. Use a "
                "lower score for uncertainty."
            )
        if self.local_risk_inventory_valid:
            return (
                "CANDIDATE-SCREEN DECISION. Read-only context tools are unavailable. "
                "For a concrete sanitizer-detectable risk in the target function, "
                "call create_suspicious_point (use a lower score when reachability "
                "or an external precondition is uncertain). Otherwise return the "
                "required completion receipt. Mark unresolved external facts "
                "INSUFFICIENT; this is a local no-candidate screen, not a proof that "
                "the function or repository is safe. Missing context alone is not a "
                "suspicious point."
            )
        return None

    async def _execute_tool(
        self, client: Client, tool_name: str, tool_args: Dict[str, Any]
    ) -> str:
        """Record the read-only evidence requested during this analysis."""
        if tool_name == self.TOOL_RECORD_LOCAL_RISK_INVENTORY:
            result = self._record_local_risk_inventory(tool_args)
            if self._context:
                self._context.increment_tool_calls()
            self.analysis_tool_history.append({
                "name": tool_name,
                "arguments": dict(tool_args),
                "successful": result.get("success") is True,
                "result_callers": [],
                "result_callers_truncated": False,
            })
            return json.dumps(result, sort_keys=True)
        result = await super()._execute_tool(client, tool_name, tool_args)
        successful = False
        result_callers: List[str] = []
        result_callers_truncated = False
        result_search_truncated = False
        result_search_evidence: List[str] = []
        result_source = ""
        try:
            payload = json.loads(result)
            successful = isinstance(payload, dict) and payload.get("success") is True
            if (successful and tool_name == "get_callers" and
                    isinstance(payload.get("callers"), list) and
                    all(isinstance(item, str) and item
                        for item in payload["callers"])):
                result_callers = list(payload["callers"])
                result_callers_truncated = payload.get("truncated") is True
            if successful and tool_name == "search_code":
                result_search_truncated = payload.get("truncated") is True
                matches = payload.get("matches")
                if isinstance(matches, list):
                    evidence_rows: List[str] = []
                    for match in matches[:64]:
                        if not isinstance(match, dict):
                            continue
                        values = [match.get("content")]
                        context = match.get("context")
                        if isinstance(context, list):
                            values.extend(context[:16])
                        for value in values:
                            if isinstance(value, str) and value.strip():
                                normalized = self._normalized_source_fragment(
                                    value[:4096])
                                if normalized and normalized not in evidence_rows:
                                    evidence_rows.append(normalized)
                    result_search_evidence = evidence_rows[:256]
            if (successful and tool_name == "get_function_source" and
                    payload.get("function_name") == tool_args.get("function_name") and
                    isinstance(payload.get("source"), str)):
                result_source = payload["source"]
        except (json.JSONDecodeError, TypeError):
            pass
        self.analysis_tool_history.append({
            "name": tool_name,
            "arguments": dict(tool_args),
            "successful": successful,
            "result_callers": result_callers,
            "result_callers_truncated": result_callers_truncated,
            "result_search_truncated": result_search_truncated,
            "result_search_evidence": result_search_evidence,
            "result_source": result_source,
        })
        return result

    def _has_pointer_length_precondition(self) -> bool:
        """Conservatively recognize pointer+length parameter contracts.

        This is only an admission guard for a negative conclusion. It is not a
        vulnerability detector and it never creates an SP.
        """
        source = self.function_source or ""
        brace = source.find("{")
        if brace < 0:
            return False
        signature, body = source[:brace], source[brace + 1:]
        match = re.search(r"\((.*)\)", signature, flags=re.S)
        if not match:
            return False
        params = [part.strip() for part in match.group(1).split(",")]
        pointer_names: List[str] = []
        count_names: List[str] = []
        for param in params:
            identifiers = re.findall(r"[A-Za-z_]\w*", param)
            if not identifiers:
                continue
            name = identifiers[-1]
            is_pointer = "*" in param or "[" in param
            if is_pointer:
                pointer_names.append(name)
            # A pointer named ``n`` is not simultaneously its own extent.
            # Negative-analysis provenance is required only when a distinct
            # scalar count/length parameter accompanies a pointer parameter.
            elif re.search(
                    r"(?:^|_)(?:n|num|count|len|length|size)(?:_|$)",
                    name, flags=re.I):
                count_names.append(name)
        pointer_used = any(re.search(
            rf"\b{re.escape(name)}\s*(?:\[|\+|->)", body)
            for name in pointer_names)
        count_used = any(re.search(rf"\b{re.escape(name)}\b", body)
                         for name in count_names)
        return bool(pointer_names and count_names and pointer_used and count_used)

    @staticmethod
    def _source_without_comments_and_literals(source: str) -> str:
        """Return a same-shape lexical view for conservative risk detection."""
        return _source_without_comments_and_literals(source)

    def _required_security_invariant_kinds(self) -> List[str]:
        """Derive generic negative-analysis lenses from source and sanitizer.

        This inventory does not identify a vulnerable line and never creates an
        SP.  It only prevents a negative conclusion from silently ignoring an
        applicable class of precondition.
        """
        return list(_generic_security_surface(
            self.function_source or "", self.sanitizer)["kinds"])

    @staticmethod
    def _completion_object(response: str) -> Optional[Dict[str, Any]]:
        marker = "FBV2_ANALYSIS_COMPLETION"
        marker_at = (response or "").rfind(marker)
        if marker_at < 0:
            return None
        tail = response[marker_at + len(marker):]
        object_at = tail.find("{")
        if object_at < 0:
            return None
        try:
            value, _ = json.JSONDecoder().raw_decode(tail[object_at:])
        except (json.JSONDecodeError, TypeError):
            return None
        return value if isinstance(value, dict) else None

    def _assess_analysis_completion(self, response: str) -> Dict[str, Any]:
        """Validate the model's scoped negative-analysis receipt."""
        if self.sp_created and not self._has_unemitted_suspicious_local_risk():
            return {
                "analysis_result": "SP_FOUND",
                "context_sufficiency": "UNKNOWN",
                "pointer_length_provenance": "UNKNOWN",
                "shared_state_writer_search": "UNKNOWN",
                "security_invariants": [],
                "shared_storage_helpers": [],
                "evidence_functions": [],
                "writer_evidence_functions": [],
                "unresolved_preconditions": [],
                "valid": True,
                "local_risk_inventory_valid": self.local_risk_inventory_valid,
                "local_risk_inventory": list(self.local_risk_inventory),
            }
        if not self.require_context_sufficiency:
            return {
                "analysis_result": "ANALYZED_NO_SP",
                "context_sufficiency": "UNKNOWN",
                "pointer_length_provenance": "UNKNOWN",
                "shared_state_writer_search": "UNKNOWN",
                "security_invariants": [],
                "shared_storage_helpers": [],
                "evidence_functions": [],
                "writer_evidence_functions": [],
                "unresolved_preconditions": [],
                "valid": True,
                "local_risk_inventory_valid": self.local_risk_inventory_valid,
                "local_risk_inventory": list(self.local_risk_inventory),
            }
        value = self._completion_object(response)
        if value is None:
            return {
                "analysis_result": "ANALYSIS_INCOMPLETE",
                "context_sufficiency": "UNKNOWN",
                "pointer_length_provenance": "UNKNOWN",
                "shared_state_writer_search": "UNKNOWN",
                "security_invariants": [],
                "shared_storage_helpers": [],
                "evidence_functions": [],
                "writer_evidence_functions": [],
                "unresolved_preconditions": ["completion receipt missing"],
                "valid": False,
            }
        result = value.get("analysis_result")
        sufficiency = value.get("context_sufficiency")
        provenance = value.get("pointer_length_provenance")
        writer_search = value.get("shared_state_writer_search")
        security_invariants = value.get("security_invariants")
        storage_helpers = value.get("shared_storage_helpers")
        evidence = value.get("evidence_functions")
        writer_evidence = value.get("writer_evidence_functions")
        unresolved = value.get("unresolved_preconditions")
        shape_valid = (
            result == "ANALYZED_NO_SP" and
            sufficiency in {"SUFFICIENT", "INSUFFICIENT"} and
            provenance in {"ESTABLISHED", "UNRESOLVED", "NOT_APPLICABLE"} and
            writer_search in {"ESTABLISHED", "UNRESOLVED", "NOT_APPLICABLE"} and
            isinstance(security_invariants, list) and
            all(isinstance(row, dict) and
                row.get("kind") in {
                    "BOUNDS_EXTENT", "LIFETIME_OWNERSHIP",
                    "ARITHMETIC_RANGE", "INITIALIZATION", "NULLABILITY",
                    "STATE_CONSISTENCY"
                } and
                isinstance(row.get("subject"), str) and
                bool(row.get("subject")) and
                row.get("status") in {
                    "ESTABLISHED", "UNRESOLVED", "NOT_APPLICABLE"
                } and
                isinstance(row.get("evidence_functions"), list) and
                all(isinstance(name, str) and name
                    for name in row["evidence_functions"]) and
                isinstance(row.get("writer_evidence_functions"), list) and
                all(isinstance(name, str) and name
                    for name in row["writer_evidence_functions"]) and
                isinstance(row.get("unresolved_preconditions"), list) and
                all(isinstance(item, str) and item
                    for item in row["unresolved_preconditions"])
                for row in security_invariants) and
            isinstance(storage_helpers, list) and
            all(isinstance(item, dict) and
                isinstance(item.get("function"), str) and
                bool(item.get("function")) and
                isinstance(item.get("candidate_callers"), list) and
                all(isinstance(name, str) and name
                    for name in item["candidate_callers"]) and
                isinstance(item.get("reviewed_callers"), list) and
                all(isinstance(name, str) and name
                    for name in item["reviewed_callers"])
                for item in storage_helpers) and
            isinstance(evidence, list) and
            all(isinstance(item, str) and item for item in evidence) and
            isinstance(writer_evidence, list) and
            all(isinstance(item, str) and item for item in writer_evidence) and
            isinstance(unresolved, list) and
            all(isinstance(item, str) and item for item in unresolved)
        )
        if not shape_valid:
            return {
                "analysis_result": "ANALYSIS_INCOMPLETE",
                "context_sufficiency": "UNKNOWN",
                "pointer_length_provenance": "UNKNOWN",
                "shared_state_writer_search": "UNKNOWN",
                "security_invariants": [],
                "shared_storage_helpers": [],
                "evidence_functions": [],
                "writer_evidence_functions": [],
                "unresolved_preconditions": ["completion receipt invalid"],
                "valid": False,
            }
        requires_provenance = self._has_pointer_length_precondition()
        complete_caller_receipts = [
            item for item in self.analysis_tool_history
            if item["name"] == "get_callers" and
            item.get("successful") is True and
            item.get("result_callers_truncated") is not True and
            isinstance(item.get("result_callers"), list) and
            isinstance(item["arguments"].get("function_name"), str)
        ]
        caller_reachable = {
            self.function_name, *self.callers, *self.caller_sources.keys()
        }
        changed = True
        while changed:
            changed = False
            for item in complete_caller_receipts:
                queried = item["arguments"]["function_name"]
                if queried not in caller_reachable:
                    continue
                for caller in item["result_callers"]:
                    if isinstance(caller, str) and caller and caller not in caller_reachable:
                        caller_reachable.add(caller)
                        changed = True
        provenance_evidence_linked = (
            bool(evidence) and
            set(evidence).issubset(caller_reachable) and
            any(name != self.function_name for name in evidence)
        )
        recursive_caller_lookup = (
            provenance_evidence_linked and any(
                item["arguments"]["function_name"] != self.function_name and
                item["arguments"]["function_name"] in caller_reachable
                for item in complete_caller_receipts
            )
        )
        inspected_functions = {
            item["arguments"].get("function_name")
            for item in self.analysis_tool_history
            if item["name"] == "get_function_source" and
            item.get("successful") is True and
            isinstance(item["arguments"].get("function_name"), str)
        }
        caller_receipts = {
            item["arguments"].get("function_name"): set(item["result_callers"])
            for item in self.analysis_tool_history
            if item["name"] == "get_callers" and
            item.get("successful") is True and
            item.get("result_callers_truncated") is not True and
            isinstance(item.get("result_callers"), list)
        }
        inspected_functions.update(self._complete_preloaded_caller_sources)
        inspected_functions.add(self.function_name)
        inspected_sources = {
            self.function_name: self.function_source,
            **self._complete_preloaded_caller_sources,
        }
        for item in self.analysis_tool_history:
            if (item["name"] == "get_function_source" and
                    item.get("successful") is True and
                    isinstance(item["arguments"].get("function_name"), str) and
                    isinstance(item.get("result_source"), str) and
                    item.get("result_source")):
                inspected_sources[item["arguments"]["function_name"]] = (
                    item["result_source"])
        complete_searches = [
            item for item in self.analysis_tool_history
            if item["name"] == "search_code" and
            item.get("successful") is True and
            item.get("result_search_truncated") is not True and
            bool(item["arguments"].get("pattern") or
                 item["arguments"].get("query")) and
            isinstance(item.get("result_search_evidence"), list) and
            bool(item.get("result_search_evidence"))
        ]
        writer_search_bound_functions: set[str] = set()
        for function_name in writer_evidence:
            source = inspected_sources.get(function_name)
            if not isinstance(source, str) or not source:
                continue
            normalized_source = self._normalized_source_fragment(source)
            for item in complete_searches:
                query = (item["arguments"].get("pattern") or
                         item["arguments"].get("query"))
                query_identifiers = {
                    token for token in re.findall(r"[A-Za-z_]\w*", query)
                    if len(token) >= 3
                }
                if (not query_identifiers or
                        not any(re.search(rf"\b{re.escape(token)}\b", source)
                                for token in query_identifiers)):
                    continue
                if any(
                    isinstance(fragment, str) and len(fragment) >= 3 and
                    fragment in normalized_source
                    for fragment in item["result_search_evidence"]
                ):
                    writer_search_bound_functions.add(function_name)
                    break
        shared_state_search_performed = (
            bool(writer_evidence) and
            set(writer_evidence).issubset(writer_search_bound_functions)
        )
        required_invariant_kinds = self._required_security_invariant_kinds()
        invariant_kinds_present = {
            row["kind"] for row in security_invariants
            if row["status"] != "NOT_APPLICABLE"
        }
        required_invariants_covered = set(required_invariant_kinds).issubset(
            invariant_kinds_present)
        invariant_rows_valid = True
        invariant_has_unresolved = False
        for row in security_invariants:
            row_evidence = set(row["evidence_functions"])
            row_writer_evidence = set(row["writer_evidence_functions"])
            if row["status"] == "ESTABLISHED":
                if (not row_evidence or
                        not row_evidence.issubset(inspected_functions) or
                        not row_writer_evidence.issubset(inspected_functions) or
                        row["unresolved_preconditions"]):
                    invariant_rows_valid = False
            elif row["status"] == "UNRESOLVED":
                invariant_has_unresolved = True
                if not row["unresolved_preconditions"]:
                    invariant_rows_valid = False
        evidence_inspected = (
            bool(evidence) and
            set(evidence).issubset(inspected_functions)
        )
        writer_evidence_inspected = (
            bool(writer_evidence) and
            set(writer_evidence).issubset(inspected_functions)
        )
        helper_callers_complete = True
        for helper in storage_helpers:
            candidate_callers = set(helper["candidate_callers"])
            reviewed_callers = set(helper["reviewed_callers"])
            if (helper["function"] not in caller_receipts or
                    candidate_callers != caller_receipts[helper["function"]] or
                    reviewed_callers != candidate_callers or
                    not reviewed_callers.issubset(inspected_functions)):
                helper_callers_complete = False
        if writer_search == "ESTABLISHED":
            writer_contract_valid = (
                bool(writer_evidence) and
                writer_evidence_inspected and
                helper_callers_complete and
                shared_state_search_performed
            )
        else:
            writer_contract_valid = (
                writer_search == "NOT_APPLICABLE" and
                not storage_helpers and
                not writer_evidence
            )
        sufficient = sufficiency == "SUFFICIENT"
        valid = True
        candidate_handoff_missing = self._has_unemitted_suspicious_local_risk()
        if candidate_handoff_missing:
            valid = False
            unresolved = list(unresolved) + [
                "source-bound SUSPICIOUS operation was not emitted for verification"
            ]
        if not self.local_risk_inventory_valid:
            valid = False
            unresolved = list(unresolved) + [
                "host-validated local risk inventory missing"
            ]
        if sufficient and unresolved:
            valid = False
        if sufficient and (not required_invariants_covered or
                           not invariant_rows_valid or
                           invariant_has_unresolved):
            valid = False
        if requires_provenance and sufficient:
            valid = (valid and provenance == "ESTABLISHED" and
                     evidence_inspected and recursive_caller_lookup and
                     writer_contract_valid and not unresolved)
        if sufficiency == "INSUFFICIENT":
            valid = (bool(unresolved) and
                     (provenance == "UNRESOLVED" or
                      writer_search == "UNRESOLVED" or
                      invariant_has_unresolved) and
                     invariant_rows_valid and required_invariants_covered)
        if ("STATE_CONSISTENCY" in required_invariant_kinds and sufficient and
                not writer_contract_valid):
            valid = False
        if candidate_handoff_missing:
            # Preserve the legacy INSUFFICIENT settlement semantics above, but
            # never let that settlement erase a source-bound discovery signal.
            valid = False
        return {
            "analysis_result": result if valid else "ANALYSIS_INCOMPLETE",
            "context_sufficiency": sufficiency if valid else "UNKNOWN",
            "pointer_length_provenance": provenance,
            "shared_state_writer_search": writer_search,
            "security_invariants": list(security_invariants),
            "shared_storage_helpers": list(storage_helpers),
            "evidence_functions": list(evidence),
            "writer_evidence_functions": list(writer_evidence),
            "unresolved_preconditions": list(unresolved),
            "requires_pointer_length_provenance": requires_provenance,
            "recursive_caller_lookup": recursive_caller_lookup,
            "caller_reachable_functions": sorted(caller_reachable),
            "provenance_evidence_linked": provenance_evidence_linked,
            "shared_state_search_performed": shared_state_search_performed,
            "writer_search_bound_functions": sorted(
                writer_search_bound_functions),
            "evidence_inspected": evidence_inspected,
            "writer_evidence_inspected": writer_evidence_inspected,
            "helper_callers_complete": helper_callers_complete,
            "writer_contract_valid": writer_contract_valid,
            "required_security_invariant_kinds": required_invariant_kinds,
            "required_invariants_covered": required_invariants_covered,
            "invariant_rows_valid": invariant_rows_valid,
            "candidate_handoff_missing": candidate_handoff_missing,
            "valid": valid,
            "analysis_complete": valid and sufficiency == "SUFFICIENT",
            "local_risk_inventory_valid": self.local_risk_inventory_valid,
            "local_risk_inventory": list(self.local_risk_inventory),
        }

    @property
    def agent_name(self) -> str:
        return AgentType.FULL_SP_GENERATOR.value

    def _log(self, message: str, level: str = "INFO") -> None:
        """Override _log to buffer logs for batch writing."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] [{level}] {message}"

        if self._log_to_buffer:
            self._log_buffer.append(formatted)

        super()._log(message, level)

    def get_log_block(self) -> str:
        """Get formatted log block for this function analysis."""
        lines = []

        lines.append("")
        lines.append("=" * 60)
        lines.append(f"Function: {self.function_name}")
        lines.append(
            f"File: {self.function_file}:{self.function_lines[0]}-{self.function_lines[1]}"
        )
        func_lines = self.function_source.count("\n") + 1 if self.function_source else 0
        lines.append(f"Size: {func_lines} lines")
        lines.append(f"Callers: {len(self.callers)} | Callees: {len(self.callees)}")
        lines.append(
            f"Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'N/A'}"
        )
        lines.append("=" * 60)
        lines.append("")

        for log_line in self._log_buffer:
            lines.append(log_line)

        lines.append("")
        lines.append("-" * 60)
        if self.stop_reason:
            lines.append(f"Result: INCOMPLETE ({self.stop_reason})")
            if self.sp_created:
                lines.append("  SP was created before analysis stopped")
        elif self.sp_created:
            lines.append("Result: SP CREATED")
            if self.sp_details:
                lines.append(f"  Type: {self.sp_details.get('vuln_type', 'unknown')}")
                lines.append(f"  Score: {self.sp_details.get('score', 0)}")
        else:
            lines.append("Result: NO ISSUE")

        duration = 0
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        lines.append(f"  Iterations: {self.total_iterations}")
        lines.append(f"  Duration: {duration:.1f}s")
        lines.append("-" * 60)
        lines.append("")

        return "\n".join(lines)

    @property
    def system_prompt(self) -> str:
        return FUNCTION_ANALYSIS_PROMPT.format(
            fuzzer=self.fuzzer,
            sanitizer=self.sanitizer,
            sanitizer_patterns=self._get_sanitizer_patterns(),
        )

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        return {
            "Agent": "Full SP Generator",
            "Mode": "full-scan",
            "Function": self.function_name,
            "File": self.function_file,
            "Lines": f"{self.function_lines[0]}-{self.function_lines[1]}",
            "Callers": len(self.callers),
            "Callees": len(self.callees),
            "Fuzzer": self.fuzzer,
            "Sanitizer": self.sanitizer,
        }

    def _configure_context(self, ctx) -> None:
        """Configure agent context with direction ID."""
        if self.direction_id:
            ctx.direction_id = self.direction_id

    def _get_summary_table(self) -> str:
        """Generate summary table."""
        duration = (
            (self.end_time - self.start_time).total_seconds()
            if self.start_time and self.end_time
            else 0
        )
        width = 60

        lines = []
        lines.append("")
        lines.append("+" + "-" * width + "+")
        lines.append("|" + " FULL SP GENERATOR RESULT ".center(width) + "|")
        lines.append("+" + "-" * width + "+")
        lines.append("|" + f"  Function: {self.function_name}".ljust(width) + "|")
        lines.append("|" + f"  Duration: {duration:.2f}s".ljust(width) + "|")
        lines.append("|" + f"  Iterations: {self.total_iterations}".ljust(width) + "|")
        lines.append(
            "|"
            + f"  SP Created: {'Yes' if self.sp_created else 'No'}".ljust(width)
            + "|"
        )

        if self.sp_details:
            lines.append("+" + "-" * width + "+")
            vuln_type = self.sp_details.get("vuln_type", "unknown")
            score = self.sp_details.get("score", 0)
            lines.append("|" + f"  Type: {vuln_type}".ljust(width) + "|")
            lines.append("|" + f"  Score: {score}".ljust(width) + "|")

        lines.append("+" + "-" * width + "+")
        lines.append("")

        return "\n".join(lines)

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message with all pre-extracted context."""
        func_lines = self.function_source.count("\n") + 1

        callee_list = ", ".join(self.callees[:15]) if self.callees else "(none)"
        if len(self.callees) > 15:
            callee_list += f" ... +{len(self.callees) - 15} more"

        message = f"""Analyze this function for {self.sanitizer}-detectable vulnerabilities.

## Target Function: `{self.function_name}`
File: `{self.function_file}` | Lines: {self.function_lines[0]}-{self.function_lines[1]} ({func_lines} lines)

```c
{self.function_source}
```
"""

        if self.require_context_sufficiency:
            invariant_kinds = self._required_security_invariant_kinds()
            rendered = ", ".join(invariant_kinds) if invariant_kinds else "(none)"
            message += f"""
## Host-derived security-invariant lenses
Required kinds: {rendered}

These kinds were mechanically derived from the target source and selected
sanitizer. They do not identify a bug or a known location. Before a negative
completion, include evidence-ledger rows for every required kind and inspect
each distinct security-relevant relationship of those kinds.

## Host-enforced analysis phases

You have {self.max_iterations} total turns for this function.

1. On the first turn, inspect the target function itself. Either create a
   suspicious point for a concrete local pattern or call
   `record_local_risk_inventory` exactly once. The inventory must bind every
   required kind to one contiguous verbatim quote from the target function.
   Never use `...` or concatenate disjoint snippets in `source_quote`; use
   separate operation rows when distinct source regions matter.
2. On the next turn, create an SP for every `SUSPICIOUS` operation and let the
   Verifier resolve reachability, caller provenance, ownership, and global
   writer questions. If a `REQUIRES_CONTEXT` operation has a concrete sanitizer
   failure hypothesis, create a lower-score SP. Do not recursively explore
   provenance branches merely to prove that no candidate exists.
3. Otherwise return the negative-completion receipt immediately. Mark an
   external precondition `INSUFFICIENT`; this records a local no-candidate
   screen and never claims that the function or repository is safe.
"""

        if self.fuzzer_source:
            fuzzer_src = self.fuzzer_source
            if len(fuzzer_src) > 3000:
                fuzzer_src = fuzzer_src[:3000] + "\n... (truncated)"
            message += f"""
## Fuzzer Entry Point: `{self.fuzzer}`
Shows how input data enters the program:

```c
{fuzzer_src}
```
"""

        if self.caller_sources:
            message += "\n## Caller Functions\n"
            for caller_name, caller_src in list(self.caller_sources.items())[:3]:
                src = caller_src
                if len(src) > 1500:
                    src = src[:1500] + "\n... (truncated)"
                message += f"""
### `{caller_name}` (calls {self.function_name}):
```c
{src}
```
"""

        message += f"""
## Callees (functions called by {self.function_name}):
{callee_list}

## Task
Analyze for {self.sanitizer} bugs. If you find issues, call `create_suspicious_point()`.
If no issue is found, follow the negative-completion contract in the system
prompt. Do not recursively prove an external negative here: hand concrete
risks to the Verifier and mark missing external facts INSUFFICIENT. Be concise.
"""
        return message

    async def analyze_async(self) -> Dict[str, Any]:
        """Run analysis on the function."""
        result = await self.run_async()
        self.analysis_completion = self._assess_analysis_completion(result)
        analysis_complete = (self.sp_created or
                             self.analysis_completion.get("analysis_complete",
                                                          True))

        return {
            "success": bool(self.analysis_completion["valid"] and
                            analysis_complete),
            "function_name": self.function_name,
            "direction_id": self.direction_id,
            "sp_created": self.sp_created,
            "sp_details": self.sp_details,
            "iterations_used": self.total_iterations,
            "response": result,
            "analysis_result": self.analysis_completion["analysis_result"],
            "context_sufficiency": self.analysis_completion["context_sufficiency"],
            "analysis_completion": self.analysis_completion,
            "local_risk_inventory": list(self.local_risk_inventory),
            "stats": self.get_stats(),
        }

    def analyze_sync(self) -> Dict[str, Any]:
        """Run analysis synchronously."""
        result = self.run()
        self.analysis_completion = self._assess_analysis_completion(result)
        analysis_complete = (self.sp_created or
                             self.analysis_completion.get("analysis_complete",
                                                          True))

        return {
            "success": bool(self.analysis_completion["valid"] and
                            analysis_complete),
            "function_name": self.function_name,
            "direction_id": self.direction_id,
            "sp_created": self.sp_created,
            "sp_details": self.sp_details,
            "iterations_used": self.total_iterations,
            "response": result,
            "analysis_result": self.analysis_completion["analysis_result"],
            "context_sufficiency": self.analysis_completion["context_sufficiency"],
            "analysis_completion": self.analysis_completion,
            "local_risk_inventory": list(self.local_risk_inventory),
            "stats": self.get_stats(),
        }


class LargeFullSPGenerator(FullSPGenerator):
    """
    Full SP Generator for large functions.

    Uses sliding window approach and context compression for large functions.
    """

    LARGE_FUNCTION_THRESHOLD = 2000
    TOOL_GET_NEXT_FUNCTION_WINDOW = "get_next_function_window"

    def __init__(
        self,
        function_name: str,
        function_source: str,
        function_file: str = "",
        function_lines: tuple = (0, 0),
        callers: List[str] = None,
        callees: List[str] = None,
        fuzzer_source: str = "",
        caller_sources: Dict[str, str] = None,
        fuzzer: str = "",
        sanitizer: str = "address",
        direction_id: str = "",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 6,
        verbose: bool = True,
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        index: int = 0,
        use_sliding_window: bool = True,
        window_size: int = 100,
        require_context_sufficiency: bool = False,
    ):
        super().__init__(
            function_name=function_name,
            function_source=function_source,
            function_file=function_file,
            function_lines=function_lines,
            callers=callers,
            callees=callees,
            fuzzer_source=fuzzer_source,
            caller_sources=caller_sources,
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            direction_id=direction_id,
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=verbose,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
            index=index,
            require_context_sufficiency=require_context_sufficiency,
        )

        self.use_sliding_window = use_sliding_window
        self.window_size = window_size
        self.current_window = 0
        self.total_windows = 0

        self.enable_context_compression = True

    @property
    def agent_name(self) -> str:
        return AgentType.LARGE_FULL_SP_GENERATOR.value

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        base = super()._get_agent_metadata()
        base["Agent"] = "Large Full SP Generator"
        base["Mode"] = "large-function"
        base["Window Size"] = self.window_size
        return base

    def _get_function_windows(self) -> List[str]:
        """Split large function into overlapping windows."""
        lines = self.function_source.split("\n")
        windows = []

        overlap = self.window_size // 5
        step = self.window_size - overlap

        for i in range(0, len(lines), step):
            window_lines = lines[i : i + self.window_size]
            windows.append("\n".join(window_lines))

            if i + self.window_size >= len(lines):
                break

        return windows

    def _has_unread_function_windows(self) -> bool:
        return self.total_windows > 0 and self.current_window < self.total_windows

    def minimum_strict_iterations(self) -> int:
        """Turns needed to expose all windows plus inventory and decision."""
        return len(self._get_function_windows()) + 2

    async def _get_tools(self, client) -> List[Dict[str, Any]]:
        """Expose a host-owned, deterministic continuation for large source."""
        tools = await super()._get_tools(client)
        if self.total_windows > 1:
            tools.append({
                "type": "function",
                "function": {
                    "name": self.TOOL_GET_NEXT_FUNCTION_WINDOW,
                    "description": (
                        "Read the next overlapping window of the same pinned "
                        "target function. Use until all windows are inspected."
                    ),
                    "parameters": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "target_function": {"type": "string"},
                        },
                        "required": ["target_function"],
                    },
                },
            })
        return tools

    def _tools_for_iteration(
        self, iteration: int, remaining: int,
    ) -> List[Dict[str, Any]]:
        if self._has_unread_function_windows():
            # Before a clean-negative decision the model must receive every
            # pinned window. It may still emit a candidate immediately.
            allowed = {
                self.TOOL_GET_NEXT_FUNCTION_WINDOW,
                self.TOOL_CREATE_SUSPICIOUS_POINT,
            }
            return [row for row in self._tools
                    if row.get("function", {}).get("name") in allowed]
        return super()._tools_for_iteration(iteration, remaining)

    def _get_urgency_message(self, iteration: int, remaining: int) -> Optional[str]:
        if self._has_unread_function_windows():
            return (
                "LARGE-FUNCTION COVERAGE. More pinned source windows remain. "
                "Call get_next_function_window, or create a suspicious point "
                "now if the current window already contains a concrete risk. "
                "A no-candidate conclusion is not eligible before every "
                "window is inspected."
            )
        return super()._get_urgency_message(iteration, remaining)

    async def _execute_tool(
        self, client: Client, tool_name: str, tool_args: Dict[str, Any]
    ) -> str:
        if tool_name != self.TOOL_GET_NEXT_FUNCTION_WINDOW:
            return await super()._execute_tool(client, tool_name, tool_args)
        if tool_args.get("target_function") != self.function_name:
            result = {"success": False, "error": "target_function mismatch"}
        elif not self._has_unread_function_windows():
            result = {"success": False, "error": "all function windows inspected"}
        else:
            windows = self._get_function_windows()
            window_index = self.current_window
            source = windows[window_index]
            self.current_window += 1
            result = {
                "success": True,
                "target_function": self.function_name,
                "window": self.current_window,
                "total_windows": self.total_windows,
                "source": source,
                "all_windows_inspected": not self._has_unread_function_windows(),
            }
        if self._context:
            self._context.increment_tool_calls()
        self.analysis_tool_history.append({
            "name": tool_name,
            "arguments": dict(tool_args),
            "successful": result.get("success") is True,
            "result_source": result.get("source", ""),
            "result_callers": [],
            "result_callers_truncated": False,
        })
        return json.dumps(result, sort_keys=True)

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message with sliding window support."""
        func_lines = self.function_source.count("\n") + 1

        if self.use_sliding_window and func_lines > self.LARGE_FUNCTION_THRESHOLD:
            windows = self._get_function_windows()
            self.total_windows = len(windows)
            self.current_window = 1 if windows else 0

            first_window = windows[0] if windows else self.function_source

            message = f"""Analyze this LARGE function for vulnerabilities.

## Target Function

**Name**: `{self.function_name}`
**File**: `{self.function_file}`
**Total Lines**: {func_lines} (large function - showing window 1/{self.total_windows})

## Source Code (Window 1/{self.total_windows})

```c
{first_window}
```

## Strategy for Large Function

This function is large ({func_lines} lines). The host will show it in pinned,
overlapping windows.
- Analyze each window for vulnerabilities
- Call `get_next_function_window` until every window is inspected
- Create SPs as you find issues
- A no-candidate conclusion is invalid before all windows are inspected

## Call Context

**Callers**: {", ".join(self.callers[:5]) if self.callers else "(none)"}
**Callees**: {", ".join(self.callees[:5]) if self.callees else "(none)"}

## Your Task

1. Analyze this section for {self.sanitizer}-detectable bugs
2. Note any suspicious patterns
3. Request more context or next window if needed
4. Create SPs for any issues found

You have {self.max_iterations} iterations for the entire function.
"""
            return message
        else:
            return super().get_initial_message(**kwargs)


class DeltaSPGenerator(SPGeneratorBase):
    """
    Delta-scan SP Generator.

    Analyzes code changes (diffs) to find suspicious points.
    Used when there are code modifications between versions.
    """

    # Score thresholds
    SCORE_HIGH_CONFIDENCE = 0.8
    SCORE_MEDIUM_CONFIDENCE = 0.5
    SCORE_DEFAULT = 0.5

    # Display constants
    TABLE_WIDTH = 70

    # Default values
    DEFAULT_FUNCTION_NAME = "unknown"
    DEFAULT_VULN_TYPE = "unknown"

    def __init__(
        self,
        fuzzer: str = "",
        sanitizer: str = "address",
        llm_client: Optional[LLMClient] = None,
        model: Optional[Union[ModelInfo, str]] = None,
        max_iterations: int = 15,
        verbose: bool = True,
        task_id: str = "",
        worker_id: str = "",
        log_dir: Optional[Path] = None,
        index: int = 0,
        target_name: str = "",
    ):
        super().__init__(
            fuzzer=fuzzer,
            sanitizer=sanitizer,
            llm_client=llm_client,
            model=model,
            max_iterations=max_iterations,
            verbose=verbose,
            task_id=task_id,
            worker_id=worker_id,
            log_dir=log_dir,
            index=index,
            target_name=target_name,
        )

        # Context for delta analysis
        self.reachable_changes: List[Dict[str, Any]] = []
        self.sp_list: List[tuple] = []  # (func_name, vuln_type, score)

    @property
    def agent_name(self) -> str:
        return AgentType.DELTA_SP_GENERATOR.value

    @property
    def is_delta(self) -> bool:
        """Delta SPG uses single agent for all changes."""
        return True

    @property
    def system_prompt(self) -> str:
        prompt = FIND_SUSPICIOUS_POINTS_PROMPT
        sanitizer_guidance = f"\n\n## Sanitizer-Specific Patterns: {self.sanitizer}\n\nFocus ONLY on these bug types (other bugs won't be detected by this sanitizer):\n"
        sanitizer_guidance += self._get_sanitizer_guidance()
        return prompt + sanitizer_guidance

    def _get_agent_metadata(self) -> dict:
        """Get metadata for agent banner."""
        return {
            "Agent": "Delta SP Generator",
            "Mode": "delta-scan",
            "Phase": "SP Finding",
            "Fuzzer": self.fuzzer,
            "Sanitizer": self.sanitizer,
            "Worker ID": self.worker_id,
            "Changed Functions": len(self.reachable_changes),
            "Goal": "Find vulnerabilities in code changes",
        }

    def _build_table_header(self, title: str, width: Optional[int] = None) -> List[str]:
        """Build table header lines."""
        w = width or self.TABLE_WIDTH
        return [
            "",
            "+" + "-" * w + "+",
            "|" + f" {title} ".center(w) + "|",
            "+" + "-" * w + "+",
        ]

    def _build_table_footer(self, width: Optional[int] = None) -> List[str]:
        """Build table footer lines."""
        w = width or self.TABLE_WIDTH
        return ["+" + "-" * w + "+", ""]

    def _build_table_row(
        self, content: str, width: Optional[int] = None, prefix: str = "  "
    ) -> str:
        """Build a single table row."""
        w = width or self.TABLE_WIDTH
        line = f"{prefix}{content}"
        if len(line) > w - 2:
            line = line[: w - 5] + "..."
        return "|" + line.ljust(w) + "|"

    def _get_summary_table(self) -> str:
        """Generate summary table for delta find mode."""
        duration = (
            (self.end_time - self.start_time).total_seconds()
            if self.start_time and self.end_time
            else 0
        )

        lines = []
        lines.extend(self._build_table_header("DELTA SP GENERATOR SUMMARY"))
        lines.append(self._build_table_row(f"Fuzzer: {self.fuzzer}"))
        lines.append(self._build_table_row(f"Sanitizer: {self.sanitizer}"))
        lines.append(self._build_table_row(f"Duration: {duration:.2f}s"))
        lines.append(self._build_table_row(f"Iterations: {self.total_iterations}"))
        lines.append(
            self._build_table_row(f"Changed Functions: {len(self.reachable_changes)}")
        )
        lines.append(self._build_table_row(f"SPs Created: {len(self.sp_list)}"))
        lines.append("+" + "-" * self.TABLE_WIDTH + "+")
        lines.append("|" + " SUSPICIOUS POINTS ".center(self.TABLE_WIDTH) + "|")
        lines.append("+" + "-" * self.TABLE_WIDTH + "+")

        if self.sp_list:
            for func_name, vuln_type, score in self.sp_list:
                score_icon = (
                    "H"
                    if score >= self.SCORE_HIGH_CONFIDENCE
                    else ("M" if score >= self.SCORE_MEDIUM_CONFIDENCE else "L")
                )
                content = f"[{score_icon}:{score:.1f}] {func_name}: {vuln_type}"
                lines.append(self._build_table_row(content))
        else:
            lines.append(self._build_table_row("(No SPs created)"))

        lines.extend(self._build_table_footer())

        return "\n".join(lines)

    async def _execute_tool(
        self,
        client: Client,
        tool_name: str,
        tool_args: Dict[str, Any],
    ) -> str:
        """Execute tool and track results."""
        result = await super()._execute_tool(client, tool_name, tool_args)

        if tool_name == self.TOOL_CREATE_SUSPICIOUS_POINT:
            try:
                data = json.loads(result)
                if data.get("success"):
                    func_name = tool_args.get(
                        "function_name", self.DEFAULT_FUNCTION_NAME
                    )
                    vuln_type = tool_args.get("vuln_type", self.DEFAULT_VULN_TYPE)
                    score = tool_args.get("score", self.SCORE_DEFAULT)
                    self.sp_list.append((func_name, vuln_type, score))
                    self._log(f"Tracked SP: {func_name} ({vuln_type})", level="INFO")
            except (json.JSONDecodeError, TypeError):
                pass

        return result

    def _format_fuzzer_code_section(self, fuzzer_code: str) -> str:
        """Format fuzzer source code section for initial message."""
        if fuzzer_code:
            return f"""## Fuzzer Source Code (CRITICAL - READ THIS FIRST!)

This code shows EXACTLY how input enters the target library.
Vulnerabilities must be reachable through this entry point.

```c
{fuzzer_code}
```

"""
        else:
            return f"""## Fuzzer Source Code

IMPORTANT: First read the fuzzer source with {self.TOOL_GET_FUNCTION_SOURCE}("{self.fuzzer}").
This shows how input enters the library - only reachable code matters!

"""

    def _format_changed_functions_section(
        self, reachable_changes: List[Dict[str, Any]]
    ) -> str:
        """Format changed functions list section."""
        if not reachable_changes:
            return ""

        message = "## Changed Functions (ALL - including static-unreachable)\n\n"
        message += "**IMPORTANT**: Analyze ALL functions below, even those marked as static-unreachable!\n"
        message += "Static analysis cannot track function pointer calls.\n\n"

        reachable = [c for c in reachable_changes if c.get("static_reachable", True)]
        unreachable = [
            c for c in reachable_changes if not c.get("static_reachable", True)
        ]

        if reachable:
            message += "### Static-Reachable Functions:\n"
            for change in reachable:
                message += f"- {change.get('function', self.DEFAULT_FUNCTION_NAME)} ({change.get('file', self.DEFAULT_FUNCTION_NAME)})\n"
                if "distance" in change and change["distance"] is not None:
                    message += f"  Distance: {change['distance']}\n"
            message += "\n"

        if unreachable:
            message += "### Static-Unreachable Functions (MAY BE REACHABLE VIA FUNCTION POINTERS!):\n"
            for change in unreachable:
                message += f"- {change.get('function', self.DEFAULT_FUNCTION_NAME)} ({change.get('file', self.DEFAULT_FUNCTION_NAME)})\n"
                message += "  Warning: Check for function pointer patterns!\n"
            message += "\n"

        return message

    def get_initial_message(self, **kwargs) -> str:
        """Generate initial message for delta find mode."""
        reachable_changes = kwargs.get("reachable_changes", self.reachable_changes)
        fuzzer_code = kwargs.get("fuzzer_code", "")

        message = f"""Analyze the code changes for potential vulnerabilities.

## Your Target Configuration (FIXED - cannot change)

**Fuzzer**: `{self.fuzzer}`
**Sanitizer**: `{self.sanitizer}`

Only find vulnerabilities that are:
1. REACHABLE from `{self.fuzzer}` (verify call path exists)
2. DETECTABLE by `{self.sanitizer}` sanitizer (bug type must match)

"""
        message += self._format_fuzzer_code_section(fuzzer_code)
        message += self._format_changed_functions_section(reachable_changes)

        message += f"""## Your Task

Follow these steps IN ORDER:

1. **READ THE DIFF**: Call get_diff to see what code was changed

2. **ANALYZE ALL CHANGED FUNCTIONS** (including static-unreachable!):
   - Read each function's source code with get_function_source
   - Look for {self.sanitizer}-detectable vulnerabilities:
     - {self._get_sanitizer_vuln_types()}
"""

        message += """
3. **CREATE SUSPICIOUS POINTS**: For each potential vulnerability:
   - One SP per unique root cause (not per symptom)
   - Use control flow description, not line numbers
   - Set confidence score based on vulnerability clarity
   - Include static_reachable info if known

**IMPORTANT**: Do NOT skip static-unreachable functions! They may be reachable via function pointers.
The Verify agent will judge actual reachability later.
"""

        return message

    def set_context(
        self,
        reachable_changes: List[Dict[str, Any]],
        fuzzer: str = None,
        sanitizer: str = None,
    ) -> None:
        """
        Set context for delta analysis.

        Args:
            reachable_changes: List of reachable changed functions
            fuzzer: Fuzzer name (optional)
            sanitizer: Sanitizer type (optional)
        """
        self.reachable_changes = reachable_changes
        if fuzzer:
            self.fuzzer = fuzzer
        if sanitizer:
            self.sanitizer = sanitizer

    async def find_suspicious_points(
        self,
        reachable_changes: List[Dict[str, Any]],
        fuzzer_code: str = "",
    ) -> str:
        """
        Find suspicious points in reachable changed code.

        Args:
            reachable_changes: List of reachable changed functions
            fuzzer_code: Fuzzer source code

        Returns:
            Agent response summarizing findings
        """
        self.reachable_changes = reachable_changes
        return await self.run_async(
            reachable_changes=reachable_changes,
            fuzzer_code=fuzzer_code,
        )

    def find_suspicious_points_sync(
        self,
        reachable_changes: List[Dict[str, Any]],
        fuzzer_code: str = "",
    ) -> str:
        """Synchronous version of find_suspicious_points."""
        self.reachable_changes = reachable_changes
        return self.run(
            reachable_changes=reachable_changes,
            fuzzer_code=fuzzer_code,
        )
