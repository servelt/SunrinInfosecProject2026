import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fuzzingbrain.agents.sp_generators import (
    FullSPGenerator,
    LargeFullSPGenerator,
    generic_security_family_priority,
    generic_security_risk_priority,
)


POINTER_COUNT_SOURCE = """
static void inspect(Item* items, int n_items) {
    for (int i = 0; i < n_items; i++) use(items[i]);
}
"""


def _agent(*, required=True):
    agent = FullSPGenerator(
        function_name="inspect",
        function_source=POINTER_COUNT_SOURCE,
        fuzzer="fixture",
        sanitizer="address",
        require_context_sufficiency=required,
        verbose=False,
    )
    if required:
        result = agent._record_local_risk_inventory({
            "target_function": "inspect",
            "operations": [{
                "kind": kind,
                "subject": f"fixture {kind.lower()} relationship",
                "source_quote": "items[i]",
                "local_status": "REQUIRES_CONTEXT",
                "missing_preconditions": ["caller-owned extent is required"],
            } for kind in agent._required_security_invariant_kinds()],
        })
        assert result["success"] is True
    return agent


def _receipt(*, sufficiency="SUFFICIENT", provenance="ESTABLISHED",
             writer_search="ESTABLISHED", evidence=None,
             writer_evidence=None, storage_helpers=None, unresolved=None,
             security_invariants=None):
    evidence = ["make_items"] if evidence is None else evidence
    writer_evidence = ["resize_items"] if writer_evidence is None else writer_evidence
    storage_helpers = ([{
        "function": "resize_items",
        "candidate_callers": ["grow_items"],
        "reviewed_callers": ["grow_items"],
    }] if storage_helpers is None else storage_helpers)
    unresolved = [] if unresolved is None else unresolved
    security_invariants = ([
        {
            "kind": kind,
            "subject": f"generic {kind.lower()} relationship",
            "status": "ESTABLISHED",
            "evidence_functions": ["inspect"],
            "writer_evidence_functions": [],
            "unresolved_preconditions": [],
        }
        for kind in ("BOUNDS_EXTENT", "LIFETIME_OWNERSHIP", "NULLABILITY")
    ] if security_invariants is None else security_invariants)
    payload = {
        "analysis_result": "ANALYZED_NO_SP",
        "context_sufficiency": sufficiency,
        "pointer_length_provenance": provenance,
        "shared_state_writer_search": writer_search,
        "security_invariants": security_invariants,
        "shared_storage_helpers": storage_helpers,
        "evidence_functions": evidence,
        "writer_evidence_functions": writer_evidence,
        "unresolved_preconditions": unresolved,
    }
    return "analysis\nFBV2_ANALYSIS_COMPLETION\n" + json.dumps(payload)


def test_pointer_count_negative_requires_recursive_caller_provenance():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers", "arguments": {"function_name": "inspect"},
         "successful": True},
        {"name": "get_function_source",
         "arguments": {"function_name": "forward_items"},
         "successful": True},
    ]
    result = agent._assess_analysis_completion(_receipt())
    assert result["requires_pointer_length_provenance"] is True
    assert result["recursive_caller_lookup"] is False
    assert result["valid"] is False
    assert result["analysis_result"] == "ANALYSIS_INCOMPLETE"


def test_pointer_count_negative_accepts_established_recursive_provenance():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers", "arguments": {"function_name": "inspect"},
         "successful": True, "result_callers": ["forward_items"],
         "result_callers_truncated": False},
        {"name": "get_function_source",
         "arguments": {"function_name": "forward_items"},
         "successful": True,
         "result_source": "void forward_items(void) { make_items(); }"},
        {"name": "get_callers",
         "arguments": {"function_name": "forward_items"},
         "successful": True, "result_callers": ["make_items"],
         "result_callers_truncated": False},
        {"name": "get_function_source",
         "arguments": {"function_name": "make_items"},
         "successful": True,
         "result_source": "void make_items(void) { inspect(items, n_items); }"},
        {"name": "search_code", "arguments": {"pattern": "items|n_items"},
         "successful": True, "result_search_truncated": False,
         "result_search_evidence": ["items = resize(items, n_items);"]},
        {"name": "get_function_source",
         "arguments": {"function_name": "resize_items"},
         "successful": True,
         "result_source": "void resize_items(void) { items = resize(items, n_items); }"},
        {"name": "get_callers", "arguments": {"function_name": "resize_items"},
         "successful": True, "result_callers": ["grow_items"],
         "result_callers_truncated": False},
        {"name": "get_function_source",
         "arguments": {"function_name": "grow_items"},
         "successful": True,
         "result_source": "void grow_items(void) { resize_items(); }"},
    ]
    result = agent._assess_analysis_completion(_receipt())
    assert result["valid"] is True
    assert result["analysis_complete"] is True
    assert result["context_sufficiency"] == "SUFFICIENT"


def test_truncated_preloaded_caller_is_not_credited_as_fully_inspected():
    agent = FullSPGenerator(
        function_name="inspect",
        function_source=POINTER_COUNT_SOURCE,
        callers=["make_items"],
        caller_sources={"make_items": "x" * 1501},
        fuzzer="fixture", sanitizer="address",
        require_context_sufficiency=True, verbose=False,
    )
    inventory = agent._record_local_risk_inventory({
        "target_function": "inspect",
        "operations": [{
            "kind": kind,
            "subject": f"fixture {kind.lower()} relationship",
            "source_quote": "items[i]",
            "local_status": "REQUIRES_CONTEXT",
            "missing_preconditions": ["caller-owned extent is required"],
        } for kind in agent._required_security_invariant_kinds()],
    })
    assert inventory["success"] is True
    assert agent._complete_preloaded_caller_sources == {}
    assert "... (truncated)" in agent.get_initial_message()
    agent.analysis_tool_history = [
        {"name": "get_callers", "arguments": {"function_name": "inspect"},
         "successful": True, "result_callers": ["make_items"],
         "result_callers_truncated": False},
        {"name": "get_callers", "arguments": {"function_name": "make_items"},
         "successful": True, "result_callers": ["entry"],
         "result_callers_truncated": False},
    ]
    result = agent._assess_analysis_completion(_receipt(
        writer_search="NOT_APPLICABLE", evidence=["make_items"],
        writer_evidence=[], storage_helpers=[]))
    assert result["evidence_inspected"] is False
    assert result["valid"] is False


def test_unresolved_provenance_is_honest_but_not_analysis_complete():
    agent = _agent()
    result = agent._assess_analysis_completion(_receipt(
        sufficiency="INSUFFICIENT",
        provenance="UNRESOLVED",
        writer_search="UNRESOLVED",
        evidence=[],
        writer_evidence=[],
        storage_helpers=[],
        unresolved=["allocation extent was not available"],
    ))
    assert result["valid"] is True
    assert result["analysis_complete"] is False
    assert result["context_sufficiency"] == "INSUFFICIENT"


def test_completion_contract_is_opt_in_for_legacy_runs():
    agent = _agent(required=False)
    result = agent._assess_analysis_completion("brief negative conclusion")
    assert result["valid"] is True
    assert result["analysis_result"] == "ANALYZED_NO_SP"


def test_prompt_contract_is_generic_not_target_specific():
    prompt = _agent().system_prompt
    assert "caller provenance" in prompt
    assert "allocation extent" in prompt
    assert "LIFETIME_OWNERSHIP" in prompt
    assert "ARITHMETIC_RANGE" in prompt
    assert "md_collect_marks" not in prompt
    assert "md4c" not in prompt


def test_strict_local_inventory_is_source_bound_and_covers_required_kinds():
    agent = FullSPGenerator(
        function_name="consume_entry",
        function_source=(
            "int consume_entry(Table *table, int index) { "
            "return table->rows[index]; }"
        ),
        sanitizer="address",
        require_context_sufficiency=True,
        verbose=False,
    )
    rows = [{
        "kind": kind,
        "subject": f"fixture {kind.lower()} operation",
        "source_quote": "table->rows[index]",
        "local_status": "REQUIRES_CONTEXT",
        "missing_preconditions": ["backing extent is established by a caller"],
    } for kind in agent._required_security_invariant_kinds()]

    accepted = agent._record_local_risk_inventory({
        "target_function": "consume_entry", "operations": rows})
    assert accepted["success"] is True
    assert agent.local_risk_inventory_valid is True
    assert {row["kind"] for row in agent.local_risk_inventory} == set(
        agent._required_security_invariant_kinds())

    wrong_function = agent._record_local_risk_inventory({
        "target_function": "different_entry", "operations": rows})
    assert wrong_function == {"success": False,
                              "error": "target_function mismatch"}

    foreign_quote = [dict(row) for row in rows]
    foreign_quote[0]["source_quote"] = "unrelated_buffer[offset]"
    rejected = agent._record_local_risk_inventory({
        "target_function": "consume_entry", "operations": foreign_quote})
    assert rejected == {"success": False,
                        "error": "source_quote is not in target source"}


def test_strict_sp_turns_switch_from_inventory_to_candidate_decision():
    agent = FullSPGenerator(
        function_name="read_slot",
        function_source="int read_slot(int *p, int i) { return p[i]; }",
        sanitizer="address",
        require_context_sufficiency=True,
        verbose=False,
    )
    tool_names = (
        "record_local_risk_inventory", "create_suspicious_point",
        "get_function_source", "get_callers", "get_callees", "search_code",
    )
    agent._tools = [{"type": "function", "function": {"name": name}}
                    for name in tool_names]

    first = {row["function"]["name"]
             for row in agent._tools_for_iteration(1, 4)}
    assert first == {"record_local_risk_inventory",
                     "create_suspicious_point"}

    result = agent._record_local_risk_inventory({
        "target_function": "read_slot",
        "operations": [{
            "kind": kind,
            "subject": f"fixture {kind.lower()} operation",
            "source_quote": "p[i]",
            "local_status": "REQUIRES_CONTEXT",
            "missing_preconditions": ["caller extent is required"],
        } for kind in agent._required_security_invariant_kinds()],
    })
    assert result["success"] is True

    middle = {row["function"]["name"]
              for row in agent._tools_for_iteration(2, 3)}
    assert middle == {"create_suspicious_point"}

    final = {row["function"]["name"]
             for row in agent._tools_for_iteration(5, 0)}
    assert final == {"create_suspicious_point"}
    assert "CANDIDATE-SCREEN DECISION" in agent._get_urgency_message(2, 3)


def test_suspicious_inventory_hands_candidate_to_verifier_before_context_proof():
    agent = FullSPGenerator(
        function_name="parse_array",
        function_source=(
            "int parse_array(Buffer *input_buffer) { "
            "input_buffer->depth++; input_buffer->offset++; "
            "return input_buffer->depth; }"
        ),
        sanitizer="address",
        require_context_sufficiency=True,
        verbose=False,
    )
    agent._tools = [{"type": "function", "function": {"name": name}}
                    for name in (
                        "record_local_risk_inventory",
                        "create_suspicious_point",
                        "get_function_source", "get_callers", "search_code",
                    )]
    rows = [{
        "kind": kind,
        "subject": "input_buffer state relationship",
        "source_quote": "input_buffer->depth++",
        "local_status": (
            "SUSPICIOUS" if kind == "STATE_CONSISTENCY"
            else "REQUIRES_CONTEXT"
        ),
        "missing_preconditions": ["failure-path balance is unresolved"],
    } for kind in agent._required_security_invariant_kinds()]

    recorded = agent._record_local_risk_inventory({
        "target_function": "parse_array", "operations": rows})

    assert recorded["success"] is True
    assert recorded["suspicious_count"] == 1
    assert "Create a suspicious point now" in recorded["next_step"]
    available = {row["function"]["name"]
                 for row in agent._tools_for_iteration(2, 3)}
    assert available == {"create_suspicious_point"}
    urgency = agent._get_urgency_message(2, 3)
    assert "CANDIDATE-FIRST HANDOFF" in urgency
    assert "Verifier" in urgency


def test_suspicious_inventory_cannot_be_silently_settled_as_no_sp():
    agent = FullSPGenerator(
        function_name="read_slot",
        function_source="int read_slot(int *p, int i) { return p[i]; }",
        sanitizer="address",
        require_context_sufficiency=True,
        verbose=False,
    )
    rows = [{
        "kind": kind,
        "subject": "indexed access",
        "source_quote": "p[i]",
        "local_status": "SUSPICIOUS",
        "missing_preconditions": ["caller extent is uncertain"],
    } for kind in agent._required_security_invariant_kinds()]
    assert agent._record_local_risk_inventory({
        "target_function": "read_slot", "operations": rows,
    })["success"] is True

    result = agent._assess_analysis_completion(_receipt(
        sufficiency="INSUFFICIENT",
        provenance="UNRESOLVED",
        writer_search="UNRESOLVED",
        evidence=[], writer_evidence=[], storage_helpers=[],
        unresolved=["caller extent is uncertain"],
        security_invariants=[{
            "kind": kind,
            "subject": "indexed access",
            "status": "UNRESOLVED",
            "evidence_functions": ["read_slot"],
            "writer_evidence_functions": [],
            "unresolved_preconditions": ["caller extent is uncertain"],
        } for kind in agent._required_security_invariant_kinds()],
    ))

    assert result["candidate_handoff_missing"] is True
    assert result["valid"] is False
    assert result["analysis_result"] == "ANALYSIS_INCOMPLETE"
    assert any("not emitted" in item
               for item in result["unresolved_preconditions"])


def test_distinct_suspicious_source_anchors_require_distinct_saved_candidates():
    agent = FullSPGenerator(
        function_name="read_pair",
        function_source=(
            "int read_pair(int *p, int i, int *q, int j) { "
            "return p[i] + q[j]; }"
        ),
        sanitizer="address",
        require_context_sufficiency=True,
        verbose=False,
    )
    required = agent._required_security_invariant_kinds()
    rows = [{
        "kind": kind,
        "subject": "first indexed access",
        "source_quote": "p[i]",
        "local_status": "SUSPICIOUS",
        "missing_preconditions": ["first backing extent is uncertain"],
    } for kind in required]
    rows.append({
        "kind": required[0],
        "subject": "second indexed access",
        "source_quote": "q[j]",
        "local_status": "SUSPICIOUS",
        "missing_preconditions": ["second backing extent is uncertain"],
    })
    assert agent._record_local_risk_inventory({
        "target_function": "read_pair", "operations": rows,
    })["success"] is True

    agent.sp_created = True
    agent.created_sp_ids.add("sp-one")
    assert agent._has_unemitted_suspicious_local_risk() is True
    agent.created_sp_ids.add("sp-two")
    assert agent._has_unemitted_suspicious_local_risk() is False


def test_requires_context_inventory_does_not_manufacture_candidate():
    agent = FullSPGenerator(
        function_name="read_slot",
        function_source="int read_slot(int *p, int i) { return p[i]; }",
        sanitizer="address",
        require_context_sufficiency=True,
        verbose=False,
    )
    agent._tools = [{"type": "function", "function": {"name": name}}
                    for name in (
                        "record_local_risk_inventory",
                        "create_suspicious_point",
                        "get_function_source", "get_callers", "search_code",
                    )]
    rows = [{
        "kind": kind,
        "subject": "indexed access",
        "source_quote": "p[i]",
        "local_status": "REQUIRES_CONTEXT",
        "missing_preconditions": ["caller extent is uncertain"],
    } for kind in agent._required_security_invariant_kinds()]
    recorded = agent._record_local_risk_inventory({
        "target_function": "read_slot", "operations": rows})

    assert recorded["suspicious_count"] == 0
    available = {row["function"]["name"]
                 for row in agent._tools_for_iteration(2, 3)}
    assert available == {"create_suspicious_point"}
    assert "INSUFFICIENT" in agent._get_urgency_message(2, 3)
    assert agent.sp_created is False


def test_large_function_must_receive_every_pinned_window_before_inventory():
    source = "\n".join(
        ["int large_target(Buffer *b) {"] +
        [f"  b->slots[{index}] += {index};" for index in range(2000)] +
        ["  return b->slots[0];", "}"]
    )
    agent = LargeFullSPGenerator(
        function_name="large_target",
        function_source=source,
        sanitizer="address",
        require_context_sufficiency=True,
        max_iterations=64,
        verbose=False,
    )
    message = agent.get_initial_message()
    agent._tools = [{"type": "function", "function": {"name": name}}
                    for name in (
                        "record_local_risk_inventory",
                        "create_suspicious_point",
                        "get_next_function_window",
                        "get_function_source", "get_callers", "search_code",
                    )]

    assert "Window 1/" in message
    assert agent.total_windows > 1
    assert agent.current_window == 1
    assert agent.minimum_strict_iterations() == agent.total_windows + 2
    assert agent.minimum_strict_iterations() > 6
    assert {row["function"]["name"]
            for row in agent._tools_for_iteration(1, 63)} == {
                "create_suspicious_point", "get_next_function_window"}

    while agent._has_unread_function_windows():
        payload = json.loads(asyncio.run(agent._execute_tool(
            None, "get_next_function_window",
            {"target_function": "large_target"},
        )))
        assert payload["success"] is True
        assert payload["source"] in source

    assert agent.current_window == agent.total_windows
    assert agent.analysis_tool_history[-1]["successful"] is True
    assert agent.analysis_tool_history[-1]["result_source"]
    available = {row["function"]["name"]
                 for row in agent._tools_for_iteration(30, 34)}
    assert available == {
        "record_local_risk_inventory", "create_suspicious_point"}


def test_local_checkpoint_contract_contains_no_target_specific_answer():
    agent = FullSPGenerator(
        function_name="scan_record",
        function_source="int scan_record(int *p, int n) { return p[n]; }",
        sanitizer="address",
        require_context_sufficiency=True,
        max_iterations=5,
        verbose=False,
    )
    message = agent.get_initial_message()
    assert "Host-enforced analysis phases" in message
    assert "record_local_risk_inventory" in message
    assert "one contiguous verbatim quote" in message
    assert "Never use `...`" in message
    assert "separate operation rows" in message
    assert "On the next turn" in message
    assert "local no-candidate" in message
    assert "md_collect_marks" not in message
    assert "md4c" not in message


def test_host_derives_generic_risk_lenses_for_multiple_bug_families():
    bounds = FullSPGenerator(
        function_name="read_entry",
        function_source="int read_entry(Table *t) { return t->rows[t->used]; }",
        sanitizer="address",
        require_context_sufficiency=True,
        verbose=False,
    )
    lifetime = FullSPGenerator(
        function_name="consume_node",
        function_source="void consume_node(Node *n) { free(n); use(n->value); }",
        sanitizer="address",
        require_context_sufficiency=True,
        verbose=False,
    )
    arithmetic = FullSPGenerator(
        function_name="scale_value",
        function_source="int scale_value(int n) { return n * 8; }",
        sanitizer="undefined",
        require_context_sufficiency=True,
        verbose=False,
    )
    initialization = FullSPGenerator(
        function_name="read_flag",
        function_source="int read_flag(void) { int flag; return flag; }",
        sanitizer="memory",
        require_context_sufficiency=True,
        verbose=False,
    )

    assert set(bounds._required_security_invariant_kinds()) == {
        "BOUNDS_EXTENT", "LIFETIME_OWNERSHIP", "NULLABILITY",
        "STATE_CONSISTENCY",
    }
    assert "LIFETIME_OWNERSHIP" in lifetime._required_security_invariant_kinds()
    assert arithmetic._required_security_invariant_kinds() == [
        "ARITHMETIC_RANGE"
    ]
    assert initialization._required_security_invariant_kinds() == [
        "INITIALIZATION"
    ]


def test_single_member_getter_does_not_force_repository_wide_state_search():
    getter = FullSPGenerator(
        function_name="node_value",
        function_source="int node_value(Node *n) { return n->value; }",
        sanitizer="address",
        require_context_sufficiency=True,
        verbose=False,
    )

    assert getter._required_security_invariant_kinds() == [
        "LIFETIME_OWNERSHIP", "NULLABILITY"
    ]


def test_generic_priority_covers_oob_uaf_integer_and_initialization_surfaces():
    fixtures = {
        "oob": ("int f(T *t, int i) { return t->rows[i + 1]; }", "address",
                "BOUNDS_EXTENT"),
        "uaf": ("void f(Node *n) { free(n); use(n->value); }", "address",
                "LIFETIME_OWNERSHIP"),
        "integer": ("int f(int n) { return (n * 8) << 1; }", "undefined",
                    "ARITHMETIC_RANGE"),
        "uninitialized": ("int f(void) { int flag; return flag; }", "memory",
                          "INITIALIZATION"),
    }

    for source, sanitizer, expected_kind in fixtures.values():
        profile = generic_security_risk_priority(source, sanitizer)
        assert profile["score"] > 0
        assert expected_kind in profile["kinds"]


def test_generic_priority_prefers_direct_multi_invariant_surface():
    wrapper = "int get_value(Node *n) { return n->value; }"
    complex_surface = """
    int consume(Table *t, int i, int n) {
        if (i + 1 < n && t->used <= t->capacity)
            return t->rows[i + 1];
        return 0;
    }
    """

    assert generic_security_risk_priority(
        complex_surface, "address")["score"] > generic_security_risk_priority(
            wrapper, "address")["score"]


def test_generic_family_priority_changes_only_the_registered_bug_family():
    bounds = "int f(T *t, int i) { return t->rows[i + 1]; }"
    lifetime = "void f(Node *n) { free(n); use(n->value); }"
    arithmetic = "int f(int n) { return (n * 8) << 1; }"
    initialized = "int f(void) { int flag = 0; return flag; }"
    uninitialized = "int f(void) { int flag; return flag; }"

    assert generic_security_family_priority(
        bounds, "address", "BOUNDS_EXTENT")["family_score"] > 0
    assert generic_security_family_priority(
        lifetime, "address", "LIFETIME_OWNERSHIP")["family_score"] > \
        generic_security_family_priority(
            bounds, "address", "LIFETIME_OWNERSHIP")["family_score"]
    assert generic_security_family_priority(
        arithmetic, "undefined", "ARITHMETIC_RANGE")["family_score"] > 0
    assert generic_security_family_priority(
        uninitialized, "memory", "INITIALIZATION")["family_score"] > \
        generic_security_family_priority(
            initialized, "memory", "INITIALIZATION")["family_score"]


def test_unary_pointer_dereference_is_not_ranked_as_multiplication():
    dereference = "int read_ptr(int *p) { return *p; }"
    multiplication = "int scale_value(int n) { return n * 8; }"

    dereference_profile = generic_security_risk_priority(
        dereference, "undefined")
    multiplication_profile = generic_security_risk_priority(
        multiplication, "undefined")

    assert dereference_profile["arithmetic_operations"] == 0
    assert "ARITHMETIC_RANGE" not in dereference_profile["kinds"]
    assert "NULLABILITY" in dereference_profile["kinds"]
    assert multiplication_profile["arithmetic_operations"] == 1
    assert "ARITHMETIC_RANGE" in multiplication_profile["kinds"]


def test_cast_then_dereference_is_not_confused_with_parenthesized_multiply():
    cast_dereferences = [
        "int f(char *p) { return (int) *p; }",
        "long f(char *p) { return (unsigned long)*p; }",
        "long f(char *p) { return (const unsigned long) *p; }",
        "long f(char *p) { return (long)*p; }",
        "unsigned f(char *p) { return (unsigned) *p; }",
        "size_t f(char *p) { return (size_t)*p; }",
        "int f(char *p) { return (_Atomic int)*p; }",
        "int f(char *p) { return (const custom_type)*p; }",
    ]
    parenthesized_multiply = (
        "int scale_value(int a, int b) { return (a) * b; }"
    )

    multiply_profile = generic_security_risk_priority(
        parenthesized_multiply, "undefined")

    for cast_dereference in cast_dereferences:
        cast_profile = generic_security_risk_priority(
            cast_dereference, "undefined")
        assert cast_profile["arithmetic_operations"] == 0
        assert "ARITHMETIC_RANGE" not in cast_profile["kinds"]
        assert "NULLABILITY" in cast_profile["kinds"]
    assert multiply_profile["arithmetic_operations"] == 1
    assert "ARITHMETIC_RANGE" in multiply_profile["kinds"]


def test_pointer_named_n_is_not_treated_as_its_own_length_parameter():
    getter = FullSPGenerator(
        function_name="node_value",
        function_source="int node_value(Node *n) { return n->value; }",
        sanitizer="address",
        require_context_sufficiency=True,
        verbose=False,
    )
    pointer_and_count = FullSPGenerator(
        function_name="read_item",
        function_source=(
            "int read_item(Item *items, int n_items) { return items[n_items]; }"
        ),
        sanitizer="address",
        require_context_sufficiency=True,
        verbose=False,
    )

    assert getter._has_pointer_length_precondition() is False
    assert pointer_and_count._has_pointer_length_precondition() is True


def test_negative_completion_rejects_missing_required_invariant_kind():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers", "arguments": {"function_name": "forward_items"},
         "successful": True, "result_callers": []},
        {"name": "get_function_source", "arguments": {"function_name": "make_items"},
         "successful": True},
    ]
    receipt = _receipt(
        writer_search="NOT_APPLICABLE",
        writer_evidence=[],
        storage_helpers=[],
        security_invariants=[{
            "kind": "BOUNDS_EXTENT",
            "subject": "items extent",
            "status": "ESTABLISHED",
            "evidence_functions": ["inspect"],
            "writer_evidence_functions": [],
            "unresolved_preconditions": [],
        }],
    )

    result = agent._assess_analysis_completion(receipt)

    assert result["required_invariants_covered"] is False
    assert result["valid"] is False
    assert result["analysis_result"] == "ANALYSIS_INCOMPLETE"


def test_shared_state_negative_requires_inspected_writer_evidence():
    agent = FullSPGenerator(
        function_name="read_entry",
        function_source="int read_entry(Table *t) { return t->rows[t->used]; }",
        sanitizer="address",
        require_context_sufficiency=True,
        verbose=False,
    )
    inventory = agent._record_local_risk_inventory({
        "target_function": "read_entry",
        "operations": [{
            "kind": kind,
            "subject": f"fixture {kind.lower()} relationship",
            "source_quote": "t->rows[t->used]",
            "local_status": "REQUIRES_CONTEXT",
            "missing_preconditions": ["writer invariant is required"],
        } for kind in agent._required_security_invariant_kinds()],
    })
    assert inventory["success"] is True
    rows = [
        {
            "kind": kind,
            "subject": kind.lower(),
            "status": "ESTABLISHED",
            "evidence_functions": ["read_entry"],
            "writer_evidence_functions": (
                ["update_table"] if kind == "STATE_CONSISTENCY" else []
            ),
            "unresolved_preconditions": [],
        }
        for kind in agent._required_security_invariant_kinds()
    ]
    receipt = _receipt(
        provenance="NOT_APPLICABLE",
        writer_search="ESTABLISHED",
        evidence=["read_entry"],
        writer_evidence=["update_table"],
        storage_helpers=[],
        security_invariants=rows,
    )
    agent.analysis_tool_history = [
        {"name": "search_code", "arguments": {"pattern": "rows|used"},
         "successful": True, "result_search_truncated": False,
         "result_search_evidence": ["t->rows = replacement;"]},
    ]

    rejected = agent._assess_analysis_completion(receipt)
    assert rejected["writer_evidence_inspected"] is False
    assert rejected["valid"] is False

    agent.analysis_tool_history.append({
        "name": "get_function_source",
        "arguments": {"function_name": "update_table"},
        "successful": True,
        "result_source": (
            "void update_table(Table *t) { t->rows = replacement; }"
        ),
    })
    accepted = agent._assess_analysis_completion(receipt)
    assert accepted["writer_contract_valid"] is True
    assert accepted["required_invariants_covered"] is True
    assert accepted["valid"] is True


def test_unresolved_generic_invariant_is_incomplete_not_safe_zero():
    agent = FullSPGenerator(
        function_name="scale_value",
        function_source="int scale_value(int n) { return n * 8; }",
        sanitizer="undefined",
        require_context_sufficiency=True,
        verbose=False,
    )
    receipt = _receipt(
        sufficiency="INSUFFICIENT",
        provenance="NOT_APPLICABLE",
        writer_search="NOT_APPLICABLE",
        evidence=[],
        writer_evidence=[],
        storage_helpers=[],
        unresolved=["input range not established"],
        security_invariants=[{
            "kind": "ARITHMETIC_RANGE",
            "subject": "multiplication range",
            "status": "UNRESOLVED",
            "evidence_functions": ["scale_value"],
            "writer_evidence_functions": [],
            "unresolved_preconditions": ["input range not established"],
        }],
    )

    result = agent._assess_analysis_completion(receipt)

    assert result["valid"] is True
    assert result["analysis_complete"] is False
    assert result["context_sufficiency"] == "INSUFFICIENT"


def test_durable_query_index_deduplicates_without_target_knowledge():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers", "arguments": {"function_name": "inspect"},
         "successful": True},
        {"name": "get_function_source",
         "arguments": {"function_name": "forward_items"},
         "successful": True},
        {"name": "search_code", "arguments": {"pattern": "items|n_items"},
         "successful": True},
        {"name": "search_code", "arguments": {"pattern": "items|n_items"},
         "successful": True},
        {"name": "get_function_source",
         "arguments": {"function_name": "forward_items"},
         "successful": True},
        {"name": "create_suspicious_point", "arguments": {
            "function_name": "inspect"}},
    ]
    index = agent._durable_analysis_index()
    assert index.count("get_callers(inspect)") == 1
    assert index.count("get_function_source(forward_items)") == 1
    assert index.count("search_code(items|n_items)") == 1
    assert "create_suspicious_point" not in index


def test_pointer_count_negative_rejects_writer_name_without_source_evidence():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers", "arguments": {"function_name": "inspect"}},
        {"name": "get_callers", "arguments": {"function_name": "forward_items"}},
        {"name": "get_function_source",
         "arguments": {"function_name": "make_items"},
         "successful": True},
        {"name": "search_code", "arguments": {"pattern": "items|n_items"},
         "successful": True},
    ]
    result = agent._assess_analysis_completion(_receipt())
    assert result["writer_evidence_inspected"] is False
    assert result["valid"] is False
    assert result["analysis_result"] == "ANALYSIS_INCOMPLETE"


def test_pointer_count_negative_rejects_failed_writer_search():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers", "arguments": {"function_name": "inspect"}},
        {"name": "get_callers", "arguments": {"function_name": "forward_items"}},
        {"name": "get_function_source",
         "arguments": {"function_name": "make_items"},
         "successful": True},
        {"name": "search_code", "arguments": {"pattern": "items|n_items"},
         "successful": False},
        {"name": "get_function_source",
         "arguments": {"function_name": "resize_items"},
         "successful": True},
        {"name": "get_callers", "arguments": {"function_name": "resize_items"},
         "successful": True, "result_callers": ["grow_items"]},
        {"name": "get_function_source",
         "arguments": {"function_name": "grow_items"},
         "successful": True},
    ]
    result = agent._assess_analysis_completion(_receipt())
    assert result["shared_state_search_performed"] is False
    assert result["valid"] is False


def test_pointer_count_negative_rejects_truncated_writer_search():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers", "arguments": {"function_name": "inspect"}},
        {"name": "get_callers", "arguments": {"function_name": "forward_items"}},
        {"name": "get_function_source",
         "arguments": {"function_name": "make_items"},
         "successful": True},
        {"name": "search_code", "arguments": {"pattern": "items|n_items"},
         "successful": True, "result_search_truncated": True},
        {"name": "get_function_source",
         "arguments": {"function_name": "resize_items"},
         "successful": True},
        {"name": "get_callers", "arguments": {"function_name": "resize_items"},
         "successful": True, "result_callers": ["grow_items"]},
        {"name": "get_function_source",
         "arguments": {"function_name": "grow_items"},
         "successful": True},
    ]

    result = agent._assess_analysis_completion(_receipt())

    assert result["shared_state_search_performed"] is False
    assert result["writer_contract_valid"] is False
    assert result["valid"] is False
    assert result["analysis_result"] == "ANALYSIS_INCOMPLETE"


def test_execute_tool_records_truncated_search_result():
    agent = _agent()
    payload = json.dumps({
        "success": True,
        "matches": [{
            "file": "fixture.c", "line": 1,
            "content": "items = resize(items, n_items);",
            "context": ["if (items != 0)", "items = resize(items, n_items);"],
        }],
        "truncated": True,
    })

    with patch(
        "fuzzingbrain.agents.base.BaseAgent._execute_tool",
        new=AsyncMock(return_value=payload),
    ):
        returned = asyncio.run(agent._execute_tool(
            None, "search_code", {"pattern": "items|n_items"}
        ))

    assert returned == payload
    assert agent.analysis_tool_history[-1]["successful"] is True
    assert agent.analysis_tool_history[-1]["result_search_truncated"] is True
    assert "items = resize(items, n_items);" in (
        agent.analysis_tool_history[-1]["result_search_evidence"])


def test_execute_tool_records_bound_function_source():
    agent = _agent()
    payload = json.dumps({
        "success": True,
        "function_name": "resize_items",
        "source": "void resize_items(void) { items = resize(items, n_items); }",
    })

    with patch(
        "fuzzingbrain.agents.base.BaseAgent._execute_tool",
        new=AsyncMock(return_value=payload),
    ):
        asyncio.run(agent._execute_tool(
            None, "get_function_source", {"function_name": "resize_items"}
        ))

    assert agent.analysis_tool_history[-1]["result_source"] == (
        "void resize_items(void) { items = resize(items, n_items); }"
    )


def test_pointer_count_negative_rejects_unrelated_caller_lineage():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers",
         "arguments": {"function_name": "unrelated_helper"},
         "successful": True, "result_callers": ["unrelated_caller"],
         "result_callers_truncated": False},
        {"name": "get_function_source",
         "arguments": {"function_name": "make_items"},
         "successful": True,
         "result_source": "void make_items(void) { inspect(items, n_items); }"},
    ]

    result = agent._assess_analysis_completion(_receipt(
        writer_search="NOT_APPLICABLE", writer_evidence=[], storage_helpers=[]
    ))

    assert result["provenance_evidence_linked"] is False
    assert result["recursive_caller_lookup"] is False
    assert result["valid"] is False


def test_shared_state_negative_rejects_unrelated_search_evidence():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers", "arguments": {"function_name": "inspect"},
         "successful": True, "result_callers": ["forward_items"],
         "result_callers_truncated": False},
        {"name": "get_callers", "arguments": {"function_name": "forward_items"},
         "successful": True, "result_callers": ["make_items"],
         "result_callers_truncated": False},
        {"name": "get_function_source", "arguments": {"function_name": "make_items"},
         "successful": True,
         "result_source": "void make_items(void) { inspect(items, n_items); }"},
        {"name": "search_code", "arguments": {"pattern": "unrelated_token"},
         "successful": True, "result_search_truncated": False,
         "result_search_evidence": ["int unrelated_token = 1;"]},
        {"name": "get_function_source", "arguments": {"function_name": "resize_items"},
         "successful": True,
         "result_source": "void resize_items(void) { items = resize(items, n_items); }"},
        {"name": "get_callers", "arguments": {"function_name": "resize_items"},
         "successful": True, "result_callers": ["grow_items"],
         "result_callers_truncated": False},
        {"name": "get_function_source", "arguments": {"function_name": "grow_items"},
         "successful": True,
         "result_source": "void grow_items(void) { resize_items(); }"},
    ]

    result = agent._assess_analysis_completion(_receipt())

    assert result["writer_search_bound_functions"] == []
    assert result["shared_state_search_performed"] is False
    assert result["writer_contract_valid"] is False
    assert result["valid"] is False


def test_pointer_count_negative_requires_every_shared_helper_caller():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers", "arguments": {"function_name": "inspect"}},
        {"name": "get_callers", "arguments": {"function_name": "forward_items"}},
        {"name": "get_function_source",
         "arguments": {"function_name": "make_items"},
         "successful": True},
        {"name": "search_code", "arguments": {"pattern": "items|n_items"},
         "successful": True},
        {"name": "get_function_source",
         "arguments": {"function_name": "resize_items"},
         "successful": True},
        {"name": "get_callers", "arguments": {"function_name": "resize_items"},
         "successful": True, "result_callers": ["grow_items", "replace_items"]},
        {"name": "get_function_source",
         "arguments": {"function_name": "grow_items"},
         "successful": True},
    ]
    result = agent._assess_analysis_completion(_receipt(storage_helpers=[{
        "function": "resize_items",
        "candidate_callers": ["grow_items", "replace_items"],
        "reviewed_callers": ["grow_items"],
    }]))
    assert result["helper_callers_complete"] is False
    assert result["valid"] is False


def test_durable_index_preserves_complete_caller_result():
    agent = _agent()
    agent.analysis_tool_history = [{
        "name": "get_callers",
        "arguments": {"function_name": "resize_items"},
        "successful": True,
        "result_callers": ["grow_items", "replace_items"],
    }]
    index = agent._durable_analysis_index()
    assert "get_callers(resize_items) => [grow_items, replace_items]" in index


def test_durable_index_marks_truncated_search_result():
    agent = _agent()
    agent.analysis_tool_history = [{
        "name": "search_code",
        "arguments": {"pattern": "items|n_items"},
        "successful": True,
        "result_search_truncated": True,
    }]

    assert "search_code(items|n_items) (TRUNCATED)" in agent._durable_analysis_index()


def test_durable_index_does_not_call_failed_queries_completed():
    agent = _agent()
    agent.analysis_tool_history = [{
        "name": "get_function_source",
        "arguments": {"function_name": "missing_source"},
        "successful": False,
    }]

    assert "missing_source" not in agent._durable_analysis_index()


def test_full_sp_keeps_exact_evidence_when_transcript_fits_bridge_cap():
    agent = _agent()
    agent.llm_client = SimpleNamespace(max_payload_chars=500_000)
    agent._tools = []
    agent.messages = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "task"},
        {"role": "tool", "tool_call_id": "t1", "content": "exact evidence"},
    ]
    before = list(agent.messages)

    with patch(
        "fuzzingbrain.agents.base.BaseAgent._compress_context",
        new=AsyncMock(),
    ) as lossy:
        asyncio.run(agent._compress_context())

    lossy.assert_not_awaited()
    assert agent.messages == before


def test_oversized_full_sp_compression_retains_host_inventory_checkpoint():
    agent = _agent()
    agent.llm_client = SimpleNamespace(max_payload_chars=4096)
    agent._tools = []
    agent.messages = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "x" * 5000},
    ]
    agent.analysis_tool_history = [{
        "name": "get_callers",
        "arguments": {"function_name": "inspect"},
        "successful": True,
        "result_callers": ["caller"],
        "result_callers_truncated": False,
    }]

    async def compress_stub(_self):
        _self.messages = [{"role": "user", "content": "lossy summary"}]

    with patch(
        "fuzzingbrain.agents.base.BaseAgent._compress_context",
        new=compress_stub,
    ):
        asyncio.run(agent._compress_context())

    checkpoint = agent.messages[-1]["content"]
    assert "FBV2_HOST_EVIDENCE_CHECKPOINT" in checkpoint
    assert "items[i]" in checkpoint
    assert "get_callers(inspect) => [caller]" in checkpoint
    assert "Treat evidence absent" in checkpoint


def test_truncated_caller_receipt_cannot_complete_analysis():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers",
         "arguments": {"function_name": "forward_items"},
         "successful": True, "result_callers": ["make_items"],
         "result_callers_truncated": True},
        {"name": "get_function_source",
         "arguments": {"function_name": "make_items"},
         "successful": True},
    ]

    result = agent._assess_analysis_completion(_receipt(
        writer_search="NOT_APPLICABLE",
        writer_evidence=[],
        storage_helpers=[],
    ))

    assert result["recursive_caller_lookup"] is False
    assert result["valid"] is False


def test_failed_source_and_recursive_lookup_cannot_complete_analysis():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers",
         "arguments": {"function_name": "forward_items"},
         "successful": False, "result_callers": []},
        {"name": "get_function_source",
         "arguments": {"function_name": "make_items"},
         "successful": False},
        {"name": "get_function_source",
         "arguments": {"function_name": "resize_items"},
         "successful": False},
        {"name": "search_code", "arguments": {"pattern": "unrelated"},
         "successful": True},
    ]

    result = agent._assess_analysis_completion(_receipt())

    assert result["recursive_caller_lookup"] is False
    assert result["evidence_inspected"] is False
    assert result["writer_evidence_inspected"] is False
    assert result["valid"] is False


def test_no_shared_storage_helper_can_be_explicitly_not_applicable():
    agent = _agent()
    agent.analysis_tool_history = [
        {"name": "get_callers",
         "arguments": {"function_name": "inspect"},
         "successful": True, "result_callers": ["forward_items"],
         "result_callers_truncated": False},
        {"name": "get_callers",
         "arguments": {"function_name": "forward_items"},
         "successful": True, "result_callers": ["make_items"],
         "result_callers_truncated": False},
        {"name": "get_function_source",
         "arguments": {"function_name": "make_items"},
         "successful": True,
         "result_source": "void make_items(void) { inspect(items, n_items); }"},
    ]

    result = agent._assess_analysis_completion(_receipt(
        writer_search="NOT_APPLICABLE",
        writer_evidence=[],
        storage_helpers=[],
    ))

    assert result["evidence_inspected"] is True
    assert result["writer_contract_valid"] is True
    assert result["helper_callers_complete"] is True
    assert result["valid"] is True
    assert result["analysis_complete"] is True
