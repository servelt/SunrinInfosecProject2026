"""Provider-free contract checks for per-assumption HP evidence closure."""

import asyncio

import pytest

from vulnerabilityanalysis.agents import AgentPipeline
ASSUMPTION = "The selected pointer remains valid at the guarded read"
LOCATION = "target.c:7"
PROPERTY = "valid memory read"
SOURCE = (
    "int target(const char *pointer) {\n"
    "  int checked = 1;\n"
    "  if (!checked) return 0;\n"
    "  if (!pointer) return 0;\n"
    "  checked += 1;\n"
    "  (void)checked;\n"
    "  return *pointer;\n"
    "}\n"
)


class Provider:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    async def generate(self, request):
        self.requests.append(request)
        return next(self.responses)


def _response(*, safe=True, rows=None, requests=None):
    return {
        "summary": "bounded read reviewed",
        "input_flow": "input selects the guarded path",
        "state_dependencies": [],
        "context_requests": requests or [],
        "safe_assumptions": [ASSUMPTION] if safe else [],
        "unknowns": [],
        "input_sources": ["data"],
        "security_sensitive_operations": ["*pointer"],
        "validations": [],
        "memory_operations": ["read pointer"],
        "evidence": ["target.c:7"],
        "hypothesis_evaluations": ([{
            "source_location": LOCATION,
            "security_property": PROPERTY,
            "source_file": "target.c",
            "source_line": 7,
            "source_quote": "return *pointer;",
            "input_influence": "INPUT_DEPENDENT",
            "hypothesis": "pointer may be invalid",
            "judgment": "EXPLICIT_SAFE_JUDGMENT",
            "reason": "the pinned owner remains live",
            "safe_assumption": ASSUMPTION,
        }] if safe else []),
        "safe_assumption_lifecycle": rows or [],
    }


def _row(disposition, *, assumption_id="", required=None,
         location=LOCATION, security_property=PROPERTY, evidence=None):
    return {
        "assumption_id": assumption_id,
        "safe_assumption": ASSUMPTION,
        "source_location": location,
        "security_property": security_property,
        "disposition": disposition,
        "reason": "provider-free evidence disposition",
        "required_context": required or [],
        "evidence_dependencies": (
            ["SELECTED_SOURCE"] if evidence is None else evidence),
    }


async def _analyze(pipeline, *, prior=None, source_file="target.c"):
    return await pipeline.analyze_function(
        "fn-target", "target", source_file, SOURCE,
        assumption_lifecycle_contract={
            "kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V4",
            "omission": "INCOMPLETE",
            "available_evidence": [{"evidence_id": "SELECTED_SOURCE"}],
        },
        prior_safe_assumptions=prior or [],
    )


def test_validated_safe_gets_stable_host_id_and_is_assertion_eligible():
    provider = Provider([_response(rows=[_row("VALIDATED_SAFE")])])
    analysis = asyncio.run(_analyze(AgentPipeline(provider)))
    assert analysis.safe_assumptions == [ASSUMPTION]
    lifecycle = analysis.safe_assumption_lifecycle
    assert lifecycle[0]["assumption_id"].startswith("safe-")
    assert lifecycle[0]["disposition"] == "VALIDATED_SAFE"
    assert provider.requests[0].payload["prior_safe_assumptions"] == []


def test_same_safe_text_at_two_source_identities_is_not_assertion_eligible():
    response = _response(rows=[
        _row("VALIDATED_SAFE"),
        _row("VALIDATED_SAFE", location="target.c:4",
             security_property="entry pointer guard"),
    ])
    duplicate = dict(response["hypothesis_evaluations"][0])
    duplicate.update({
        "source_location": "target.c:4", "source_line": 4,
        "source_quote": "if (!pointer) return 0;",
        "security_property": "entry pointer guard",
    })
    response["hypothesis_evaluations"].append(duplicate)
    analysis = asyncio.run(_analyze(AgentPipeline(Provider([response]))))
    assert analysis.safe_assumptions == []
    assert len(analysis.safe_assumption_lifecycle) == 2
    assert all(row["disposition"] == "INCOMPLETE"
               for row in analysis.safe_assumption_lifecycle)
    assert all("ambiguous SAFE text" in row["reason"]
               for row in analysis.safe_assumption_lifecycle)


def test_candidate_with_unresolved_dependency_cannot_be_validated():
    response = _response(rows=[_row(
        "VALIDATED_SAFE", required=[{"target": "owner", "request_type": "FUNCTION"}])])
    analysis = asyncio.run(_analyze(AgentPipeline(Provider([response]))))
    assert analysis.safe_assumptions == []
    assert analysis.safe_assumption_lifecycle[0]["disposition"] == "INCOMPLETE"


def test_unbound_evidence_id_cannot_close_a_safe_candidate():
    row = _row("VALIDATED_SAFE")
    row["evidence_dependencies"] = ["MODEL_INVENTED_EVIDENCE"]
    analysis = asyncio.run(_analyze(AgentPipeline(Provider([
        _response(rows=[row])]))))
    assert analysis.safe_assumptions == []
    assert analysis.safe_assumption_lifecycle[0]["disposition"] == "INCOMPLETE"
    assert "unbound evidence" in analysis.safe_assumption_lifecycle[0]["reason"]


def test_prior_candidate_must_be_explicitly_reclassified_not_silently_omitted():
    first_provider = Provider([_response(rows=[_row("PROPOSED")])])
    first = asyncio.run(_analyze(AgentPipeline(first_provider)))
    prior = first.safe_assumption_lifecycle
    second = _response(safe=False, rows=[])
    analysis = asyncio.run(_analyze(AgentPipeline(Provider([second])), prior=prior))
    assert analysis.safe_assumptions == []
    assert analysis.safe_assumption_lifecycle[0]["disposition"] == "INCOMPLETE"
    assert analysis.safe_assumption_lifecycle[0]["reason"] == (
        "OMITTED_PRIOR_SAFE_DISPOSITION")


def test_parse_array_style_reclassification_is_not_promoted_to_assertion():
    first = asyncio.run(_analyze(AgentPipeline(Provider([
        _response(rows=[_row("PROPOSED")])]))))
    assumption_id = first.safe_assumption_lifecycle[0]["assumption_id"]
    second_response = _response(
        safe=False, rows=[_row("RECLASSIFIED_VALIDATION",
                              assumption_id=assumption_id)])
    second_response["validations"] = [
        "The existing increment and guard prevent offset underflow."]
    second = asyncio.run(_analyze(
        AgentPipeline(Provider([second_response])),
        prior=first.safe_assumption_lifecycle))
    assert second.safe_assumptions == []
    assert second.safe_assumption_lifecycle[0]["disposition"] == (
        "RECLASSIFIED_VALIDATION")


@pytest.mark.parametrize("disposition", ["INVALIDATED", "ASSERTION_INELIGIBLE"])
def test_terminal_non_safe_disposition_never_reaches_assertion(disposition):
    first = asyncio.run(_analyze(AgentPipeline(Provider([
        _response(rows=[_row("PROPOSED")])]))))
    assumption_id = first.safe_assumption_lifecycle[0]["assumption_id"]
    final = asyncio.run(_analyze(AgentPipeline(Provider([
        _response(safe=False, rows=[_row(
            disposition, assumption_id=assumption_id)])
    ])), prior=first.safe_assumption_lifecycle))
    assert final.safe_assumptions == []
    assert final.safe_assumption_lifecycle[0]["disposition"] == disposition


def test_wrong_prior_id_is_rejected_instead_of_rebound_by_text():
    prior = _row("PROPOSED", assumption_id="safe-known")
    response = _response(rows=[_row("VALIDATED_SAFE", assumption_id="safe-other")])
    with pytest.raises(ValueError, match="unknown prior ID"):
        asyncio.run(_analyze(AgentPipeline(Provider([response])), prior=[prior]))


def test_same_safe_text_at_a_different_location_cannot_validate_prior_id():
    first = asyncio.run(_analyze(AgentPipeline(Provider([
        _response(rows=[_row("PROPOSED")])]))))
    assumption_id = first.safe_assumption_lifecycle[0]["assumption_id"]
    response = _response(rows=[_row(
        "VALIDATED_SAFE", assumption_id=assumption_id)])
    response["hypothesis_evaluations"][0]["source_location"] = "target.c:6"
    response["hypothesis_evaluations"][0]["source_line"] = 6
    response["hypothesis_evaluations"][0]["source_quote"] = "(void)checked;"
    analysis = asyncio.run(_analyze(
        AgentPipeline(Provider([response])),
        prior=first.safe_assumption_lifecycle))
    assert analysis.safe_assumptions == []
    assert analysis.safe_assumption_lifecycle[0]["disposition"] == "INCOMPLETE"
    assert "pinned-source SAFE identity" in (
        analysis.safe_assumption_lifecycle[0]["reason"])


@pytest.mark.parametrize("location", [
    "unrelated.c:7", "/nonexistent/foreign.c:7", "../target.c:7",
])
def test_source_location_file_must_resolve_to_selected_pinned_source(location):
    response = _response(rows=[_row(
        "VALIDATED_SAFE", location=location)])
    response["hypothesis_evaluations"][0]["source_location"] = location
    with pytest.raises(ValueError, match="pinned source identity"):
        asyncio.run(_analyze(AgentPipeline(Provider([response]))))


@pytest.mark.parametrize("field,value", [
    ("source_line", 999),
    ("source_quote", "return pointer[999];"),
    ("source_file", "other.c"),
    ("source_file", "arget.c"),
])
def test_validated_safe_requires_real_pinned_source_line_and_quote(field, value):
    response = _response(rows=[_row("VALIDATED_SAFE")])
    response["hypothesis_evaluations"][0][field] = value
    with pytest.raises(ValueError, match="pinned source"):
        asyncio.run(_analyze(AgentPipeline(Provider([response]))))


@pytest.mark.parametrize("terminal", [
    "INVALIDATED", "RECLASSIFIED_VALIDATION", "INCOMPLETE",
    "ASSERTION_INELIGIBLE",
])
def test_terminal_disposition_cannot_be_revived_as_validated_safe(terminal):
    prior = _row(terminal, assumption_id="safe-terminal")
    response = _response(rows=[_row(
        "VALIDATED_SAFE", assumption_id="safe-terminal")])
    with pytest.raises(ValueError, match="terminal disposition changed"):
        asyncio.run(_analyze(
            AgentPipeline(Provider([response])), prior=[prior]))


def test_terminal_identity_cannot_be_reintroduced_as_a_new_candidate():
    prior = _row("INVALIDATED", assumption_id="safe-terminal")
    response = _response(rows=[_row("VALIDATED_SAFE")])
    with pytest.raises(ValueError, match="known canonical identity"):
        asyncio.run(_analyze(
            AgentPipeline(Provider([response])), prior=[prior]))


def test_terminal_identity_cannot_be_reintroduced_by_property_synonym():
    prior = _row(
        "INVALIDATED", assumption_id="safe-terminal",
        security_property="bounded read")
    current_prior = _row(
        "INVALIDATED", assumption_id="safe-terminal",
        security_property="bounded read")
    current_new = _row(
        "VALIDATED_SAFE", security_property="read remains within bounds")
    response = _response(rows=[current_prior, current_new])
    response["hypothesis_evaluations"][0]["security_property"] = (
        "read remains within bounds")
    with pytest.raises(ValueError, match="known canonical identity"):
        asyncio.run(_analyze(
            AgentPipeline(Provider([response])), prior=[prior]))


def test_terminal_anchor_cannot_be_reintroduced_by_assumption_paraphrase():
    prior = _row("INVALIDATED", assumption_id="safe-terminal")
    paraphrase = "The selected pointer cannot be invalid at this guarded read"
    current_prior = _row("INVALIDATED", assumption_id="safe-terminal")
    current_new = _row("VALIDATED_SAFE", security_property="bounded dereference")
    current_new["safe_assumption"] = paraphrase
    response = _response(rows=[current_prior, current_new])
    response["safe_assumptions"] = [paraphrase]
    response["hypothesis_evaluations"][0].update({
        "security_property": "bounded dereference",
        "safe_assumption": paraphrase,
    })
    with pytest.raises(ValueError, match="terminal source anchor"):
        asyncio.run(_analyze(
            AgentPipeline(Provider([response])), prior=[prior]))


@pytest.mark.parametrize("transition,new_first", [
    ("INVALIDATED", False), ("INVALIDATED", True), ("OMITTED", False),
])
def test_current_round_terminal_anchor_cannot_be_rebased(
        transition, new_first):
    prior = _row("PROPOSED", assumption_id="safe-open")
    paraphrase = "The selected pointer cannot be invalid at this guarded read"
    current_new = _row("VALIDATED_SAFE", security_property="bounded dereference")
    current_new["safe_assumption"] = paraphrase
    rows = [current_new]
    if transition != "OMITTED":
        terminal_row = _row(transition, assumption_id="safe-open")
        rows = ([current_new, terminal_row] if new_first else
                [terminal_row, current_new])
    response = _response(rows=rows)
    response["safe_assumptions"] = [paraphrase]
    response["hypothesis_evaluations"][0].update({
        "security_property": "bounded dereference",
        "safe_assumption": paraphrase,
    })
    with pytest.raises(ValueError, match="terminal source anchor"):
        asyncio.run(_analyze(
            AgentPipeline(Provider([response])), prior=[prior]))


def _preseed_same_anchor_aliases(*, second_location=LOCATION):
    second_assumption = (
        "The selected pointer cannot be invalid at this guarded read")
    second_property = "bounded dereference"
    first = _response(safe=False)
    first["hypothesis_evaluations"] = [
        {
            "source_location": LOCATION, "security_property": PROPERTY,
            "source_file": "target.c", "source_line": 7,
            "source_quote": "return *pointer;",
            "input_influence": "UNKNOWN", "hypothesis": "pointer may be invalid",
            "judgment": "UNKNOWN", "reason": "more evidence is required",
            "safe_assumption": "",
        },
        {
            "source_location": second_location,
            "security_property": second_property,
            "source_file": "target.c",
            "source_line": 6 if second_location.endswith(":6") else 7,
            "source_quote": (
                "(void)checked;" if second_location.endswith(":6") else
                "return *pointer;"),
            "input_influence": "UNKNOWN",
            "hypothesis": "the guarded read may lack a live pointer",
            "judgment": "UNKNOWN", "reason": "more evidence is required",
            "safe_assumption": "",
        },
    ]
    first_a = _row("PROPOSED")
    first_b = _row(
        "PROPOSED", location=second_location,
        security_property=second_property)
    first_b["safe_assumption"] = second_assumption
    first["safe_assumption_lifecycle"] = [first_a, first_b]
    analysis = asyncio.run(_analyze(AgentPipeline(Provider([first]))))
    return analysis.safe_assumption_lifecycle, second_assumption, second_property


@pytest.mark.parametrize("variant", [
    "terminal_first", "validated_first", "omitted_terminal",
])
def test_preseeded_alias_cannot_validate_against_terminal_anchor(variant):
    prior, second_assumption, second_property = _preseed_same_anchor_aliases()
    terminal = dict(prior[0])
    terminal["disposition"] = "INVALIDATED"
    validated = dict(prior[1])
    validated["disposition"] = "VALIDATED_SAFE"
    rows = [terminal, validated]
    if variant == "validated_first":
        rows.reverse()
    elif variant == "omitted_terminal":
        rows = [validated]
    response = _response(rows=rows)
    response["safe_assumptions"] = [second_assumption]
    response["hypothesis_evaluations"][0].update({
        "security_property": second_property,
        "safe_assumption": second_assumption,
    })
    with pytest.raises(ValueError, match="terminal source anchor conflict"):
        asyncio.run(_analyze(
            AgentPipeline(Provider([response])), prior=prior))


def test_preseeded_candidate_at_different_line_can_validate_independently():
    prior, second_assumption, second_property = _preseed_same_anchor_aliases(
        second_location="target.c:6")
    terminal = dict(prior[0])
    terminal["disposition"] = "INVALIDATED"
    validated = dict(prior[1])
    validated["disposition"] = "VALIDATED_SAFE"
    response = _response(rows=[terminal, validated])
    response["safe_assumptions"] = [second_assumption]
    response["hypothesis_evaluations"][0].update({
        "source_location": "target.c:6", "source_line": 6,
        "source_quote": "(void)checked;",
        "security_property": second_property,
        "safe_assumption": second_assumption,
    })
    analysis = asyncio.run(_analyze(
        AgentPipeline(Provider([response])), prior=prior))
    assert analysis.safe_assumptions == [second_assumption]
    assert [row["disposition"] for row in
            analysis.safe_assumption_lifecycle] == [
                "INVALIDATED", "VALIDATED_SAFE"]


@pytest.mark.parametrize("alias_kind", ["relative", "absolute"])
def test_terminal_identity_cannot_be_reintroduced_through_path_alias(
        tmp_path, alias_kind):
    selected = tmp_path / "checkout" / "src" / "target.c"
    prior = _row(
        "INVALIDATED", assumption_id="safe-terminal", location="target.c:7")
    alias = ("src/target.c:7" if alias_kind == "relative" else
             f"{selected}:7")
    current_prior = _row(
        "INVALIDATED", assumption_id="safe-terminal", location="target.c:7")
    current_new = _row("VALIDATED_SAFE", location=alias)
    response = _response(rows=[current_prior, current_new])
    response["hypothesis_evaluations"][0]["source_location"] = alias
    response["hypothesis_evaluations"][0]["source_file"] = (
        "src/target.c" if alias_kind == "relative" else str(selected))
    with pytest.raises(ValueError, match="known canonical identity"):
        asyncio.run(_analyze(
            AgentPipeline(Provider([response])), prior=[prior],
            source_file=str(selected)))


def test_different_real_source_line_remains_an_independent_candidate(tmp_path):
    selected = tmp_path / "checkout" / "src" / "target.c"
    prior = _row(
        "INVALIDATED", assumption_id="safe-terminal", location="target.c:7")
    current_prior = _row(
        "INVALIDATED", assumption_id="safe-terminal", location="target.c:7")
    current_new = _row("VALIDATED_SAFE", location="src/target.c:6")
    response = _response(rows=[current_prior, current_new])
    evaluation = response["hypothesis_evaluations"][0]
    evaluation.update({
        "source_location": "src/target.c:6",
        "source_file": "src/target.c",
        "source_line": 6,
        "source_quote": "(void)checked;",
    })
    analysis = asyncio.run(_analyze(
        AgentPipeline(Provider([response])), prior=[prior],
        source_file=str(selected)))
    assert [row["disposition"] for row in analysis.safe_assumption_lifecycle] == [
        "INVALIDATED", "VALIDATED_SAFE"]
    assert (analysis.safe_assumption_lifecycle[0]["assumption_id"] !=
            analysis.safe_assumption_lifecycle[1]["assumption_id"])


@pytest.mark.parametrize("changed", ["evidence", "context"])
def test_terminal_evidence_basis_is_immutable(changed):
    prior = _row("VALIDATED_SAFE", assumption_id="safe-terminal")
    if changed == "evidence":
        current = _row(
            "VALIDATED_SAFE", assumption_id="safe-terminal",
            evidence=["MODEL_INVENTED_EVIDENCE"])
    else:
        current = _row(
            "VALIDATED_SAFE", assumption_id="safe-terminal",
            required=[{"target": "helper", "request_type": "FUNCTION"}])
    with pytest.raises(ValueError, match="terminal evidence basis changed"):
        asyncio.run(_analyze(
            AgentPipeline(Provider([_response(rows=[current])])),
            prior=[prior]))


def test_missing_lifecycle_field_is_rejected_live_but_allowed_in_legacy_replay():
    response = _response()
    del response["safe_assumption_lifecycle"]
    with pytest.raises(Exception, match="safe_assumption_lifecycle"):
        asyncio.run(_analyze(AgentPipeline(Provider([response]))))

    with pytest.raises(Exception, match="safe_assumption_lifecycle"):
        asyncio.run(AgentPipeline(Provider([response])).analyze_function(
            "fn-target", "target", "target.c", SOURCE))

    ordinary = asyncio.run(AgentPipeline(
        Provider([response]), legacy_offline_replay=True).analyze_function(
            "fn-target", "target", "target.c", SOURCE))
    assert ordinary.safe_assumptions == [ASSUMPTION]
    assert ordinary.safe_assumption_lifecycle == []


def test_concurrent_lifecycle_runs_do_not_share_candidate_identity_or_state():
    async def one(function_id, disposition):
        pipeline = AgentPipeline(Provider([
            _response(rows=[_row(disposition)])]))
        return await pipeline.analyze_function(
            function_id, "target", "target.c", SOURCE,
            assumption_lifecycle_contract={
                "kind": "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V4",
                "available_evidence": [{"evidence_id": "SELECTED_SOURCE"}]},
            prior_safe_assumptions=[])

    async def run_both():
        return await asyncio.gather(
            one("fn-a", "VALIDATED_SAFE"), one("fn-b", "PROPOSED"))

    first, second = asyncio.run(run_both())
    assert first.safe_assumptions == [ASSUMPTION]
    assert second.safe_assumptions == []
    assert (first.safe_assumption_lifecycle[0]["assumption_id"] !=
            second.safe_assumption_lifecycle[0]["assumption_id"])
    assert [first.safe_assumption_lifecycle[0]["disposition"],
            second.safe_assumption_lifecycle[0]["disposition"]] == [
                "VALIDATED_SAFE", "PROPOSED"]
