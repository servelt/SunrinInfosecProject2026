"""Function Analyzer request-to-hypothesis attribution boundaries."""

import asyncio

from vulnerabilityanalysis.agents import AgentPipeline, _ANALYSIS


class Provider:
    def __init__(self, response):
        self.response = response

    async def generate(self, request):
        return self.response


def _response(index):
    return {
        "summary": "reviewed",
        "input_flow": "input",
        "state_dependencies": [],
        "context_requests": [{
            "target": "helper",
            "request_type": "FUNCTION",
            "reason": "resolve helper contract",
            "expected_information": "source",
            "hypothesis_index": index,
        }],
        "safe_assumptions": [],
        "unknowns": [],
        "input_sources": [],
        "security_sensitive_operations": [],
        "validations": [],
        "memory_operations": [],
        "evidence": [],
        "safe_assumption_lifecycle": [],
        "hypothesis_evaluations": [{
            "source_location": "target.c:1",
            "security_property": "bounded read",
            "source_file": "target.c",
            "source_line": 1,
            "source_quote": "int target(char *p){return helper(p);}",
            "input_influence": "INPUT_DEPENDENT",
            "hypothesis": "the helper may return a short buffer",
            "judgment": "UNKNOWN",
            "reason": "helper source is missing",
            "safe_assumption": "",
        }],
    }


def test_live_schema_requires_context_hypothesis_index():
    row = _ANALYSIS["properties"]["context_requests"]["items"]
    assert "hypothesis_index" in row["required"]


def test_valid_index_is_bound_to_exact_same_response_hypothesis():
    analysis = asyncio.run(AgentPipeline(
        Provider(_response(0))).analyze_function(
            "fn", "target", "target.c",
            "int target(char *p){return helper(p);}"))
    request = analysis.context_requests[0]
    assert request.attribution_verified is True
    assert request.related_hypothesis == "the helper may return a short buffer"
    assert request.related_judgment == "UNKNOWN"
    assert request.related_reason == "helper source is missing"
    assert request.related_source_location == "target.c:1"
    assert request.related_security_property == "bounded read"


def test_out_of_range_index_is_retained_but_fails_closed():
    analysis = asyncio.run(AgentPipeline(
        Provider(_response(9))).analyze_function(
            "fn", "target", "target.c",
            "int target(char *p){return helper(p);}"))
    request = analysis.context_requests[0]
    assert request.attribution_verified is False
    assert request.related_hypothesis == ""
    assert request.related_judgment == ""
    assert request.related_reason == ""


def test_indexed_evaluation_without_pinned_source_identity_fails_closed():
    response = _response(0)
    response["hypothesis_evaluations"][0]["source_quote"] = "return p[0];"
    analysis = asyncio.run(AgentPipeline(
        Provider(response)).analyze_function(
            "fn", "target", "target.c",
            "int target(char *p){return helper(p);}"))
    request = analysis.context_requests[0]
    assert request.attribution_verified is False
    # The Host retains the model claim for audit, but closure cannot trust it.
    assert request.related_judgment == "UNKNOWN"


def test_index_without_exact_target_lexical_binding_fails_closed():
    response = _response(0)
    response["hypothesis_evaluations"][0].update({
        "hypothesis": "unrelated_helper may have a state transition failure",
        "reason": "another public contract is absent",
    })
    analysis = asyncio.run(AgentPipeline(
        Provider(response)).analyze_function(
            "fn", "target", "target.c",
            "int target(char *p){return helper(p);}"))
    request = analysis.context_requests[0]
    assert request.attribution_verified is False
    assert request.related_hypothesis.startswith("unrelated_helper")


def test_prose_only_target_without_source_token_fails_closed():
    response = _response(0)
    response["hypothesis_evaluations"][0].update({
        "source_quote": "int target(char *p){return p[0];}",
        "hypothesis": "helper may return a short buffer",
        "reason": "helper source is missing",
    })
    analysis = asyncio.run(AgentPipeline(
        Provider(response)).analyze_function(
            "fn", "target", "target.c", "int target(char *p){return p[0];}"))
    request = analysis.context_requests[0]
    assert request.attribution_verified is False
    assert request.related_hypothesis.startswith("helper")

