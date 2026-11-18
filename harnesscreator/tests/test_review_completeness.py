"""A harness review passes only when it reports each of HC01..HC16 exactly once."""

from harnesscreator.contexts.measured_harness import CHECKS, review_problems


def _review(ids, status="PASS"):
    return {"checks": [{"check_id": i, "status": status, "evidence": "x"} for i in ids], "summary": ""}


def test_complete_review():
    assert review_problems(_review(sorted(CHECKS))) == []


def test_one_check_is_not_a_review():
    assert review_problems(_review(["HC01"])) == ["missing " + ", ".join(sorted(set(CHECKS) - {"HC01"}))]


def test_repeated_and_unknown_ids():
    ids = sorted(CHECKS) + ["HC03", "HC99"]
    assert review_problems(_review(ids)) == ["repeated HC03", "unknown HC99"]


def test_empty_review():
    assert review_problems({"checks": [], "summary": "review raised"})[0].startswith("missing HC01")
