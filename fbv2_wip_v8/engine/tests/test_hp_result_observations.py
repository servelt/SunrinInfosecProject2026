from devtools.hp_result_observations import hp_physical_observations
import pytest


def test_not_reached_and_ran_does_not_imply_assertion_reached():
    row = hp_physical_observations("NOT_REACHED", {
        "status": "RAN", "assertion_reached_count": 0,
        "assertion_violated_count": 0, "violation_witnesses": [],
        "other_crash_artifacts": [],
        "assertion_counts_scope": "sampled corpus replay, not all fuzz executions"})
    assert row["initial_assertion_reached"] is False
    assert row["guided_assertion_reached_count"] == 0
    assert row["guided_witness_observed"] is False
    assert row["guided_crash_observed_ungated"] is False
    assert "sampled corpus" in row["guided_assertion_counts_scope"]
    assert row["security_gate_credit"] == "NOT_CREDITED"


def test_guided_crash_and_witness_are_both_retained():
    row = hp_physical_observations("NOT_REACHED", {
        "status": "CRASH_OBSERVED_INCOMPLETE", "violation_witnesses": ["witness"],
        "other_crash_artifacts": ["crash"],
        "violation_triage": {"classification": "OVERSTRONG_ASSUMPTION"}})
    assert row["guided_crash_observed_ungated"] is True
    assert row["guided_witness_observed"] is True
    assert row["assertion_triage_classification"] == "OVERSTRONG_ASSUMPTION"
    assert row["security_gate_credit"] == "NOT_CREDITED"


def test_unreplayed_crash_named_artifact_is_not_sanitizer_observation():
    row = hp_physical_observations("NOT_REACHED", {
        "status": "RAN", "other_crash_artifacts": ["crash-candidate"],
        "violation_witnesses": []})
    assert row["guided_crash_observed_ungated"] is None
    assert row["guided_crash_artifacts_reported"] == 1
    assert row["security_gate_credit"] == "NOT_CREDITED"


def test_missing_or_invalid_counts_are_unknown():
    row = hp_physical_observations("ERROR", {"assertion_reached_count": True,
                                            "assertion_violated_count": -1})
    assert row["initial_assertion_reached"] is None
    assert row["guided_assertion_reached_count"] is None
    assert row["guided_assertion_violated_count"] is None
    assert row["guided_crash_observed_ungated"] is None


def test_valid_rerun_mismatch_classification_is_preserved():
    row = hp_physical_observations("VIOLATED", {
        "violation_triage": {"classification": "NOT_A_VIOLATION"}})
    assert row["assertion_triage_classification"] == "NOT_A_VIOLATION"
    assert row["security_gate_credit"] == "NOT_CREDITED"


def test_malformed_status_and_classification_do_not_create_credit():
    row = hp_physical_observations({}, {"status": [], "violation_triage": {
        "classification": {"status": "VERIFIED"}}})
    assert row["initial_assertion_reached"] is None
    assert row["assertion_triage_classification"] is None
    assert row["security_gate_credit"] == "NOT_CREDITED"


@pytest.mark.parametrize("segment_fields", [
    {"initial_segment_status": "CRASH_OBSERVED_INCOMPLETE",
     "continuation": {"status": "ERROR"}},
    {"initial_segment_status": "ASSERTION_WITNESS_OBSERVED",
     "continuation": {"status": "CRASH_OBSERVED_INCOMPLETE"}},
])
def test_continuation_failure_retains_observed_segment_crash(segment_fields):
    row = hp_physical_observations("NOT_REACHED", {
        "status": "INCOMPLETE_CONTINUATION", **segment_fields,
        "violation_witnesses": [], "other_crash_artifacts": []})
    assert row["guided_crash_observed_ungated"] is True
    assert row["initial_assertion_reached"] is False
    assert row["security_gate_credit"] == "NOT_CREDITED"


def test_malformed_segment_labels_do_not_create_crash_observation():
    row = hp_physical_observations("NOT_REACHED", {
        "status": "INCOMPLETE_CONTINUATION",
        "initial_segment_status": ["CRASH_OBSERVED_INCOMPLETE"],
        "continuation": "CRASH_OBSERVED_INCOMPLETE"})
    assert row["guided_crash_observed_ungated"] is None
