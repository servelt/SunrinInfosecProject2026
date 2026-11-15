"""Describe HP observations without granting safety or vulnerability credit."""


def hp_physical_observations(assertion_status, guided):
    known = type(assertion_status) is str and assertion_status in {
        "HELD_FOR_EXECUTION", "VIOLATED", "NOT_REACHED"}
    report = guided if type(guided) is dict else {}
    status = report.get("status") if type(report.get("status")) is str else None

    def count(name):
        value = report.get(name)
        return value if type(value) is int and value >= 0 else None

    witnesses = report.get("violation_witnesses")
    artifacts = report.get("other_crash_artifacts")
    continuation = report.get("continuation")
    segment_statuses = (
        status, report.get("initial_segment_status"),
        continuation.get("status") if type(continuation) is dict else None)
    # A later continuation failure may replace the aggregate status. Preserve
    # an already observed sanitizer Crash from either recorded segment.
    observed_crash = any(type(item) is str and
                         item == "CRASH_OBSERVED_INCOMPLETE"
                         for item in segment_statuses)
    crash = (True if observed_crash else
             False if type(artifacts) is list and artifacts == [] and
             status in {"RAN", "ASSERTION_WITNESS_OBSERVED"} else None)
    triage = report.get("violation_triage")
    classification = triage.get("classification") if type(triage) is dict else None
    if type(classification) is not str or classification not in {"SECURITY_DEFECT_POSSIBLE", "OVERSTRONG_ASSUMPTION",
                              "INSUFFICIENT_EVIDENCE", "NOT_A_VIOLATION"}:
        classification = None
    return {
        "initial_assertion_reached": assertion_status != "NOT_REACHED" if known else None,
        "initial_assertion_violated": assertion_status == "VIOLATED" if known else None,
        "guided_assertion_reached_count": count("assertion_reached_count"),
        "guided_assertion_violated_count": count("assertion_violated_count"),
        "guided_assertion_counts_scope": report.get("assertion_counts_scope"),
        "guided_witness_observed": bool(witnesses) if type(witnesses) is list else None,
        "guided_crash_observed_ungated": crash,
        "guided_crash_artifacts_reported": len(artifacts) if type(artifacts) is list else None,
        "assertion_triage_classification": classification,
        "security_gate_credit": "NOT_CREDITED",
    }
