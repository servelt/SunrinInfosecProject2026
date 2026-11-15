"""Deterministic gates between scenario analysis and harness code generation.

These tests do not claim semantic correctness. They detect broken references,
missing observations, fabricated runtime status and mismatched mutation steps
*before* asking an LLM to write or rebuild C code.
"""
from __future__ import annotations

from dataclasses import dataclass
from ..models import HarnessPlan, ScenarioStatus, ScenarioWitness
from .request_trace import response_hex_attested


@dataclass(frozen=True)
class ContractAudit:
    plan_id: str
    passed: bool
    failures: tuple[str, ...]
    proof_level: str


def audit_harness_plan(
    witness: ScenarioWitness, plan: HarnessPlan, *, allow_unproven: bool = False,
) -> ContractAudit:
    failures: list[str] = []
    if witness.status not in {
        ScenarioStatus.PROVEN_RUNTIME,
        ScenarioStatus.OBSERVED_RUNTIME,
        ScenarioStatus.REPLAYED_RUNTIME,
        *( [ScenarioStatus.UNPROVEN, ScenarioStatus.INFRASTRUCTURE_FAILED] if allow_unproven else [] ),
    }:
        failures.append("witness is neither proven nor an explicitly labeled exploratory observation")
    if plan.witness_id != witness.witness_id or plan.scenario_id != witness.scenario_id:
        failures.append("plan references a different original-program witness")
    if plan.target_action_id != witness.target_action_id:
        failures.append("plan changes the target action")
    if not witness.steps:
        failures.append("witness has no concrete input steps")
    else:
        if [item.index for item in witness.steps] != list(range(len(witness.steps))):
            failures.append("witness step indices are not contiguous")
        fuzz_index = witness.fuzz_step_index if witness.fuzz_step_index >= 0 else len(witness.steps) - 1
        if not 0 <= fuzz_index < len(witness.steps):
            failures.append("witness fuzz step is outside the scenario")
        elif (plan.setup_steps != witness.steps[:fuzz_index]
              or plan.fuzz_step != witness.steps[fuzz_index]
              or plan.post_steps != witness.steps[fuzz_index + 1:]
              or plan.fuzz_step_index != fuzz_index):
            failures.append("plan does not preserve the witness setup/fuzz/post sequence")
        if plan.fuzz_step.action_id != witness.target_action_id:
            failures.append("fuzz input targets a different action than the witness")
        for step in witness.steps:
            try:
                bytes.fromhex(step.request_hex)
            except ValueError:
                failures.append(f"step {step.index} is not a valid byte sequence")
        if plan.required_function_ids and len(plan.required_function_ids) != len(set(plan.required_function_ids)):
            failures.append("plan repeats required function identifiers")
    if witness.status is ScenarioStatus.PROVEN_RUNTIME:
        if len(witness.observations) != len(witness.steps) or not all(
            item.success
            and (
                item.response_success
                or (
                    item.target_probe == "request-correlated-jsonl-v1"
                    and "semantic-outcome:success" in item.probe_trace
                    and "semantic-outcome:failure" not in item.probe_trace
                )
            )
            and item.entry_reached
            and item.target_reached and item.request_hex == witness.steps[index].request_hex
            and item.action_id == witness.steps[index].action_id
            and item.target_probe == "request-correlated-jsonl-v1"
            and response_hex_attested(item.probe_trace, item.response_hex)
            and "semantic-outcome:failure" not in item.probe_trace
            for index, item in enumerate(witness.observations)
        ):
            failures.append("PROVEN_RUNTIME lacks exact per-step input/handler execution evidence")
    if witness.status is ScenarioStatus.OBSERVED_RUNTIME:
        if len(witness.observations) != len(witness.steps) or not all(
            item.response_success and item.entry_reached and item.target_observed
            for item in witness.observations
        ):
            failures.append("OBSERVED_RUNTIME lacks observed response and ordered handler chain")
    if witness.status is ScenarioStatus.REPLAYED_RUNTIME:
        if len(witness.observations) != len(witness.steps) or not all(
            item.response_success and item.success
            for item in witness.observations
        ):
            failures.append("REPLAYED_RUNTIME lacks complete original-response observations")
        if any(item.target_reached for item in witness.observations):
            failures.append("response-only witness mixes proven and unproven target reach")
    return ContractAudit(
        plan_id=plan.plan_id,
        passed=not failures,
        failures=tuple(failures),
        proof_level=str(witness.status),
    )
