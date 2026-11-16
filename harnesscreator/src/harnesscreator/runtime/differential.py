"""Source-instrumented original-vs-harness differential validation.

A comparison is meaningful only when *both* binaries expose compatible
semantic observations, and the original trace has a request-correlated input.
Ordinary GDB function hits, binary startup, libFuzzer corpus growth, and
matching exit codes are not enough to claim behavioral equivalence.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..models import HarnessDraft, HarnessPlan, ScenarioStatus, ScenarioWitness
from .request_trace import RequestTraceJournal, exact_acquisitions
from .runner import CommandRunner


@dataclass(frozen=True)
class DifferentialResult:
    status: str  # MATCH, MISMATCH, INSUFFICIENT_EVIDENCE, INFRASTRUCTURE_FAILED
    detail: str
    original_state: str = ""
    harness_state: str = ""
    delivery_challenge_hex: str = ""

    @property
    def passed(self) -> bool:
        return self.status == "MATCH"


def _semantic_value(trace: list[str], label: str) -> str:
    found = [part.partition(":")[2] for part in trace if part.startswith(f"{label}:")]
    return found[0] if len(found) == 1 else ""


def _reference_steps(plan: HarnessPlan, witness: ScenarioWitness) -> tuple[list[tuple[bytes, str, str, str, str, str, tuple[str, int] | None]], str]:
    """Return ordered request, Entry, handler, response, state and outcome evidence.

    A successful runtime witness is not enough for differential comparison:
    every step must also have a product-emitted semantic result. In particular,
    a valid final result must not conceal a missing setup or post request.
    """
    steps = [*plan.setup_steps, plan.fuzz_step, *plan.post_steps]
    if (len(steps) != len(witness.steps)
        or len(witness.observations) != len(steps)
        or len(plan.setup_entry_function_ids) != len(plan.setup_steps)
        or len(plan.post_entry_function_ids) != len(plan.post_steps)):
        return [], "plan and original request sequence or Entry mapping differ"
    entries = [
        *plan.setup_entry_function_ids,
        plan.fuzz_entry_function_id,
        *plan.post_entry_function_ids,
    ]
    fuzz_index = len(plan.setup_steps)
    if (plan.fuzz_step_index not in (-1, fuzz_index)
        or witness.fuzz_step_index not in (-1, fuzz_index)
        or not plan.required_function_ids):
        return [], "fuzz step or target function mapping is ambiguous"
    result: list[tuple[bytes, str, str, str, str, str, tuple[str, int] | None]] = []
    for index, (step, original_step, observation, entry) in enumerate(
        zip(steps, witness.steps, witness.observations, entries)
    ):
        if (not entry or step.request_hex != original_step.request_hex
            or step.action_id != original_step.action_id
            or step.entry_id != original_step.entry_id
            or observation.request_hex != original_step.request_hex
            or observation.action_id != original_step.action_id
            or observation.index != original_step.index
            or observation.entry_function_id != entry
            or not observation.success or not observation.target_reached):
            return [], f"original step {index} has no matching successful request evidence"
        target = (
            plan.required_function_ids[-1] if index == fuzz_index
            else observation.target_function_id
        )
        if not target or observation.target_function_id != target:
            return [], f"original step {index} has no unambiguous target handler"
        trace = observation.probe_trace
        state = _semantic_value(trace, "semantic-state")
        response = _semantic_value(trace, "semantic-response")
        outcome = _semantic_value(trace, "semantic-outcome")
        raw_site = _semantic_value(trace, "semantic-success-site")
        success_site: tuple[str, int] | None = None
        if outcome == "success":
            function_id, separator, line = raw_site.rpartition("@")
            if not separator or not function_id or not line.isdecimal():
                return [], f"original step {index} has no source-validated completion site"
            success_site = (function_id, int(line))
        elif raw_site:
            return [], f"original step {index} has a completion site without success outcome"
        if (not state or not response
            or (outcome and outcome != "success")):
            return [], f"original step {index} has no comparable successful semantic result"
        try:
            request = bytes.fromhex(step.request_hex)
            response_bytes = bytes.fromhex(observation.response_hex)
        except ValueError:
            return [], f"original step {index} has invalid request or response bytes"
        if hashlib.sha256(response_bytes).hexdigest() != response:
            return [], f"original step {index} result disagrees with its observed response"
        result.append((request, entry, target, response, state, outcome, success_site))
    return result, ""


def _ordered_harness_requests(
    events: list[dict], reference: list[tuple[bytes, str, str, str, str, str, tuple[str, int] | None]],
) -> tuple[list[str], str]:
    """Match every acquisition to the witnessed sequence, including repeats.

    The journal does not have an iteration identifier. A complete, contiguous
    request sequence is therefore the strongest grouping available. Interleaved
    requests or additional acquisitions remain insufficient evidence.
    """
    acquisition_ids: dict[str, int] = {}
    last_event: dict[str, int] = {}
    for index, event in enumerate(events):
        request_id = event.get("request_id")
        if request_id is not None:
            if not isinstance(request_id, str) or not request_id:
                return [], "trace contains an invalid request identity"
            last_event[request_id] = index
        if event.get("event") in {"acquire", "acquire_fragment"}:
            if not request_id:
                return [], "acquisition has no request identity"
            acquisition_ids.setdefault(request_id, index)
    if not acquisition_ids or set(last_event) != set(acquisition_ids):
        return [], "trace contains missing or unacquired request identities"
    ordered = sorted(acquisition_ids, key=acquisition_ids.get)
    if len(ordered) % len(reference):
        return [], "harness did not execute a complete witnessed request sequence"
    for index, request_id in enumerate(ordered):
        request, entry, *_ = reference[index % len(reference)]
        matches = {
            item_id for item_id, _, _ in exact_acquisitions(events, request, entry)
        }
        if request_id not in matches:
            return [], f"harness request {index} differs from the witnessed byte/Entry sequence"
        if (index + 1 < len(ordered)
            and last_event[request_id] >= acquisition_ids[ordered[index + 1]]):
            return [], "request events interleave across sequence steps or invocations"
    return ordered, ""


class DifferentialVerifier:
    def __init__(self, runner: CommandRunner | None = None):
        self.runner = runner or CommandRunner()

    async def verify(
        self,
        *,
        draft: HarnessDraft,
        plan: HarnessPlan,
        witness: ScenarioWitness,
        artifact_dir: Path,
        source_root: Path,
        probe_input_delivery: bool = False,
    ) -> DifferentialResult:
        if witness.status is not ScenarioStatus.PROVEN_RUNTIME:
            return DifferentialResult("INSUFFICIENT_EVIDENCE", "original request has no proven runtime identity")
        # A generated harness must not generate its own proof record. Events
        # should come from the audited application's instrumented source,
        # linked by the trusted build. The source audit is necessary but does
        # not replace a build-provenance or code-integrity check.
        if "HARNESSCREATOR_TRACE_JSONL" in draft.code or (
            "response_sha256" in draft.code and "state_digest" in draft.code
        ):
            return DifferentialResult(
                "INSUFFICIENT_EVIDENCE",
                "generated harness contains trace-emission logic; independent product instrumentation required",
            )
        reference, reference_problem = _reference_steps(plan, witness)
        if reference_problem:
            return DifferentialResult("INSUFFICIENT_EVIDENCE", reference_problem)
        manifest = draft.manifest
        if not manifest.binary:
            return DifferentialResult("INSUFFICIENT_EVIDENCE", "generated harness has no executable path")
        binary_path = str(manifest.binary)
        for token, value in (("{source_root}", str(source_root)), ("{output}", str(artifact_dir))):
            binary_path = binary_path.replace(token, value)
        binary = Path(binary_path)
        if not binary.is_file():
            return DifferentialResult("INFRASTRUCTURE_FAILED", f"harness executable missing: {binary}")
        request = reference[len(plan.setup_steps)][0]
        with tempfile.TemporaryDirectory(prefix="hc-diff-") as td:
            folder = Path(td)
            seed = folder / "reference-seed"
            journal_path = folder / "harness.jsonl"
            seed.write_bytes(request)
            journal_path.write_bytes(b"")
            environment = os.environ.copy()
            environment["HARNESSCREATOR_TRACE_JSONL"] = str(journal_path)
            environment.setdefault("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=1")
            try:
                report = await self.runner.run(
                    [str(binary), str(seed), "-runs=1", "-timeout=10"],
                    cwd=artifact_dir, env=environment, timeout_seconds=30,
                )
            except Exception as exc:
                return DifferentialResult("INFRASTRUCTURE_FAILED", f"harness replay failed: {type(exc).__name__}: {exc}")
            if report.timed_out or report.returncode != 0:
                diagnostic = (report.stderr or report.stdout).strip()[-1200:]
                if "LeakSanitizer has encountered a fatal error" in report.stderr:
                    return DifferentialResult(
                        "INFRASTRUCTURE_FAILED",
                        "LeakSanitizer could not complete its process-exit check: "
                        + diagnostic,
                    )
                if (report.returncode == -11 and not diagnostic
                    and not journal_path.read_bytes()):
                    # A silent pre-trace SIGSEGV cannot be attributed to the
                    # product or the sanitizer runtime. It is not evidence
                    # of a semantic mismatch or a product vulnerability.
                    return DifferentialResult(
                        "INSUFFICIENT_EVIDENCE",
                        "harness replay exited with SIGSEGV before any "
                        "request-correlated trace or diagnostic was emitted",
                    )
                return DifferentialResult(
                    "MISMATCH",
                    "harness did not complete the reference input "
                    f"(exit={report.returncode}, timed_out={report.timed_out})"
                    + (f": {diagnostic}" if diagnostic else ""),
                )
            # libFuzzer can invoke LLVMFuzzerTestOneInput more than once even
            # with -runs=1 (e.g. corpus initialization). Require a fresh ID for
            # each invocation and compare every matching iteration. Never
            # collapse repeated observations into a single ambiguous request.
            try:
                data = journal_path.read_bytes()
                if len(data) > 2_000_000 or (data and not data.endswith(b"\n")):
                    raise ValueError("incomplete or excessive journal")
                events = [json.loads(line) for line in data.splitlines()]
                if any(not isinstance(item, dict) for item in events):
                    raise ValueError("non-object event")
            except (OSError, ValueError, UnicodeError) as exc:
                return DifferentialResult("INSUFFICIENT_EVIDENCE", f"harness trace is invalid: {exc}")
            relevant_ids, sequence_problem = _ordered_harness_requests(events, reference)
            if sequence_problem:
                return DifferentialResult("INSUFFICIENT_EVIDENCE", sequence_problem)
            last_state = ""
            for index, request_id in enumerate(relevant_ids):
                step_request, step_entry, step_target, source_response, source_state, source_outcome, success_site = (
                    reference[index % len(reference)]
                )
                one = folder / f"iteration-{index}.jsonl"
                one.write_text("".join(
                    json.dumps(item) + "\n" for item in events
                    if item.get("request_id") == request_id
                ))
                observed = RequestTraceJournal(one).observe(
                    0, step_request, step_entry, step_target,
                    success_sites=(success_site,) if success_site else (),
                )
                if not observed.target_reached:
                    return DifferentialResult("INSUFFICIENT_EVIDENCE", "harness did not emit correlated semantic events: " + observed.problem)
                harness_state = _semantic_value(list(observed.trace), "semantic-state")
                harness_response = _semantic_value(list(observed.trace), "semantic-response")
                if not harness_state or not harness_response:
                    return DifferentialResult("INSUFFICIENT_EVIDENCE", "harness emitted no comparable state and response digest")
                harness_outcome = _semantic_value(list(observed.trace), "semantic-outcome")
                harness_site = _semantic_value(list(observed.trace), "semantic-success-site")
                if (harness_state != source_state or harness_response != source_response
                    or harness_outcome != source_outcome
                    or harness_site != (
                        f"{success_site[0]}@{success_site[1]}" if success_site else ""
                    )):
                    return DifferentialResult(
                        "MISMATCH", f"reference step {index % len(reference)} changed response, outcome or observed semantic state",
                        source_state, harness_state,
                    )
                last_state = harness_state
        challenge_hex = ""
        if probe_input_delivery:
            # HC08/HC10 were only source-level leads. A reference-seed replay
            # cannot distinguish a genuine Data/Size handoff from a harness
            # that always sends the one witnessed request. Challenge the built
            # binary with different bytes and require those exact bytes at the
            # same instrumented Entry. This is a delivery probe, not a claim
            # that the mutated request should succeed semantically.
            if not request:
                return DifferentialResult(
                    "INSUFFICIENT_EVIDENCE",
                    "cannot challenge delivery of an empty witnessed request",
                )
            challenge = os.urandom(len(request))
            while challenge == request:
                challenge = os.urandom(len(request))
            challenge_hex = challenge.hex()
            with tempfile.TemporaryDirectory(prefix="hc-diff-delivery-") as td:
                probe_folder = Path(td)
                probe_seed = probe_folder / "challenge-seed"
                probe_journal = probe_folder / "harness.jsonl"
                probe_seed.write_bytes(challenge)
                probe_journal.write_bytes(b"")
                probe_env = environment.copy()
                probe_env["HARNESSCREATOR_TRACE_JSONL"] = str(probe_journal)
                try:
                    probe_report = await self.runner.run(
                        [str(binary), str(probe_seed), "-runs=1", "-timeout=10"],
                        cwd=artifact_dir, env=probe_env, timeout_seconds=30,
                    )
                except Exception as exc:
                    return DifferentialResult(
                        "INFRASTRUCTURE_FAILED",
                        f"input-delivery challenge failed: {type(exc).__name__}: {exc}",
                        delivery_challenge_hex=challenge_hex,
                    )
                if probe_report.timed_out or probe_report.returncode != 0:
                    return DifferentialResult(
                        "INSUFFICIENT_EVIDENCE",
                        "input-delivery challenge did not complete normally "
                        f"(exit={probe_report.returncode}, timed_out={probe_report.timed_out})",
                        delivery_challenge_hex=challenge_hex,
                    )
                try:
                    probe_data = probe_journal.read_bytes()
                    if (not probe_data or len(probe_data) > 2_000_000
                        or not probe_data.endswith(b"\n")):
                        raise ValueError("missing, incomplete or excessive challenge journal")
                    probe_events = [json.loads(line) for line in probe_data.splitlines()]
                    if any(not isinstance(item, dict) for item in probe_events):
                        raise ValueError("non-object challenge event")
                except (OSError, ValueError, UnicodeError) as exc:
                    return DifferentialResult(
                        "INSUFFICIENT_EVIDENCE",
                        f"input-delivery challenge trace is invalid: {exc}",
                        delivery_challenge_hex=challenge_hex,
                    )
                fuzz_index = len(plan.setup_steps)
                challenged = list(reference)
                challenged[fuzz_index] = (
                    challenge, *challenged[fuzz_index][1:],
                )
                # A malformed fuzz request may legitimately prevent post
                # actions. Accept either a complete sequence or a sequence
                # ending at the challenged fuzz step, never an extra request.
                variants = (challenged, challenged[:fuzz_index + 1])
                if not any(
                    _ordered_harness_requests(probe_events, variant)[1] == ""
                    for variant in variants
                ):
                    return DifferentialResult(
                        "INSUFFICIENT_EVIDENCE",
                        "built harness did not acquire the challenge bytes "
                        "at the witnessed Entry in the expected request order",
                        delivery_challenge_hex=challenge_hex,
                    )
        return DifferentialResult(
            "MATCH", f"matched {len(relevant_ids) // len(reference)} complete instrumented libFuzzer invocation(s)"
            + (" and an independent input-delivery challenge" if probe_input_delivery else ""),
            reference[-1][4], last_state, challenge_hex,
        )
