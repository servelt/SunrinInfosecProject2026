"""Goal A.1: structured independent-Gate resolution (producer side).

Real short-lived shell processes stand in for the replay target; no Target,
Fuzzer, model, Docker or network is used. A BLOCKED_* status never settles a
crash by itself: only a completed, conclusive process may be TERMINAL_REJECTED.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import stat

import pytest

from vulnerabilityanalysis import scan
from vulnerabilityanalysis.final_verification import (
    GATE_INCOMPLETE, GATE_TERMINAL_REJECTED, OBSERVED_REPLAY_SEGMENT,
    crash_fingerprint, independent_replay, independent_replay_resolution,
    observed_crash_type_blocker)
from vulnerabilityanalysis.models import (FixedPoC, IndependentValidation, PoC,
                                          RootCauseResult, RuntimeResult,
                                          SuspiciousPoint)

UAF = ("==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602 "
       "at pc 0x1 bp 0x2 sp 0x3\nREAD of size 1 at 0x602 thread T0\n"
       "    #0 0x4f in victim /src/target.c:15:3\n"
       "    #1 0x5f in LLVMFuzzerTestOneInput /src/fuzz.c:4:1\n")
OTHER_SYMBOLIZED = ("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000 "
                    "(pc 0x1 bp 0x2 sp 0x3 T0)\n"
                    "    #0 0x4f in other_function /src/other.c:40:2\n")
UNSYMBOLIZED = ("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000 "
                "(pc 0x1 bp 0x2 sp 0x3 T0)\n"
                "    #0 0x4f  (/target/binary+0x1234)\n")
ALLOCATION_TOO_BIG = (
    "==1==ERROR: AddressSanitizer: requested allocation size 0xffffffffff "
    "exceeds maximum supported size of 0x10000000000 (thread T0)\n"
    "    #0 0x4f in malloc_wrapper /src/target.c:30:3\n"
    "SUMMARY: AddressSanitizer: allocation-size-too-big in malloc_wrapper\n")


def _script(path: Path, body: str) -> Path:
    path.write_text("#!/bin/sh\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _fixed(tmp_path: Path, body: str) -> FixedPoC:
    binary = _script(tmp_path / "target.sh", body)
    data = tmp_path / "input.bin"
    data.write_bytes(b"input")
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()  # noqa: E731
    return FixedPoC("poc", "crash-1", str(data), "gen.py", str(binary),
                    [str(binary), "{input}"], "AddressSanitizer: heap-use-after-free",
                    "AddressSanitizer: heap-use-after-free",
                    "victim:/src/target.c:15", "target.c:15",
                    sha(data), sha(binary))


def _replay(tmp_path: Path, body: str, timeout: float = 5.0):
    fixed = _fixed(tmp_path, body)
    out = tmp_path / "independent"
    validation = independent_replay(fixed, out, timeout_seconds=timeout)
    runtime_path = out / "runtime.json"
    runtime = (RuntimeResult(**json.loads(runtime_path.read_text()))
               if runtime_path.is_file() else None)
    return fixed, validation, runtime


def _stderr_body(text: str, code: int) -> str:
    escaped = text.replace("'", "'\\''")
    return f"printf '%s' '{escaped}' >&2\nexit {code}"


def test_replay_timeout_is_environment_error_and_pending(tmp_path):
    # G-1: a replay timeout used to surface as BLOCKED_INDEPENDENT_REPLAY.
    fixed, validation, runtime = _replay(tmp_path, "sleep 30", timeout=0.5)
    assert validation.status == "ENVIRONMENT_ERROR"
    assert runtime.timed_out is True and runtime.exit_code is None
    assert independent_replay_resolution(fixed, validation, runtime) == (
        GATE_INCOMPLETE, "REPLAY_PROCESS_INCOMPLETE")


def test_single_clean_exit_not_reproduced_stays_pending(tmp_path):
    fixed, validation, runtime = _replay(tmp_path, "exit 0")
    assert validation.status == "NOT_REPRODUCED"
    assert independent_replay_resolution(fixed, validation, runtime) == (
        GATE_INCOMPLETE, "REPLAY_NOT_REPRODUCED_REPEAT_POLICY_UNDEFINED")


@pytest.mark.parametrize("body, reason", [
    ("kill -9 $$", "REPLAY_KILLED_BY_SIGNAL"),           # OOM killer / envelope kill
    ("exit 127", "REPLAY_NONZERO_EXIT_WITHOUT_ORACLE"),  # loader failure
    ("echo '==1==AddressSanitizer failed to allocate shadow' >&2; exit 1",
     "REPLAY_NONZERO_EXIT_WITHOUT_ORACLE"),             # ASan init failure
])
def test_abnormal_not_reproduced_stays_pending(tmp_path, body, reason):
    fixed, validation, runtime = _replay(tmp_path, body)
    assert validation.status == "NOT_REPRODUCED"
    assert independent_replay_resolution(fixed, validation, runtime) == (
        GATE_INCOMPLETE, reason)


def test_symbolized_inconsistent_replay_stays_pending(tmp_path):
    # Goal A.1.1 (F8): one different sanitizer crash does not prove the
    # original crash is absent.
    fixed, validation, runtime = _replay(tmp_path, _stderr_body(OTHER_SYMBOLIZED, 1))
    assert validation.status == "INCONSISTENT"
    assert runtime.failure_classification == "SANITIZER_CRASH"
    assert independent_replay_resolution(fixed, validation, runtime) == (
        GATE_INCOMPLETE, "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED")


@pytest.mark.parametrize("stderr, reason", [
    (UNSYMBOLIZED, "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED"),
    (ALLOCATION_TOO_BIG, "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED"),
])
def test_unsymbolized_or_resource_inconsistent_stays_pending(tmp_path, stderr, reason):
    fixed, validation, runtime = _replay(tmp_path, _stderr_body(stderr, 1))
    assert validation.status == "INCONSISTENT"
    assert independent_replay_resolution(fixed, validation, runtime) == (
        GATE_INCOMPLETE, reason)


def test_exit_code_none_and_missing_or_forged_receipts_stay_pending(tmp_path):
    fixed, validation, runtime = _replay(tmp_path, "exit 0")
    no_exit = RuntimeResult(None, "", "", None, False, None, None, "HARNESS_NOT_STARTED")
    launch_failure = IndependentValidation(
        fixed.poc_id, fixed.sp_id, "ENVIRONMENT_ERROR", None, None, None,
        "replay process failed to complete")
    assert independent_replay_resolution(fixed, launch_failure, no_exit) == (
        GATE_INCOMPLETE, "REPLAY_PROCESS_INCOMPLETE")
    assert independent_replay_resolution(fixed, validation, None) == (
        GATE_INCOMPLETE, "REPLAY_RUNTIME_MISSING")
    forged = IndependentValidation(**{**asdict(validation), "status": "INCONSISTENT"})
    assert independent_replay_resolution(fixed, forged, runtime) == (
        GATE_INCOMPLETE, "REPLAY_RECEIPT_INCONSISTENT")
    # A forged "clean" validation cannot hide a timed-out RuntimeResult.
    timed_out = RuntimeResult(**{**asdict(runtime), "timed_out": True, "exit_code": None})
    assert independent_replay_resolution(fixed, validation, timed_out) == (
        GATE_INCOMPLETE, "REPLAY_RECEIPT_INCONSISTENT")


def test_missing_frozen_input_is_environment_error(tmp_path):
    fixed = _fixed(tmp_path, "exit 0")
    Path(fixed.input_path).write_bytes(b"changed")
    validation = independent_replay(fixed, tmp_path / "independent")
    assert validation.status == "ENVIRONMENT_ERROR"
    assert not (tmp_path / "independent" / "runtime.json").exists()
    assert independent_replay_resolution(fixed, validation, None) == (
        GATE_INCOMPLETE, "REPLAY_RUNTIME_MISSING")


# ---- producer: _verify_observed_target_crash ------------------------------

def _target_result(stderr: str, *, exit_code=1, timed_out=False) -> RuntimeResult:
    from vulnerabilityanalysis.runtime import parse_sanitizer
    result = RuntimeResult(exit_code, "", stderr, None, timed_out,
                           parse_sanitizer(stderr), None, "SANITIZER_CRASH")
    result.crash_triage = {"category": "TARGET_CRASH", "top_source_frame": None,
                           "source_provenance": None, "crash_relation": "UNRELATED"}
    return result


def _point(sp_id="lead", status="OPEN") -> SuspiciousPoint:
    return SuspiciousPoint(sp_id, "w", "d", "victim", "target.c", "target.c:15",
                           "use", "UAF", [], "UNKNOWN", [], [], [], [], status=status)


def _observe(tmp_path: Path, result: RuntimeResult, binary: Path | None = None,
             point: SuspiciousPoint | None = None) -> dict:
    run_dir = tmp_path / "run"
    crash_id = crash_fingerprint(result)
    crash_path = run_dir / "runtime" / "crashes" / f"{crash_id}.json"
    crash_path.parent.mkdir(parents=True)
    data = tmp_path / "input.bin"
    data.write_bytes(b"input")
    binary = binary or _script(tmp_path / "target.sh", "exit 0")
    crash_path.write_text(json.dumps({"crash_id": crash_id, "observations": []}))
    poc = PoC("poc", "lead", "gen", str(data), [str(binary), "{input}"], "crash")
    scan._verify_observed_target_crash(
        run_dir, crash_path, poc, point or _point(), result, tmp_path, tmp_path / "h.c",
        binary, None)
    return json.loads(crash_path.read_text())


def test_unsupported_crash_type_is_pending_for_human_review(tmp_path):
    # Goal A.1.1 (R9): no spec-bound out-of-scope policy yet, so never settled.
    result = _target_result(OTHER_SYMBOLIZED)
    assert observed_crash_type_blocker(result) == "UNSUPPORTED_CRASH_TYPE"
    record = _observe(tmp_path, result)
    assert record["independent_verification_status"] == "BLOCKED_UNSUPPORTED_CRASH_TYPE"
    resolution = record["independent_gate_resolution"]
    assert resolution["resolution"] == GATE_INCOMPLETE
    assert resolution["reason"] == "UNSUPPORTED_CRASH_TYPE_HUMAN_REVIEW_PENDING"
    assert resolution["crash_id"] == crash_fingerprint(result)


def test_uncompleted_primary_run_is_never_unsupported_terminal(tmp_path):
    # triage maps a timeout to ENVIRONMENT_ERROR; even a forged TARGET_CRASH
    # triage on an uncompleted run is not conclusive.
    result = _target_result(OTHER_SYMBOLIZED, exit_code=None, timed_out=True)
    record = _observe(tmp_path, result)
    assert record["independent_verification_status"] == "BLOCKED_UNSUPPORTED_CRASH_TYPE"
    assert record["independent_gate_resolution"]["resolution"] == GATE_INCOMPLETE


def test_source_provenance_block_is_pending(tmp_path):
    record = _observe(tmp_path, _target_result(UAF))  # no free/alloc stacks
    assert record["independent_verification_status"] == "BLOCKED_SOURCE_PROVENANCE"
    assert record["independent_gate_resolution"] == {
        "kind": "VA_INDEPENDENT_GATE_RESOLUTION_V1",
        "crash_id": record["independent_hypothesis"]["crash_id"],
        "status": "BLOCKED_SOURCE_PROVENANCE", "resolution": GATE_INCOMPLETE,
        "reason": "SOURCE_PROVENANCE_UNVERIFIED", "replay": None}


def test_covered_by_original_sp_is_not_terminal(tmp_path):
    record = _observe(tmp_path, _target_result(UAF), point=_point(status="VERIFIED"))
    assert record["independent_gate_resolution"]["resolution"] == GATE_INCOMPLETE


def _confirmed_hypothesis(monkeypatch, *, freeze_error: Exception | None = None):
    def hypothesis(result, *_a, **_k):
        crash_id = crash_fingerprint(result)
        return _point(sp_id=crash_id), {"crash_id": crash_id}

    def root(point, result, *_a, **_k):
        return RootCauseResult(point.sp_id, "c", "EXACT", "victim", "target.c:15",
                               result.sanitizer, [], [], [], "", "", [], [], [],
                               "CONFIRMED")
    monkeypatch.setattr(scan, "observed_crash_hypothesis", hypothesis)
    monkeypatch.setattr(scan, "verify_root_cause", root)
    if freeze_error is not None:
        def broken(*_a, **_k):
            raise freeze_error
        monkeypatch.setattr(scan, "freeze_poc", broken)


def test_fixed_poc_block_is_pending(tmp_path, monkeypatch):
    _confirmed_hypothesis(monkeypatch, freeze_error=OSError("disk"))
    record = _observe(tmp_path, _target_result(UAF))
    assert record["independent_verification_status"] == "BLOCKED_FIXED_POC"
    assert record["independent_gate_resolution"]["resolution"] == GATE_INCOMPLETE
    assert record["independent_gate_resolution"]["reason"] == "FIXED_POC_UNAVAILABLE"


@pytest.mark.parametrize("body, timeout, resolution, reason", [
    ("sleep 30", 0.5, GATE_INCOMPLETE, "REPLAY_PROCESS_INCOMPLETE"),
    ("exit 0", 5.0, GATE_INCOMPLETE, "REPLAY_NOT_REPRODUCED_REPEAT_POLICY_UNDEFINED"),
    ("kill -9 $$", 5.0, GATE_INCOMPLETE, "REPLAY_KILLED_BY_SIGNAL"),
])
def test_producer_replay_block_carries_structured_resolution(
        tmp_path, monkeypatch, body, timeout, resolution, reason):
    _confirmed_hypothesis(monkeypatch)
    real = scan.independent_replay
    seen = []

    def bounded(*args, **kwargs):
        seen.append(kwargs.get("process_segment"))
        return real(*args, timeout_seconds=timeout, **kwargs)
    monkeypatch.setattr(scan, "independent_replay", bounded)
    binary = _script(tmp_path / "target.sh", body)
    record = _observe(tmp_path, _target_result(UAF), binary=binary)
    assert seen == [OBSERVED_REPLAY_SEGMENT]
    assert record["independent_verification_status"] == "BLOCKED_INDEPENDENT_REPLAY"
    produced = record["independent_gate_resolution"]
    assert (produced["resolution"], produced["reason"]) == (resolution, reason)
    replay = produced["replay"]
    assert replay["process_segment"] == OBSERVED_REPLAY_SEGMENT
    for key in ("validation", "runtime", "fixed_poc"):
        path = Path(replay[f"{key}_artifact"])
        assert hashlib.sha256(path.read_bytes()).hexdigest() == replay[f"{key}_sha256"]


# ---- internal red-team regressions (R1, R5) --------------------------------

PARTIAL_SYMBOLIZATION = (
    "==1==WARNING: Failed to use and restart external symbolizer!\n"
    "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602 "
    "at pc 0x1 bp 0x2 sp 0x3\nREAD of size 1 at 0x602 thread T0\n"
    "    #0 0x4f  (/target/binary+0x1234)\n"
    "    #1 0x5f in LLVMFuzzerTestOneInput /src/fuzz.c:4:1\n")
SAME_ORACLE_OTHER_FRAME = (
    "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602 "
    "at pc 0x1 bp 0x2 sp 0x3\nREAD of size 1 at 0x602 thread T0\n"
    "    #0 0x4f in other_function /src/other.c:40:2\n")


def test_partially_symbolized_replay_stays_pending(tmp_path):
    # R1: the symbolizer failed on frame #0, so the signature would come from
    # frame #1 and look "inconsistent" although the crash may be identical.
    fixed, validation, runtime = _replay(
        tmp_path, _stderr_body(PARTIAL_SYMBOLIZATION, 1))
    assert validation.status == "INCONSISTENT"
    assert independent_replay_resolution(fixed, validation, runtime) == (
        GATE_INCOMPLETE, "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED")


def test_same_oracle_other_frame_stays_pending(tmp_path):
    fixed, validation, runtime = _replay(
        tmp_path, _stderr_body(SAME_ORACLE_OTHER_FRAME, 1))
    assert validation.status == "INCONSISTENT"
    assert independent_replay_resolution(fixed, validation, runtime) == (
        GATE_INCOMPLETE, "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED")


def test_stored_classification_is_recomputed(tmp_path):
    # R5: a forged stored label cannot turn a resource failure into a crash.
    fixed, validation, runtime = _replay(tmp_path, _stderr_body(ALLOCATION_TOO_BIG, 1))
    forged = RuntimeResult(**{**asdict(runtime),
                              "failure_classification": "SANITIZER_CRASH"})
    assert independent_replay_resolution(fixed, validation, forged) == (
        GATE_INCOMPLETE, "REPLAY_RECEIPT_INCONSISTENT")


# ---- internal red-team round 2 regressions (F2, F3) ------------------------

def test_signal_killed_primary_is_not_unsupported_terminal(tmp_path):
    result = _target_result(OTHER_SYMBOLIZED, exit_code=-9)
    result.signal = 9
    record = _observe(tmp_path, result)
    assert record["independent_verification_status"] == "BLOCKED_UNSUPPORTED_CRASH_TYPE"
    assert record["independent_gate_resolution"]["reason"] == (
        "UNSUPPORTED_CRASH_TYPE_PRIMARY_INCOMPLETE")


def test_recoverable_ubsan_primary_is_not_unsupported_terminal(tmp_path):
    stderr = "/src/t.c:3:1: runtime error: signed integer overflow\n" + \
             "    #0 0x1 in victim /src/target.c:15:3\n"
    record = _observe(tmp_path, _target_result(stderr))
    assert record["independent_gate_resolution"]["resolution"] == GATE_INCOMPLETE


def test_non_asan_replay_is_never_inconsistent_terminal(tmp_path):
    # F3: a target-printed fake frame before a UBSan report is not a symbolized stack.
    stderr = ("#0 0x1 in fake /x.c:1\n/src/t.c:3:1: runtime error: "
              "signed integer overflow\n    #0 0x4f  (/target/binary+0x1)\n")
    fixed, validation, runtime = _replay(tmp_path, _stderr_body(stderr, 1))
    assert validation.status == "INCONSISTENT"
    assert independent_replay_resolution(fixed, validation, runtime)[0] == GATE_INCOMPLETE


# ---- internal red-team round 3 regressions (R3-1..R3-4) --------------------

INC_INTERCEPTOR = ("==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000 "
                   "(pc 0x1 bp 0x2 sp 0x3 T0)\n"
                   "    #0 0x1 in strlen /src/llvm-project/compiler-rt/lib/sanitizer_common/"
                   "sanitizer_common_interceptors.inc:389:5\n"
                   "    #1 0x2 in other_function /src/other.c:40:2\n")
GCC_RUNTIME_THEN_UNSYMBOLIZED = (
    "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000 (pc 0x1 T0)\n"
    "    #0 0x1 in __asan_memcpy ../../../../src/libsanitizer/asan/asan_interceptors.cpp:63\n"
    "    #1 0x2  (/target/binary+0x10)\n")
RELATIVE_RUNTIME_THEN_UNSYMBOLIZED = (
    "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000 (pc 0x1 T0)\n"
    "    #0 0x1 in __asan_memcpy compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63\n"
    "    #1 0x2  (/target/binary+0x10)\n")
UNSYMBOLIZED_RUNTIME_THEN_APP = (
    "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000 (pc 0x1 T0)\n"
    "    #0 0x1 in __interceptor_free (/usr/lib/libasan.so+0x10)\n"
    "    #1 0x2 in other_function /src/other.c:40:2\n")


@pytest.mark.parametrize("stderr, expected", [
    (INC_INTERCEPTOR, (GATE_INCOMPLETE, "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED")),
    (UNSYMBOLIZED_RUNTIME_THEN_APP, (GATE_INCOMPLETE, "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED")),
    (GCC_RUNTIME_THEN_UNSYMBOLIZED, (GATE_INCOMPLETE, "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED")),
    (RELATIVE_RUNTIME_THEN_UNSYMBOLIZED, (GATE_INCOMPLETE, "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED")),
])
def test_sanitizer_runtime_frames_are_skipped_by_component(tmp_path, stderr, expected):
    fixed, validation, runtime = _replay(tmp_path, _stderr_body(stderr, 1))
    assert validation.status == "INCONSISTENT"
    assert independent_replay_resolution(fixed, validation, runtime) == expected


def test_non_asan_unsupported_has_its_own_reason(tmp_path):
    stderr = "/src/t.c:3:1: runtime error: signed integer overflow\n" \
             "    #0 0x1 in victim /src/target.c:15:3\n"
    record = _observe(tmp_path, _target_result(stderr))
    assert record["independent_gate_resolution"]["reason"] == (
        "UNSUPPORTED_CRASH_TYPE_NON_ASAN_ORACLE")


# ---- Goal A.1.1 (independent cold review: F4, F9) --------------------------

from vulnerabilityanalysis.final_verification import (  # noqa: E402
    REPLAY_ASAN_OPTIONS, _replay_status, _signature)

INTERCEPTOR_ALPHA = (
    "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602 at pc 0x1\n"
    "READ of size 8 at 0x602 thread T0\n"
    "    #0 0x1 in __interceptor_memcpy /src/llvm-project/compiler-rt/lib/asan/"
    "asan_interceptors_memintrinsics.cpp:63:3\n"
    "    #1 0x2 in parse_alpha /target/src/parser.c:101:5\n"
    "freed by thread T0 here:\n    #0 0x3 in free /src/llvm-project/compiler-rt/lib/asan/"
    "asan_malloc_linux.cpp:52:3\n    #1 0x4 in release /target/src/parser.c:50:3\n")
INTERCEPTOR_BETA = INTERCEPTOR_ALPHA.replace(
    "parse_alpha /target/src/parser.c:101:5", "parse_beta /target/src/parser.c:202:9")


def _crash(stderr):
    from vulnerabilityanalysis.runtime import parse_sanitizer
    return RuntimeResult(1, "", stderr, None, False, parse_sanitizer(stderr), None,
                         "SANITIZER_CRASH")


@pytest.mark.parametrize("suffix", [
    ":allow_addr2line=1:halt_on_error=0",
    ":allow_addr2line=1:external_symbolizer_path=/usr/bin/addr2line:handle_abort=1",
    ":allow_addr2line=1garbage",
])
def test_replay_options_reject_overriding_suffix(suffix):
    from vulnerabilityanalysis.final_verification import REPLAY_ASAN_OPTIONS, _replay_options_pinned
    assert not _replay_options_pinned(REPLAY_ASAN_OPTIONS + suffix)
    assert _replay_options_pinned(REPLAY_ASAN_OPTIONS)
    assert _replay_options_pinned(REPLAY_ASAN_OPTIONS +
        ":allow_addr2line=1:external_symbolizer_path=/usr/bin/addr2line")


def _fixed_for(primary):
    return FixedPoC("poc", "crash", "in", "gen", "bin", ["bin", "{input}"],
                    primary.sanitizer, "AddressSanitizer: heap-use-after-free",
                    _signature(primary) or "", "x", "0" * 64, "1" * 64,
                    crash_fingerprint(primary))


def test_shared_interceptor_frame_is_not_the_signature():
    alpha, beta = _crash(INTERCEPTOR_ALPHA), _crash(INTERCEPTOR_BETA)
    assert _signature(alpha) == "parse_alpha:/target/src/parser.c:101"
    assert _signature(beta) == "parse_beta:/target/src/parser.c:202"
    assert crash_fingerprint(alpha) != crash_fingerprint(beta)
    # Different application crash behind the same interceptor: never REPRODUCED.
    assert _replay_status(beta, _fixed_for(alpha))[0] == "INCONSISTENT"
    # The same application crash still reproduces.
    assert _replay_status(_crash(INTERCEPTOR_ALPHA), _fixed_for(alpha))[0] == "REPRODUCED"


@pytest.mark.parametrize("runtime_frame", [
    "#0 0x1 in __interceptor_memcpy (/usr/lib/libasan.so.8+0x10)",       # unsymbolized
    "#0 0x1 in __asan_memcpy ../../../../src/libsanitizer/asan/asan_interceptors.cpp:63",
    "#0 0x1 in memcpy compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:63",
    "#0 0x1 in strlen /src/llvm-project/compiler-rt/lib/sanitizer_common/"
    "sanitizer_common_interceptors.inc:389:5",
])
def test_runtime_frame_variants_are_skipped(runtime_frame):
    stderr = ("==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x1\n"
              f"    {runtime_frame}\n    #1 0x2 in parse_alpha /target/src/parser.c:101:5\n")
    assert _signature(_crash(stderr)) == "parse_alpha:/target/src/parser.c:101"


def test_unsymbolized_frame_before_application_frame_blocks_signature():
    stderr = ("==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x1\n"
              "    #0 0x1  (/target/libvendored.so+0x1234)\n"
              "    #1 0x2 in parse_alpha /target/src/parser.c:101:5\n")
    crash = _crash(stderr)
    assert _signature(crash) is None
    # No signature: the root gate and freeze cannot produce a VERIFIED path.
    fixed = _fixed_for(_crash(INTERCEPTOR_ALPHA))
    assert _replay_status(crash, fixed)[0] == "INCONSISTENT"


def test_replay_runs_with_pinned_asan_options_and_records_them(tmp_path, monkeypatch):
    # F9: an inherited ASAN_OPTIONS cannot change replay behaviour.
    monkeypatch.setenv("ASAN_OPTIONS", "allocator_may_return_null=1:detect_leaks=0")
    seen = tmp_path / "seen.txt"
    fixed, validation, runtime = _replay(
        tmp_path, f'printf "%s" "$ASAN_OPTIONS" > {seen}\nexit 0')
    used = seen.read_text()
    assert used.startswith(REPLAY_ASAN_OPTIONS)
    assert "allocator_may_return_null=1" not in used
    assert runtime.runtime_profile["pinned_asan_options"] == REPLAY_ASAN_OPTIONS
    assert runtime.runtime_profile["replay_asan_options"] == used
    assert independent_replay_resolution(fixed, validation, runtime)[0] == (
        GATE_INCOMPLETE)
    unpinned = RuntimeResult(**{**asdict(runtime), "runtime_profile": None})
    assert independent_replay_resolution(fixed, validation, unpinned) == (
        GATE_INCOMPLETE, "REPLAY_ENVIRONMENT_UNPINNED")


def test_replay_drops_parent_loader_and_sanitizer_environment(tmp_path, monkeypatch):
    from vulnerabilityanalysis.runtime import CLEAN_RUNTIME_ENVIRONMENT
    from vulnerabilityanalysis.final_verification import _replay_environment_pinned
    for key in ("LD_PRELOAD", "LD_LIBRARY_PATH", "ASAN_SYMBOLIZER_PATH",
                "UBSAN_OPTIONS", "LSAN_OPTIONS", "PYTHONPATH"):
        monkeypatch.setenv(key, "/parent-only/sentinel")
    monkeypatch.setenv("PATH", str(tmp_path))
    fixed, validation, runtime = _replay(tmp_path,
        'printf "%s\\n" "${LD_PRELOAD-unset}" "${LD_LIBRARY_PATH-unset}" '
        '"${ASAN_SYMBOLIZER_PATH-unset}" "${UBSAN_OPTIONS-unset}" '
        '"${LSAN_OPTIONS-unset}" "${PYTHONPATH-unset}" "$PATH"\nexit 0')
    assert runtime.stdout.splitlines() == ["unset"] * 6 + [CLEAN_RUNTIME_ENVIRONMENT["PATH"]]
    profile = runtime.runtime_profile
    assert _replay_environment_pinned(profile)
    assert set(profile["execution_environment"]) == {"PATH", "LANG", "LC_ALL", "ASAN_OPTIONS"}
    forged = {**profile, "execution_environment": {
        **profile["execution_environment"], "LD_PRELOAD": "/injected.so"}}
    bad = RuntimeResult(**{**asdict(runtime), "runtime_profile": forged})
    assert independent_replay_resolution(fixed, validation, bad) == (
        GATE_INCOMPLETE, "REPLAY_ENVIRONMENT_UNPINNED")
    legacy = {"pinned_asan_options": REPLAY_ASAN_OPTIONS,
              "replay_asan_options": profile["replay_asan_options"]}
    assert not _replay_environment_pinned(legacy)


# ---- Goal A.1.2 (independent cold review: same first line, other crash) -----

from dataclasses import replace  # noqa: E402

from vulnerabilityanalysis.final_verification import (  # noqa: E402
    freeze_poc, replay_identity_proven)

SHARED_ALPHA = (
    "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602 at pc 0x1\n"
    "READ of size 8 at 0x602 thread T0\n"
    "    #0 0x1 in shared_access /target/src/parser.c:101:5\n"
    "    #1 0x2 in caller_alpha /target/src/parser.c:300:3\n"
    "\n0x602 is located 0 bytes inside of 8-byte region\n"
    "freed by thread T0 here:\n"
    "    #0 0x3 in free /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:52:3\n"
    "    #1 0x4 in release_alpha /target/src/lifetime.c:70:3\n"
    "\npreviously allocated by thread T0 here:\n"
    "    #0 0x5 in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:68:3\n"
    "    #1 0x6 in make_node /target/src/lifetime.c:20:12\n")
SHARED_BETA = SHARED_ALPHA.replace(
    "caller_alpha /target/src/parser.c:300:3", "caller_beta /target/src/parser.c:400:3"
).replace("release_alpha /target/src/lifetime.c:70:3",
          "release_beta /target/src/lifetime.c:80:3")
SHARED_OTHER_FREE = SHARED_ALPHA.replace(
    "release_alpha /target/src/lifetime.c:70:3", "release_beta /target/src/lifetime.c:80:3")
SHARED_OTHER_ALLOC = SHARED_ALPHA.replace(
    "make_node /target/src/lifetime.c:20:12", "make_leaf /target/src/lifetime.c:33:12")


def test_same_first_application_line_is_not_the_same_crash():
    # Codex A.1.1 cold-review counterexample.
    alpha, beta = _crash(SHARED_ALPHA), _crash(SHARED_BETA)
    assert _signature(alpha) == _signature(beta) == "shared_access:/target/src/parser.c:101"
    assert crash_fingerprint(alpha) != crash_fingerprint(beta)
    fixed = _fixed_for(alpha)
    assert _replay_status(beta, fixed)[0] == "INCONSISTENT"
    # The identical crash (other addresses / PIDs) still reproduces.
    same = _crash(SHARED_ALPHA.replace("0x602", "0x7f3").replace("==1==", "==4242=="))
    assert _replay_status(same, fixed)[0] == "REPRODUCED"


def test_deep_frame_and_access_size_change_crash_identity():
    shared = ("==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602\n"
              "READ of size 1 at 0x602 thread T0\n" +
              "".join(f"    #{n} 0x{n + 10:x} in step{n} /src/chain.hh:{n + 1}:1\n"
                      for n in range(7)))
    deeper = shared.replace("step6 /src/chain.hh:7:1",
                            "other6 /src/chain.hh:77:1")
    changed_access = shared.replace("READ of size 1", "WRITE of size 8")
    primary = _crash(shared)
    assert crash_fingerprint(primary) != crash_fingerprint(_crash(deeper))
    assert crash_fingerprint(primary) != crash_fingerprint(_crash(changed_access))
    assert _replay_status(_crash(deeper), _fixed_for(primary))[0] == "INCONSISTENT"


@pytest.mark.parametrize("stderr", [SHARED_BETA, SHARED_OTHER_FREE, SHARED_OTHER_ALLOC])
def test_other_lifetime_path_with_same_oracle_is_pending(stderr):
    fixed = _fixed_for(_crash(SHARED_ALPHA))
    assert _replay_status(_crash(stderr), fixed)[0] == "INCONSISTENT"


@pytest.mark.parametrize("fingerprint", [None, "", "crash-forged", 7])
def test_missing_or_forged_frozen_fingerprint_is_never_reproduced(fingerprint):
    fixed = replace(_fixed_for(_crash(SHARED_ALPHA)), expected_crash_fingerprint=fingerprint)
    assert _replay_status(_crash(SHARED_ALPHA), fixed)[0] == "INCONSISTENT"


def _real_replay(tmp_path, primary_text, replay_text):
    """freeze_poc + independent_replay with a real process printing ``replay_text``."""
    binary = _script(tmp_path / "target.sh", _stderr_body(replay_text, 1))
    data = tmp_path / "input.bin"
    data.write_bytes(b"input")
    primary = _crash(primary_text)
    point = _point(sp_id="crash-1")
    poc = PoC("poc", "crash-1", "gen", str(data), [str(binary), "{input}"], "crash")
    fixed = freeze_poc(poc, point, binary, primary.sanitizer, "lifetime.c:70",
                       _signature(primary), tmp_path / "fixed",
                       expected_crash_fingerprint=crash_fingerprint(primary))
    validation = independent_replay(fixed, tmp_path / "independent")
    runtime = RuntimeResult(**json.loads((tmp_path / "independent" / "runtime.json").read_text()))
    return primary, fixed, validation, runtime


def test_real_replay_of_the_same_crash_reproduces_and_binds_fingerprints(tmp_path):
    primary, fixed, validation, runtime = _real_replay(tmp_path, SHARED_ALPHA, SHARED_ALPHA)
    assert validation.status == "REPRODUCED"
    assert json.loads((tmp_path / "fixed" / "fixed.json").read_text())[
        "expected_crash_fingerprint"] == crash_fingerprint(primary)
    assert validation.actual_crash_fingerprint == crash_fingerprint(primary)
    assert replay_identity_proven(primary, fixed, validation, runtime)
    # Forged or missing receipts are not accepted even though the runtime agrees.
    assert not replay_identity_proven(
        primary, fixed, replace(validation, actual_crash_fingerprint=None), runtime)
    assert not replay_identity_proven(
        primary, replace(fixed, expected_crash_fingerprint="crash-forged"),
        validation, runtime)
    assert not replay_identity_proven(
        primary, fixed, validation, replace(runtime, runtime_profile=None))
    assert independent_replay_resolution(
        fixed, replace(validation, actual_crash_fingerprint="crash-forged"), runtime) == (
        GATE_INCOMPLETE, "REPLAY_RECEIPT_INCONSISTENT")


def test_real_replay_of_another_lifetime_crash_is_pending(tmp_path):
    primary, fixed, validation, runtime = _real_replay(tmp_path, SHARED_ALPHA, SHARED_BETA)
    assert validation.status == "INCONSISTENT"
    assert validation.actual_crash_fingerprint != fixed.expected_crash_fingerprint
    assert not replay_identity_proven(primary, fixed, validation, runtime)
    # A forged REPRODUCED receipt for that replay cannot pass the recomputation.
    forged = replace(validation, status="REPRODUCED",
                     actual_crash_fingerprint=fixed.expected_crash_fingerprint)
    assert not replay_identity_proven(primary, fixed, forged, runtime)
    assert independent_replay_resolution(fixed, validation, runtime) == (
        GATE_INCOMPLETE, "REPLAY_INCONSISTENT_REPEAT_POLICY_UNDEFINED")
