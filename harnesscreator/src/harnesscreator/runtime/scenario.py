from __future__ import annotations

import asyncio
import inspect
import os
import re
import select
import shlex
import shutil
import signal
import socket
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import Awaitable, Callable, Iterable

from ..analysis.graph import GraphStore
from ..input_transport import classify_external_transport, permits_explicit_socket_trial
from ..models import (
    ActionActor,
    CrashReproductionStatus,
    ExternalActionSchema,
    HarnessPlan,
    ObservedActionBinding,
    OriginalCrashReplay,
    ProjectSpec,
    RuntimeStepObservation,
    ScenarioCandidate,
    ScenarioStatus,
    ScenarioStep,
    ScenarioWitness,
    SeedSpec,
    stable_id,
)
from .crash import crash_signatures_match, extract_crash_signature
from .memcached_frames import FrameError, read_response as read_memcached_response
from .request_trace import RequestTraceJournal, response_attested


_CRASH_MARKERS = (
    b"AddressSanitizer",
    b"UndefinedBehaviorSanitizer",
    b"MemorySanitizer",
    b"ThreadSanitizer",
    b"runtime error:",
    b"Segmentation fault",
    b"stack-overflow",
)


def _response_marker_matches(response: bytes, marker: bytes) -> bool:
    """Reject embedded substrings that masquerade as an entire status token.

    A generic marker oracle is still not a protocol decoder. For textual
    multi-line replies, match an entire line. For an unframed marker, require
    an exact response or an ASCII whitespace delimiter. Protocol-aware frame
    readers remain preferable for production acceptance.
    """
    if not marker:
        return False
    if b"\n" in marker:
        return marker in response.splitlines(keepends=True)
    if response == marker:
        return True
    # Prefix markers such as b"OK:" are supported, but only from the
    # start of a response line. b"STORED" must not match b"NOT_STORED".
    # Prefix matching is permitted only for explicit prefix syntax. A marker
    # such as b"STORED" is a whole response token, not a prefix of
    # b"STORED_ERROR" or b"STORED_MORE".
    prefix_marker = marker.endswith((b":", b" ", b"\t"))
    return any(
        line == marker or (prefix_marker and line.startswith(marker))
        for line in response.splitlines()
    )


TargetObserver = Callable[
    [ScenarioStep, ExternalActionSchema, bytes, bytes],
    bool | Awaitable[bool],
]


class ScenarioRuntimeVerifier:
    """Execute planned external requests against the original program.

    Only trusted ``ProjectSpec.scenario_command`` argv is launched and no
    shell is involved.  This class is the sole producer of
    ``ScenarioStatus.PROVEN_RUNTIME``.
    """

    def __init__(
        self,
        project: ProjectSpec,
        actions: Iterable[ExternalActionSchema],
        graph: GraphStore | None = None,
        *,
        target_observer: TargetObserver | None = None,
    ):
        self.project = project
        self.actions = {item.action_id: item for item in actions}
        self.graph = graph
        # Deliberate dependency-injection seam for transport unit tests.  The
        # production orchestrator never provides it; production proof uses
        # the GDB-backed exact-handler probe below.
        self._target_observer = target_observer
        self._cache: dict[str, ScenarioWitness] = {}

    async def verify_many(
        self, candidates: list[ScenarioCandidate]
    ) -> list[ScenarioWitness]:
        result: list[ScenarioWitness] = []
        for candidate in candidates:
            if candidate.status is not ScenarioStatus.CANDIDATE:
                result.append(self._not_executed(candidate, candidate.blocker or "scenario was not plannable"))
                continue
            result.append(await self.verify(candidate))
        return result

    async def verify(
        self,
        candidate: ScenarioCandidate,
        *,
        use_cache: bool = False,
    ) -> ScenarioWitness:
        # A scenario's input surface comes from SOURCE analysis, not a global
        # CLI switch. Never discard an incompatible candidate during Action
        # discovery; report a concrete runtime limitation for this candidate.
        if self.project.scenario_channel == "auto":
            transports = [
                _action_transport(self.actions[step.action_id])
                for step in candidate.steps if step.action_id in self.actions
            ]
            if len(transports) != len(candidate.steps) or not all(transports):
                return self._not_executed(
                    candidate, "runtime adapter unknown: source Entry transport is ambiguous"
                )
            if len(set(transports)) != 1:
                return self._not_executed(
                    candidate, "mixed external input transports require an explicit multi-channel executor"
                )
            selected = transports[0]
            if (self.project.scenario_command
                and selected in {"tcp", "udp"}
                and self.project.scenario_port is None):
                return self._not_executed(
                    candidate, f"{selected} executor requires --scenario-port"
                )
            if (self.project.scenario_command and selected == "unix_stream"
                and not self.project.scenario_socket_path
                and not any("{scenario_socket_path}" in token
                            for token in self.project.scenario_command)):
                return self._not_executed(
                    candidate,
                    "unix_stream executor requires --scenario-socket-path or "
                    "{scenario_socket_path} in the original command",
                )
            from dataclasses import replace as dc_replace
            verifier = ScenarioRuntimeVerifier(
                dc_replace(self.project, scenario_channel=selected),
                self.actions.values(), self.graph,
                target_observer=self._target_observer,
            )
            return await verifier.verify(candidate, use_cache=use_cache)
        # Runtime executions may depend on external state and source revision.
        # Do not re-use a previous success by default; explicit test callers
        # may still opt in when they own an immutable sandbox.
        cache_key = stable_id(
            "scenario-execution",
            *self.project.scenario_command,
            self.project.scenario_channel,
            self.project.scenario_response_protocol,
            self.project.scenario_attribution,
            self.project.scenario_exploratory_drafts,
            self.project.scenario_require_target_reach,
            self.project.scenario_host,
            self.project.scenario_socket_path,
            self.project.scenario_port,
            *[
                f"{name}={value}"
                for name, value in sorted(self.project.scenario_environment.items())
            ],
            *[
                f"{step.action_id}:{step.request_hex}:"
                f"{self.actions.get(step.action_id).entry_function_id if self.actions.get(step.action_id) else ''}:"
                f"{self.actions.get(step.action_id).handler_function_id if self.actions.get(step.action_id) else ''}:"
                f"{','.join(step.expected_success_markers_hex)}:"
                f"prelude={step.connection_prelude_marker_hex}:"
                + ",".join(
                    f"{item.binding}@{item.producer_step_index}:"
                    f"{item.offset}+{item.width}"
                    for item in step.request_binding_uses
                )
                + ":"
                + ",".join(
                    f"{item.binding}:{item.offset}+{item.width}"
                    for item in step.response_binding_extractors
                )
                for step in candidate.steps
            ],
        )
        cached = self._cache.get(cache_key) if use_cache else None
        if cached is not None:
            return replace(
                cached,
                witness_id=stable_id("witness", candidate.scenario_id, cache_key),
                scenario_id=candidate.scenario_id,
                target_action_id=candidate.target_action_id,
                steps=list(cached.steps),
                rationale=cached.rationale + "; reused exact runtime execution cache",
            )
        if not self.project.scenario_command:
            witness = self._not_executed(
                candidate,
                "no trusted original-program scenario command/channel is configured",
            )
            if use_cache:
                self._cache[cache_key] = witness
            return witness
        compatibility_error = self._compatibility_error(candidate)
        if compatibility_error:
            witness = self._not_executed(candidate, compatibility_error)
            if use_cache:
                self._cache[cache_key] = witness
            return witness
        try:
            witness = await self._execute(candidate)
        except Exception as exc:
            witness = ScenarioWitness(
                witness_id=stable_id("witness", candidate.scenario_id, "infrastructure"),
                scenario_id=candidate.scenario_id,
                target_action_id=candidate.target_action_id,
                steps=list(candidate.steps),
                observations=[],
                command=list(self.project.scenario_command),
                channel=self.project.scenario_channel,
                process_returncode=None,
                status=ScenarioStatus.INFRASTRUCTURE_FAILED,
                rationale=f"scenario executor raised {type(exc).__name__}: {exc}",
                fuzz_step_index=candidate.fuzz_step_index,
            )
        if use_cache:
            self._cache[cache_key] = witness
        return witness

    async def _execute(self, candidate: ScenarioCandidate) -> ScenarioWitness:
        if self.project.scenario_channel in {"file", "argv", "env"}:
            return await self._execute_one_shot(candidate)
        unix_socket_dir: tempfile.TemporaryDirectory[str] | None = None
        unix_socket_path = self.project.scenario_socket_path
        if self.project.scenario_channel == "unix_stream":
            if not unix_socket_path:
                unix_socket_dir = tempfile.TemporaryDirectory(prefix="hc-unix-socket-")
                unix_socket_path = str(Path(unix_socket_dir.name) / "server.sock")
            if os.path.lexists(unix_socket_path):
                if unix_socket_dir is not None:
                    unix_socket_dir.cleanup()
                return self._not_executed(
                    candidate,
                    f"original Unix socket path already exists: {unix_socket_path}",
                )
        argv = [
            token.replace("{source_root}", str(self.project.source_root))
                 .replace("{scenario_socket_path}", unix_socket_path)
            for token in self.project.scenario_command
        ]
        environment = os.environ.copy()
        environment.update(self.project.scenario_environment)
        stdin_mode = self.project.scenario_channel == "stdin"
        if self.project.scenario_channel in {"tcp", "udp"}:
            assert self.project.scenario_port is not None
            await asyncio.to_thread(
                _assert_endpoint_available,
                self.project.scenario_host,
                self.project.scenario_port,
                self.project.scenario_channel,
            )
        target_probe: _GdbTargetProbe | RequestTraceJournal | None = None
        gdb_probe: _GdbTargetProbe | None = None
        trace_path: Path | None = None
        protocol_stdin_read: int | None = None
        protocol_stdin_write: int | None = None
        protocol_stdout_read: int | None = None
        protocol_stdout_write: int | None = None
        launch_argv = argv
        if self.project.scenario_require_target_reach and self._target_observer is None:
            if self.project.scenario_attribution == "trace":
                descriptor, path = tempfile.mkstemp(prefix="hc-request-trace-", suffix=".jsonl")
                os.close(descriptor)
                trace_path = Path(path)
                environment["HARNESSCREATOR_TRACE_JSONL"] = path
                target_probe = RequestTraceJournal(trace_path)
            elif shutil.which("gdb") is not None and not stdin_mode:
                assert self.graph is not None
                gdb_probe = _GdbTargetProbe(
                    self.project,
                    self.graph,
                    self.actions.values(),
                    redirect_inferior_stdio=stdin_mode,
                )
                target_probe = gdb_probe
                protocol_stdin_write = gdb_probe.stdin_fd
                protocol_stdout_read = gdb_probe.stdout_fd
                launch_argv = gdb_probe.launch_argv(argv)
            # Without GDB, exploratory mode still replays the real request;
            # it cannot imply Entry/handler reach and remains an unqualified draft.
        launch_started = time.monotonic()
        try:
            process = await asyncio.create_subprocess_exec(
                *launch_argv,
                cwd=self.project.source_root,
                env=environment,
                stdin=(
                    asyncio.subprocess.DEVNULL
                    if gdb_probe is not None
                    else asyncio.subprocess.PIPE
                    if stdin_mode
                    else asyncio.subprocess.DEVNULL
                ),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        except BaseException:
            if unix_socket_dir is not None:
                unix_socket_dir.cleanup()
            if gdb_probe is not None:
                gdb_probe.close()
            if trace_path is not None:
                try:
                    trace_path.unlink(missing_ok=True)
                except OSError:
                    pass
            raise
        observations: list[RuntimeStepObservation] = []
        connection_prelude = b""
        connection_prelude_error = ""
        executed_steps: list[ScenarioStep] = []
        runtime_bindings: dict[str, bytes] = {}
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        udp_socket: socket.socket | None = None
        infrastructure_error = ""
        captured_stdout = b""
        captured_stderr = b""
        natural_returncode: int | None = None
        tcp_connect_after_launch_seconds: float | None = None
        verifier_terminated = False
        stdout_drain: asyncio.Task[bytes] | None = None
        stderr_drain: asyncio.Task[bytes] | None = None
        if process.stderr is not None:
            stderr_drain = asyncio.create_task(
                _drain_stream(process.stderr, self.project.scenario_response_limit)
            )
        if (not stdin_mode or gdb_probe is not None) and process.stdout is not None:
            stdout_drain = asyncio.create_task(
                _drain_stream(process.stdout, self.project.scenario_response_limit)
            )
        try:
            if self.project.scenario_channel in {"tcp", "unix_stream"}:
                reader, writer = (
                    await self._connect_tcp(process)
                    if self.project.scenario_channel == "tcp"
                    else await self._connect_unix(process, unix_socket_path)
                )
                tcp_connect_after_launch_seconds = (
                    time.monotonic() - launch_started
                )
                first_marker = (
                    candidate.steps[0].connection_prelude_marker_hex
                    if candidate.steps else ""
                )
                if first_marker:
                    try:
                        connection_prelude = await _read_line_prelude(
                            reader, bytes.fromhex(first_marker),
                            limit=self.project.scenario_response_limit,
                            timeout=self.project.scenario_startup_timeout,
                        )
                    except (ValueError, TimeoutError, asyncio.TimeoutError,
                            asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                            ConnectionError) as exc:
                        connection_prelude_error = (
                            f"source-proposed server-first line was not observed "
                            f"before client input: {type(exc).__name__}: {exc}"
                        )
            elif self.project.scenario_channel == "udp":
                udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_socket.settimeout(self.project.scenario_step_timeout)
            elif self.project.scenario_channel == "stdin":
                await asyncio.sleep(min(0.05, self.project.scenario_startup_timeout))

            for step in candidate.steps:
                started = time.monotonic()
                action = self.actions[step.action_id]
                if connection_prelude_error:
                    observations.append(RuntimeStepObservation(
                        index=step.index, action_id=step.action_id,
                        request_hex=step.request_hex, response_hex="",
                        success=False, detail=connection_prelude_error,
                        duration_seconds=time.monotonic() - started,
                        target_function_id=action.handler_function_id,
                        entry_function_id=action.entry_function_id,
                    ))
                    break
                target_offset = target_probe.offset() if target_probe is not None else 0
                request, binding_error = _materialize_runtime_request(
                    step, runtime_bindings
                )
                concrete_step = replace(step, request_hex=request.hex())
                executed_steps.append(concrete_step)
                extracted_bindings: dict[str, str] = {}
                if binding_error:
                    observations.append(RuntimeStepObservation(
                        index=step.index,
                        action_id=step.action_id,
                        request_hex=request.hex(),
                        response_hex="",
                        success=False,
                        detail=binding_error,
                        duration_seconds=time.monotonic() - started,
                        response_success=False,
                        extracted_bindings={},
                        target_function_id=action.handler_function_id,
                        target_reached=False,
                        target_probe=(target_probe.mechanism if target_probe else "runtime observer"),
                        entry_function_id=action.entry_function_id,
                        entry_reached=False,
                        probe_trace=[],
                    ))
                    break
                protocol_success = None
                unverified_request_trial = any(
                    _is_experimental_input_origin(example.origin)
                    for example in action.examples
                )
                # The original process may still be initializing when the
                # first request is delivered (especially under a debugger).
                # An ordinary per-request timeout must not classify slow
                # startup as an invalid input or an absent handler.
                response_timeout = (
                    max(self.project.scenario_startup_timeout,
                        self.project.scenario_step_timeout)
                    if step.index == candidate.steps[0].index
                    else self.project.scenario_step_timeout
                )
                oracle_read_timed_out = False
                request_write_completed = False
                write_observation: list[bool] = []
                try:
                    if self.project.scenario_channel in {"tcp", "unix_stream"}:
                        assert writer is not None and reader is not None
                        writer.write(request)
                        await writer.drain()
                        request_write_completed = True
                        if self.project.scenario_response_protocol == "memcached_ascii":
                            response, protocol_success = await read_memcached_response(
                                reader, request, limit=self.project.scenario_response_limit,
                                timeout=response_timeout,
                            )
                        else:
                            response = await _read_until_oracle(
                                reader, self._oracle_markers(step),
                                limit=self.project.scenario_response_limit,
                                timeout=response_timeout,
                                minimum_size=_minimum_response_size(step),
                            )
                    elif self.project.scenario_channel == "udp":
                        assert udp_socket is not None and self.project.scenario_port is not None
                        response = await asyncio.to_thread(
                            _udp_exchange_with_startup_retry,
                            udp_socket,
                            request,
                            self.project.scenario_host,
                            self.project.scenario_port,
                            self.project.scenario_response_limit,
                            response_timeout,
                            write_observation=write_observation,
                        )
                        request_write_completed = bool(write_observation)
                    else:
                        if gdb_probe is not None:
                            assert protocol_stdin_write is not None
                            assert protocol_stdout_read is not None
                            await asyncio.to_thread(
                                _write_all_fd, protocol_stdin_write, request
                            )
                            request_write_completed = True
                            response = await asyncio.to_thread(
                                _read_fd_until_oracle,
                                protocol_stdout_read,
                                self._oracle_markers(step),
                                self.project.scenario_response_limit,
                                response_timeout,
                                _minimum_response_size(step),
                            )
                        else:
                            assert process.stdin is not None and process.stdout is not None
                            process.stdin.write(request)
                            await process.stdin.drain()
                            request_write_completed = True
                            if (unverified_request_trial
                                and len(candidate.steps) == 1
                                and not self._oracle_markers(step)):
                                # A one-request stdin hypothesis has no
                                # response grammar or follow-up write. Close
                                # the pipe so EOF-delimited programs can
                                # finish instead of spending the full reply
                                # timeout waiting for another input. This is
                                # exploratory only and grants no success proof.
                                process.stdin.close()
                            response = await _read_until_oracle(
                                process.stdout,
                                self._oracle_markers(step),
                                limit=self.project.scenario_response_limit,
                                timeout=response_timeout,
                                minimum_size=_minimum_response_size(step),
                            )
                    success, detail = self._response_success(step, response)
                    if (
                        response
                        and self.project.scenario_response_protocol == "markers"
                        and not self._oracle_markers(step)
                        and _minimum_response_size(step) == 0
                    ):
                        detail += (
                            "; first available stream chunk observed; "
                            "origin and frame boundary unknown"
                        )
                    if (
                        self.project.scenario_exploratory_drafts
                        and unverified_request_trial
                        and protocol_success is True
                        and not step.expected_success_markers_hex
                    ):
                        # A protocol parser can recognize STORED without a
                        # source-derived oracle. This is useful evidence for
                        # a draft, but must NEVER become PROVEN_RUNTIME.
                        success = True
                        detail = (
                            "protocol-level acceptance observed on the original "
                            "program; source-derived success and exact handler "
                            "attribution remain unproven"
                        )
                    if protocol_success is False:
                        success, detail = False, "memcached response reports failure or lookup miss"
                    response_success = success
                    if success:
                        extracted, extraction_error = _extract_response_bindings(
                            step, response
                        )
                        if extraction_error:
                            success = False
                            detail = extraction_error
                        else:
                            runtime_bindings.update(extracted)
                            extracted_bindings = {
                                name: value.hex()
                                for name, value in extracted.items()
                            }
                except (asyncio.TimeoutError, TimeoutError, ConnectionError, OSError, FrameError) as exc:
                    if self.project.scenario_channel == "udp":
                        request_write_completed = bool(write_observation)
                    # A partial reply is useful when recovering an unknown
                    # input format. It remains a failed response observation:
                    # the expected frame/result was never completed.
                    response = exc.partial if isinstance(exc, ResponseReadTimeout) else b""
                    success = False
                    response_success = False
                    oracle_read_timed_out = isinstance(exc, (asyncio.TimeoutError, TimeoutError))
                    detail = f"transport/response failure: {type(exc).__name__}: {exc}"
                    if response:
                        detail += "; partial response bytes preserved without success proof"
                (
                    entry_reached,
                    target_reached,
                    target_mechanism,
                    observed_probe_trace,
                ) = await self._target_reached(
                    step,
                    action,
                    request,
                    response,
                    target_probe,
                    target_offset,
                )
                # A source-backed response marker and a request-correlated
                # explicit failure outcome cannot jointly prove successful
                # normal flow. Preserve the observed response separately but
                # fail closed on this contradictory original-program record.
                if "semantic-outcome:failure" in observed_probe_trace:
                    success = False
                    detail = (
                        "request-correlated original trace reports failure; "
                        "response marker cannot establish successful completion"
                    )
                if (success and target_mechanism == "request-correlated-jsonl-v1"
                    and not response_attested(observed_probe_trace, response)):
                    success = False
                    detail = (
                        "handler attribution was observed, but the original "
                        "result was not bound to this request and response"
                    )
                if (
                    not success
                    and not step.expected_success_markers_hex
                    and not step.response_binding_extractors
                    and action.success_evidence
                    and not unverified_request_trial
                    and protocol_success is not False
                    and (not detail.startswith("transport/response failure:") or oracle_read_timed_out)
                    and not detail.startswith("matched failure marker")
                    and self._trace_reports_success(
                        entry_reached, target_reached, target_mechanism,
                        observed_probe_trace,
                    )
                ):
                    success = True
                    detail = "source-backed success outcome observed for this exact request in the original program"
                target_observed = target_reached
                if gdb_probe is not None:
                    # Independently record the GDB observation. It cannot
                    # establish attribution and must not set target_reached.
                    _, target_observed = gdb_probe.ordered_chain_reached(
                        action, target_offset
                    )
                if success and (not entry_reached or not target_reached):
                    if self.project.scenario_exploratory_drafts:
                        # Protocol acceptance can be observed without an
                        # instrumented request trace. Keep the replay result
                        # so source-supported candidates survive; it never
                        # establishes exact handler reachability and cannot
                        # become PROVEN_RUNTIME.
                        if entry_reached and target_observed:
                            detail += "; ordered breakpoint chain observed without request attribution"
                        else:
                            detail += "; original response replayed without request-correlated target evidence"
                    else:
                        success = False
                        detail = (
                            f"{detail}; response oracle matched, but the exact "
                            f"acquisition-to-handler chain "
                            f"{action.entry_function_id}->{action.handler_function_id} "
                            "was not established for this request"
                        )
                observations.append(RuntimeStepObservation(
                    index=step.index,
                    action_id=step.action_id,
                    request_hex=request.hex(),
                    response_hex=response.hex(),
                    success=success,
                    detail=detail,
                    duration_seconds=time.monotonic() - started,
                    request_write_completed=request_write_completed,
                    response_success=response_success,
                    extracted_bindings=extracted_bindings,
                    target_function_id=action.handler_function_id,
                    target_reached=target_reached,
                    target_observed=target_observed,
                    target_probe=target_mechanism,
                    entry_function_id=action.entry_function_id,
                    entry_reached=entry_reached,
                    probe_trace=observed_probe_trace,
                ))
                if not success:
                    break
                if process.returncode is not None:
                    natural_returncode = process.returncode
                    break
            natural_returncode = process.returncode if process.returncode is not None else natural_returncode
        except (ConnectionError, OSError, asyncio.TimeoutError) as exc:
            infrastructure_error = f"original program did not become ready: {type(exc).__name__}: {exc}"
        finally:
            launched_descendants = _process_descendants(process.pid)
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except (ConnectionError, OSError):
                    pass
            if udp_socket is not None:
                udp_socket.close()
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except (BrokenPipeError, ConnectionError):
                    pass
            if target_probe is None:
                for descriptor in (
                    protocol_stdin_write, protocol_stdout_read,
                    protocol_stdin_read, protocol_stdout_write,
                ):
                    if isinstance(descriptor, int):
                        try:
                            os.close(descriptor)
                        except OSError:
                            pass
            if process.returncode is None:
                # Give a peer that just closed/crashed a short chance to report
                # its natural status before we deliberately terminate a normal
                # long-running server.
                await asyncio.sleep(0.05)
            if process.returncode is None:
                verifier_terminated = True
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    verifier_terminated = False
                _signal_processes(launched_descendants, signal.SIGTERM)
                try:
                    await asyncio.wait_for(process.wait(), timeout=1.0)
                except asyncio.TimeoutError:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    _signal_processes(launched_descendants, signal.SIGKILL)
                    await process.wait()
            if not verifier_terminated:
                natural_returncode = process.returncode
            if gdb_probe is not None:
                # Closing the verifier-held FIFO endpoints also releases an
                # inferior that is still blocked in a stdin read after GDB
                # itself has terminated.
                gdb_probe.close()
            if trace_path is not None:
                try:
                    trace_path.unlink(missing_ok=True)
                except OSError:
                    pass
            if stdout_drain is not None:
                captured_stdout = await _bounded_drain_result(stdout_drain)
            elif process.stdout is not None:
                captured_stdout = await process.stdout.read(
                    self.project.scenario_response_limit
                )
            if stderr_drain is not None:
                captured_stderr = await _bounded_drain_result(stderr_drain)
            if unix_socket_dir is not None:
                unix_socket_dir.cleanup()

        observed_output = b"\n".join(
            bytes.fromhex(item.response_hex) for item in observations
        )
        crash_output = observed_output + b"\n" + captured_stdout + b"\n" + captured_stderr
        crashed = (
            natural_returncode is not None and natural_returncode < 0
        ) or any(marker in crash_output for marker in _CRASH_MARKERS) or bool(
            re.search(rb"Program received signal SIG[A-Z0-9]+", crash_output)
        )
        if infrastructure_error:
            status = ScenarioStatus.INFRASTRUCTURE_FAILED
            rationale = infrastructure_error
        elif crashed:
            status = ScenarioStatus.REJECTED
            rationale = "the proposed normal-flow scenario crashed the original program"
        elif natural_returncode not in {None, 0}:
            status = ScenarioStatus.UNPROVEN
            rationale = (
                "the original program exited with a nonzero status after the "
                "request; normal completion was not established"
            )
        elif observations and len(observations) == len(candidate.steps) and all(
            item.success and item.target_reached
            and item.target_probe == "request-correlated-jsonl-v1"
            and response_attested(item.probe_trace, bytes.fromhex(item.response_hex))
            for item in observations
        ) and all(
            self.actions[step.action_id].success_evidence
            and not any(
                _is_experimental_input_origin(example.origin)
                for example in self.actions[step.action_id].examples
            )
            for step in candidate.steps
        ):
            status = ScenarioStatus.PROVEN_RUNTIME
            rationale = (
                "every request reached its exact graph-resolved handler and "
                "completed with a source-derived response marker or request-correlated success outcome in the original program"
            )
        elif (
            self.project.scenario_exploratory_drafts
            and observations
            and len(observations) == len(candidate.steps)
            and all(item.response_success and item.success for item in observations)
            and all(item.entry_reached and item.target_observed for item in observations)
        ):
            status = ScenarioStatus.OBSERVED_RUNTIME
            rationale = (
                "accepted responses and ordered Entry-to-handler breakpoints "
                "were observed without request identity; NOT a PROVEN_RUNTIME witness"
            )
        elif (
            self.project.scenario_exploratory_drafts
            and observations
            and len(observations) == len(candidate.steps)
            and all(item.response_success and item.success for item in observations)
            and not all(item.target_reached for item in observations)
        ):
            status = ScenarioStatus.REPLAYED_RUNTIME
            rationale = (
                "accepted responses replayed in a fresh original process, "
                "but exact Entry/handler attribution is unavailable; NOT PROVEN_RUNTIME"
            )
        else:
            status = ScenarioStatus.UNPROVEN
            rationale = (
                observations[-1].detail if observations
                else "no request observation was produced"
            )
            if target_probe is not None and (captured_stdout or captured_stderr):
                probe_diagnostics = (captured_stdout + b"\n" + captured_stderr).decode(
                    "utf-8", errors="replace"
                )[-2000:]
                rationale += f"; target-probe diagnostics: {probe_diagnostics}"
        action_bindings = [
            ObservedActionBinding(
                step_index=item.index,
                action_id=item.action_id,
                entry_id=next(
                    (step.entry_id for step in executed_steps if step.index == item.index),
                    "",
                ),
                actor=self.actions[item.action_id].actor,
                direction=self.actions[item.action_id].direction,
                channel=self.project.scenario_channel,
                request_hex=item.request_hex,
                entry_function_id=item.entry_function_id,
                entry_reached=item.entry_reached,
                target_function_id=item.target_function_id,
                target_reached=item.target_reached,
                response_success=item.response_success,
                state_observation=item.detail,
                probe=item.target_probe,
                probe_trace=list(item.probe_trace),
            )
            for item in observations
        ]
        crash_text = crash_output.decode("utf-8", errors="replace")[-16_000:]
        return ScenarioWitness(
            witness_id=stable_id("witness", candidate.scenario_id, status, *[item.response_hex for item in observations]),
            scenario_id=candidate.scenario_id,
            target_action_id=candidate.target_action_id,
            steps=(
                executed_steps
                if status in {ScenarioStatus.PROVEN_RUNTIME, ScenarioStatus.OBSERVED_RUNTIME, ScenarioStatus.REPLAYED_RUNTIME}
                else list(candidate.steps)
            ),
            observations=observations,
            command=argv,
            channel=self.project.scenario_channel,
            process_returncode=natural_returncode,
            status=status,
            rationale=rationale,
            original_program_crashed=crashed,
            sanitizer_output=crash_text if crashed else "",
            action_bindings=action_bindings,
            target_trace=[
                marker
                for item in observations
                for marker in item.probe_trace
            ],
            fuzz_step_index=candidate.fuzz_step_index,
            crash_signature=(
                extract_crash_signature(crash_text, natural_returncode)
                if crashed else None
            ),
            tcp_connect_after_launch_seconds=tcp_connect_after_launch_seconds,
            connection_prelude_hex=connection_prelude.hex(),
        )

    async def _target_reached(
        self,
        step: ScenarioStep,
        action: ExternalActionSchema,
        request: bytes,
        response: bytes,
        probe: _GdbTargetProbe | RequestTraceJournal | None,
        probe_offset: int,
    ) -> tuple[bool, bool, str, list[str]]:
        if self._target_observer is not None:
            observed = self._target_observer(step, action, request, response)
            if inspect.isawaitable(observed):
                observed = await observed
            return (
                bool(observed),
                bool(observed),
                "injected runtime target observer",
                [f"injected-observer:{str(bool(observed)).casefold()}"],
            )
        if not self.project.scenario_require_target_reach:
            # Skipping a check is not a positive observation. This option is
            # available to direct API callers for exploratory tests only and
            # must never manufacture a PROVEN_RUNTIME witness.
            return (
                False,
                False,
                "target reach check explicitly disabled; no attribution proof",
                ["target-reach-check-disabled"],
            )
        if probe is None:
            return False, False, "no exact-target probe", []
        if isinstance(probe, RequestTraceJournal):
            success_sites: list[tuple[str, int]] = []
            if self.graph is not None:
                for item in action.success_evidence:
                    if item.line is None:
                        continue
                    for site in _probe_sites(
                        [item], self.graph,
                        required_function_id=item.function_id,
                    ):
                        if site == (item.file, item.line):
                            success_sites.append((item.function_id, item.line))
            # The daemon can flush its reply before appending the request's
            # result event. Read the append-only journal until that same
            # request completes or the configured step time expires. A
            # contradictory completed event is never repaired by waiting.
            loop = asyncio.get_running_loop()
            deadline = loop.time() + self.project.scenario_step_timeout
            while True:
                observed = probe.observe(
                    probe_offset,
                    request,
                    action.entry_function_id,
                    action.handler_function_id,
                    action.dispatcher_function_id,
                    require_dispatch=bool(action.operation_seed_ids),
                    response=response,
                    success_sites=tuple(success_sites),
                )
                if not observed.pending:
                    break
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                await asyncio.sleep(min(0.02, remaining))
            return (
                observed.entry_reached,
                observed.target_reached,
                probe.mechanism + (f"; {observed.problem}" if observed.problem else ""),
                list(observed.trace),
            )
        entry_reached, target_reached, trace = probe.ordered_chain_observation(
            action,
            probe_offset,
        )
        # Breakpoint markers contain no request, connection, or thread identity.
        # Another request can produce the same ordered sequence in this time
        # slice. Until a probe can prove request attribution, those markers
        # are diagnostic only and cannot establish a runtime witness.
        return (
            entry_reached,
            False,
            probe.mechanism + "; request attribution unavailable",
            trace,
        )

    def _environment_variable_name(self, action_id: str) -> str:
        if self.project.scenario_input_env:
            return self.project.scenario_input_env
        action = self.actions.get(action_id)
        if action is None or self.graph is None:
            return ""
        function = self.graph.bundle.functions.get(action.entry_function_id)
        if function is None:
            return ""
        names = set(re.findall(
            r'\b(?:getenv|secure_getenv)\s*\(\s*"([A-Za-z_][A-Za-z0-9_]*)"\s*\)',
            function.source,
        ))
        return next(iter(names)) if len(names) == 1 else ""

    async def _execute_one_shot(self, candidate: ScenarioCandidate) -> ScenarioWitness:
        """Replay one source-derived input via a file/argv/environment surface.

        The command is trusted CLI configuration and never model-authored.
        Each invocation gets an isolated temp input; no shell expansion.
        Without a request-correlated trace (or injected test observer), an
        oracle match is at most an exploratory replay, NEVER runtime proof.
        """
        step = candidate.steps[0]
        action = self.actions[step.action_id]
        channel = self.project.scenario_channel
        request, binding_error = _materialize_runtime_request(step, {})
        if binding_error:
            return self._not_executed(candidate, binding_error)
        if channel in {"argv", "env"} and b"\x00" in request:
            return self._not_executed(candidate, f"{channel} cannot encode NUL bytes")
        argv = [
            token.replace("{source_root}", str(self.project.source_root))
            for token in self.project.scenario_command
        ]
        environment = os.environ.copy()
        environment.update(self.project.scenario_environment)
        trace_path: Path | None = None
        target_probe: RequestTraceJournal | None = None
        with tempfile.TemporaryDirectory(prefix="hc-original-input-") as scratch:
            input_file = Path(scratch) / "input.bin"
            if channel == "file":
                input_file.write_bytes(request)
                argv = [token.replace("{input_file}", str(input_file)) for token in argv]
            elif channel == "argv":
                text = request.decode("utf-8", errors="surrogateescape")
                argv = [token.replace("{input_arg}", text) for token in argv]
            elif channel == "env":
                name = self._environment_variable_name(step.action_id)
                if not name:
                    return self._not_executed(candidate, "environment key was not established")
                environment[name] = request.decode(
                    "utf-8", errors="surrogateescape"
                )
            if (self.project.scenario_attribution == "trace"
                and self.project.scenario_require_target_reach
                and self._target_observer is None):
                trace_path = Path(scratch) / "request-trace.jsonl"
                environment["HARNESSCREATOR_TRACE_JSONL"] = str(trace_path)
                target_probe = RequestTraceJournal(trace_path)
            started = time.monotonic()
            process = await asyncio.create_subprocess_exec(
                *argv, cwd=self.project.source_root, env=environment,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            stdout_task = asyncio.create_task(
                _drain_stream(process.stdout, self.project.scenario_response_limit)
            )
            stderr_task = asyncio.create_task(
                _drain_stream(process.stderr, self.project.scenario_response_limit)
            )
            try:
                await asyncio.wait_for(
                    process.wait(),
                    timeout=self.project.scenario_startup_timeout
                    + self.project.scenario_step_timeout,
                )
            except asyncio.TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
                await _bounded_drain_result(stdout_task)
                await _bounded_drain_result(stderr_task)
                return self._not_executed(
                    candidate, f"{channel} original program timed out"
                )
            stdout = await _bounded_drain_result(stdout_task)
            stderr = await _bounded_drain_result(stderr_task)
            response_success, detail = self._response_success(step, stdout)
            if process.returncode != 0:
                response_success = False
                detail += f"; original process exited with code {process.returncode}"
            (
                entry_reached, target_reached, target_mechanism, probe_trace,
            ) = await self._target_reached(
                step, action, request, stdout, target_probe, 0,
            )
            semantic_success = (
                process.returncode == 0
                and not step.expected_success_markers_hex
                and not step.response_binding_extractors
                and action.success_evidence
                and not any(
                    _is_experimental_input_origin(example.origin)
                    for example in action.examples
                )
                and not detail.startswith("matched failure marker")
                and self._trace_reports_success(
                    entry_reached, target_reached, target_mechanism, probe_trace,
                )
            )
            matched = (
                (response_success or semantic_success)
                and entry_reached and target_reached
                and (target_mechanism != "request-correlated-jsonl-v1"
                     or response_attested(probe_trace, stdout))
            )
            if (response_success and not matched and entry_reached and target_reached
                and target_mechanism == "request-correlated-jsonl-v1"):
                detail = (
                    "handler attribution was observed, but the original "
                    "result was not bound to this request and response"
                )
            if semantic_success:
                detail = "source-backed success outcome observed for this exact request in the original program"
            observation = RuntimeStepObservation(
                index=step.index, action_id=step.action_id,
                request_hex=request.hex(), response_hex=stdout.hex(),
                success=matched or (response_success and self.project.scenario_exploratory_drafts),
                detail=detail, duration_seconds=time.monotonic() - started,
                response_success=response_success, target_function_id=action.handler_function_id,
                target_reached=target_reached, target_probe=target_mechanism,
                entry_function_id=action.entry_function_id,
                entry_reached=entry_reached, probe_trace=probe_trace,
            )
            crashed = bool(
                any(marker in stderr for marker in _CRASH_MARKERS)
                or (process.returncode is not None and process.returncode < 0)
            )
            if crashed:
                status = ScenarioStatus.REJECTED
                rationale = "sanitizer/crash marker observed in original program"
            elif (matched and target_mechanism == "request-correlated-jsonl-v1"
                  and action.success_evidence
                  and not any(
                      _is_experimental_input_origin(example.origin)
                      for example in action.examples
                  )):
                status = ScenarioStatus.PROVEN_RUNTIME
                rationale = "request-correlated original execution and source-derived completion verified"
            elif matched:
                status = ScenarioStatus.UNPROVEN
                rationale = (
                    "original output matched the candidate marker and the target was "
                    "reached, but source-backed success evidence or established input "
                    "bytes are missing; NOT PROVEN_RUNTIME"
                )
            elif response_success and self.project.scenario_exploratory_drafts:
                status = ScenarioStatus.REPLAYED_RUNTIME
                rationale = (
                    "original process returned the source-derived success oracle, "
                    "but input-to-handler causality was not verified; NOT PROVEN_RUNTIME"
                )
            else:
                status = ScenarioStatus.UNPROVEN
                rationale = detail + "; exact entry-to-handler attribution unavailable"
            return ScenarioWitness(
                witness_id=stable_id("witness", candidate.scenario_id, status, request.hex(), stdout.hex()),
                scenario_id=candidate.scenario_id,
                target_action_id=candidate.target_action_id,
                steps=[replace(step, request_hex=request.hex())],
                observations=[observation],
                command=argv if channel != "env" else list(self.project.scenario_command),
                channel=channel, process_returncode=process.returncode,
                status=status, rationale=rationale,
                original_program_crashed=crashed,
                sanitizer_output=stderr.decode("utf-8", errors="replace") if crashed else "",
                fuzz_step_index=candidate.fuzz_step_index,
                crash_signature=(
                    extract_crash_signature(
                        stderr.decode("utf-8", errors="replace"),
                        process.returncode,
                    ) if crashed else None
                ),
            )

    async def _connect_tcp(
        self, process: asyncio.subprocess.Process
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        deadline = time.monotonic() + self.project.scenario_startup_timeout
        last_error: OSError | None = None
        while time.monotonic() < deadline:
            if process.returncode is not None:
                raise ConnectionError(
                    f"original program exited before accepting input: {process.returncode}"
                )
            try:
                return await asyncio.open_connection(
                    self.project.scenario_host, self.project.scenario_port
                )
            except OSError as exc:
                last_error = exc
                await asyncio.sleep(0.05)
        raise ConnectionError(
            f"timed out connecting to {self.project.scenario_host}:{self.project.scenario_port}: {last_error}"
        )

    async def _connect_unix(
        self, process: asyncio.subprocess.Process, pathname: str,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        deadline = time.monotonic() + self.project.scenario_startup_timeout
        last_error: OSError | None = None
        while time.monotonic() < deadline:
            if process.returncode is not None:
                raise ConnectionError(
                    f"original program exited before accepting Unix socket input: {process.returncode}"
                )
            try:
                return await asyncio.open_unix_connection(pathname)
            except OSError as exc:
                last_error = exc
                await asyncio.sleep(0.05)
        raise ConnectionError(
            f"timed out connecting to Unix socket {pathname}: {last_error}"
        )

    def _response_success(
        self, step: ScenarioStep, response: bytes
    ) -> tuple[bool, str]:
        action = self.actions.get(step.action_id)
        failure_markers = [
            bytes.fromhex(item) for item in (action.failure_markers_hex if action else [])
        ]
        matched_failure = next((
            item for item in failure_markers if _response_marker_matches(response, item)
        ), None)
        if matched_failure is not None:
            return False, f"matched failure marker {matched_failure.hex()}"
        markers = [bytes.fromhex(item) for item in step.expected_success_markers_hex]
        if not markers:
            return False, "no source-derived response success marker was available"
        matched = next((
            item for item in markers if _response_marker_matches(response, item)
        ), None)
        if matched is None:
            return False, "response did not contain any expected success marker"
        return True, f"matched success marker {matched.hex()}"

    @staticmethod
    def _trace_reports_success(
        entry_reached: bool, target_reached: bool,
        mechanism: str, trace: list[str],
    ) -> bool:
        # Only a cooperating original build can make this claim. A response,
        # GDB hit order, injected test observer, or state digest alone cannot.
        return (
            entry_reached and target_reached
            and mechanism == "request-correlated-jsonl-v1"
            and "semantic-outcome:success" in trace
            and "semantic-outcome:failure" not in trace
        )

    def _oracle_markers(self, step: ScenarioStep) -> list[bytes]:
        action = self.actions.get(step.action_id)
        values = [*step.expected_success_markers_hex]
        if action is not None:
            values.extend(action.failure_markers_hex)
        return [bytes.fromhex(item) for item in dict.fromkeys(values)]

    def _compatibility_error(self, candidate: ScenarioCandidate) -> str:
        channel = self.project.scenario_channel
        if any(step.connection_prelude_marker_hex for step in candidate.steps):
            if channel not in {"tcp", "unix_stream"}:
                return "line-framed server-first prelude requires a stream socket executor"
            if (not candidate.steps
                or any(step.connection_prelude_marker_hex for step in candidate.steps[1:])):
                return "server-first prelude belongs only to the first step on a fresh connection"
        if channel in {"file", "argv", "env"}:
            if len(candidate.steps) != 1:
                return (
                    f"{channel} executor is single-shot; multiple setup/post requests "
                    "need a state-preserving adapter, not separate process launches"
                )
            if channel == "file" and not any(
                "{input_file}" in token for token in self.project.scenario_command
            ):
                return "file executor requires a {input_file} argument in --scenario-command"
            if channel == "argv" and not any(
                "{input_arg}" in token for token in self.project.scenario_command
            ):
                return "argv executor requires an {input_arg} argument in --scenario-command"
            if channel == "env" and not self._environment_variable_name(candidate.steps[0].action_id):
                return "env executor requires a unique source-backed getenv(\"NAME\") or --scenario-input-env NAME"
            if (self.project.scenario_require_target_reach
                and self._target_observer is None
                and self.project.scenario_attribution != "trace"
                and not self.project.scenario_exploratory_drafts):
                return (
                    f"{channel} executor requires request-correlated trace instrumentation "
                    "for strict proof, or --scenario-exploratory-drafts for unqualified replay"
                )
        if self.project.scenario_require_target_reach and self._target_observer is None:
            if self.graph is None:
                return (
                    "exact target reach is required, but no analysis graph was "
                    "provided to the original-program verifier"
                )
            if self.project.scenario_attribution == "gdb":
                if not self.project.scenario_exploratory_drafts:
                    # _target_reached() deliberately treats GDB's ordered
                    # breakpoint hits as diagnostic: they carry no request
                    # identity. Avoid executing a whole scenario only to
                    # produce the same unavoidable UNPROVEN verdict.
                    return (
                        "strict request attribution is unavailable from GDB "
                        "breakpoint order; configure request-correlated trace "
                        "instrumentation or explicitly choose unqualified "
                        "exploratory drafts"
                    )
        available_bindings: dict[str, tuple[int, int]] = {}
        for step in candidate.steps:
            action = self.actions.get(step.action_id)
            if action is None:
                return f"scenario references unknown action {step.action_id}"
            if (
                self.project.scenario_require_target_reach
                and self._target_observer is None
                and self.graph is not None
                and action.handler_function_id not in self.graph.bundle.functions
            ):
                return (
                    f"action {step.action_id} has no graph-resolved exact handler "
                    f"{action.handler_function_id!r}"
                )
            if (
                self.project.scenario_require_target_reach
                and self._target_observer is None
                and self.graph is not None
                and action.entry_function_id not in self.graph.bundle.functions
            ):
                return (
                    f"action {step.action_id} has no graph-resolved acquisition "
                    f"function {action.entry_function_id!r}"
                )
            if (self.project.scenario_require_target_reach
                and self._target_observer is None
                and not self.project.scenario_exploratory_drafts):
                # Strict mode needs source-located probes. Exploratory mode
                # may replay without them but can never treat a mere response
                # as attributed handler reachability.
                entry_probe_error = _probe_evidence_error(
                    action.entry_probe_evidence,
                    self.graph,
                    required_function_id=action.entry_function_id,
                    label="verified acquisition",
                )
                if entry_probe_error:
                    return f"action {step.action_id}: {entry_probe_error}"
                if action.operation_seed_ids:
                    dispatch_probe_error = _probe_evidence_error(
                        action.dispatch_probe_evidence,
                        self.graph,
                        required_function_id=action.dispatcher_function_id,
                        label="dispatcher branch",
                    )
                    if dispatch_probe_error:
                        return f"action {step.action_id}: {dispatch_probe_error}"
                if (
                    self.project.scenario_attribution == "gdb"
                    and not (self.project.scenario_exploratory_drafts and shutil.which("gdb") is None)
                    and action.handler_function_id == action.dispatcher_function_id
                    and not action.dispatch_probe_evidence
                ):
                    return (
                        f"action {step.action_id} is handled inside its dispatcher, "
                        "but has no exact branch probe; function-entry reach would "
                        "not distinguish the requested operation"
                    )
            transport = _action_transport(action)
            if (not transport and self.project.scenario_channel in {"tcp", "udp"}
                and permits_explicit_socket_trial(
                    action.channel_kind, action.source_api, self.project.scenario_channel,
                )):
                # An explicitly configured Internet endpoint is a runtime
                # hypothesis. It may be tried against the original program,
                # but only request-correlated original trace can prove that
                # this Entry actually acquired the submitted bytes. Auto
                # selection still refuses to infer TCP/UDP from recv spelling.
                transport = self.project.scenario_channel
            if (not transport and self.project.scenario_channel == "unix_stream"
                and permits_explicit_socket_trial(
                    action.channel_kind, action.source_api, "unix_stream",
                )):
                # A configured AF_UNIX pathname is a trial for an unresolved
                # Unix socket type. The original trace still owns proof.
                transport = "unix_stream"
            if not transport:
                return (
                    f"action {step.action_id} has no configured concrete executor "
                    f"for channel {action.channel_kind!r} and source API {action.source_api!r}"
                )
            if transport and transport != self.project.scenario_channel:
                return (
                    f"action {step.action_id} uses {transport}, but the configured "
                    f"original-program executor uses {self.project.scenario_channel}"
                )
            if (
                self.project.scenario_channel in {"tcp", "udp", "unix_stream"}
                and action.actor is ActionActor.OUTBOUND_PEER
            ):
                return (
                    f"action {step.action_id} consumes an outbound-peer response, "
                    "but the configured executor supplies inbound client requests"
                )
            if not action.success_markers_hex or not action.success_evidence:
                # A source-located command literal can justify a bounded
                # original-program *trial*, not a success verdict. Preserve
                # the ordinary strict oracle gate for all other candidates.
                # A source-backed, request-correlated result event is the
                # sole markerless completion path in strict trace mode.
                is_unverified_trial = any(
                    _is_experimental_input_origin(example.origin)
                    for example in action.examples
                )
                # Experimental raw data is an allowed ORIGINAL-PROGRAM
                # execution even in strict mode. It still cannot establish
                # a success oracle, target attribution, or PROVEN_RUNTIME.
                trace_outcome_can_be_tested = (
                    bool(action.success_evidence)
                    and not action.success_markers_hex
                    and self.project.scenario_attribution == "trace"
                    and self.project.scenario_require_target_reach
                    and self._target_observer is None
                )
                if (not is_unverified_trial
                    and not trace_outcome_can_be_tested
                    and self.project.scenario_require_target_reach):
                    return (
                        f"action {step.action_id} has no source-evidenced success oracle"
                    )
            template_hex = step.request_template_hex or step.request_hex
            try:
                template_size = len(bytes.fromhex(template_hex))
            except ValueError:
                return f"action {step.action_id} has an invalid request template"
            for use in step.request_binding_uses:
                source = available_bindings.get(use.binding)
                if source is None:
                    return (
                        f"action {step.action_id} consumes runtime binding "
                        f"{use.binding!r} before a response extractor produced it"
                    )
                producer_index, width = source
                if producer_index != use.producer_step_index:
                    return (
                        f"action {step.action_id} binding {use.binding!r} names "
                        "a different producer step"
                    )
                if width != use.width:
                    return (
                        f"action {step.action_id} binding {use.binding!r} width "
                        f"mismatch: response={width}, request={use.width}"
                    )
                if use.offset < 0 or use.offset + use.width > template_size:
                    return (
                        f"action {step.action_id} binding {use.binding!r} patch "
                        "falls outside the request template"
                    )
            for extractor in step.response_binding_extractors:
                available_bindings[extractor.binding] = (
                    step.index, extractor.width
                )
        return ""

    def _not_executed(
        self, candidate: ScenarioCandidate, rationale: str
    ) -> ScenarioWitness:
        return ScenarioWitness(
            witness_id=stable_id("witness", candidate.scenario_id, "unproven", rationale),
            scenario_id=candidate.scenario_id,
            target_action_id=candidate.target_action_id,
            steps=list(candidate.steps),
            observations=[],
            command=list(self.project.scenario_command),
            channel=self.project.scenario_channel,
            process_returncode=None,
            status=ScenarioStatus.UNPROVEN,
            rationale=rationale,
            fuzz_step_index=candidate.fuzz_step_index,
        )


class OriginalCrashReproducer:
    """Lift a harness crash back to external requests and replay it."""

    def __init__(self, verifier: ScenarioRuntimeVerifier):
        self.verifier = verifier

    async def reproduce(
        self,
        harness_id: str,
        plan: HarnessPlan,
        seeds: list[SeedSpec],
    ) -> list[OriginalCrashReplay]:
        if not seeds:
            return []
        result: list[OriginalCrashReplay] = []
        for seed in seeds:
            lifted = [*plan.setup_steps, replace(
                plan.fuzz_step,
                index=len(plan.setup_steps),
                request_hex=seed.data_hex,
                request_template_hex=seed.data_hex,
            ), *plan.post_steps]
            candidate = ScenarioCandidate(
                scenario_id=stable_id("crash-scenario", harness_id, seed.name, seed.data_hex),
                target_action_id=plan.target_action_id,
                steps=lifted,
                required_entries=list(dict.fromkeys(step.entry_id for step in lifted)),
                satisfied_resources=[],
                planning_evidence=["fuzz-step mapping from the accepted HarnessPlan"],
                fuzz_step_index=len(plan.setup_steps),
            )
            # A finding must be reproduced by a fresh original-program
            # execution.  Reusing a normal-flow witness would hide changed
            # nonces/session IDs and would not be crash reproduction.
            observation = await self.verifier.verify(candidate, use_cache=False)
            expected_signature = seed.crash_signature
            observed_signature = observation.crash_signature
            signature_matched = crash_signatures_match(
                expected_signature, observed_signature
            )
            input_attributed = _crash_replay_has_exact_input_acquisition(
                observation, candidate.fuzz_step_index,
            )
            status = (
                CrashReproductionStatus.ORIGINAL_REPRODUCED
                if observation.original_program_crashed and signature_matched
                else CrashReproductionStatus.INFRASTRUCTURE_FAILED
                if observation.status is ScenarioStatus.INFRASTRUCTURE_FAILED
                else CrashReproductionStatus.UNCONFIRMED
            )
            if status is CrashReproductionStatus.ORIGINAL_REPRODUCED and input_attributed:
                rationale = (
                    "the original acquired the exact fuzzed request and "
                    "reproduced the same normalized crash signature"
                )
            elif status is CrashReproductionStatus.ORIGINAL_REPRODUCED:
                rationale = (
                    "the original reproduced the normalized crash signature; "
                    "request-to-Entry causality and vulnerability status remain unproven"
                )
            elif status is CrashReproductionStatus.INFRASTRUCTURE_FAILED:
                rationale = (
                    "the original execution failed before replay could complete: "
                    + observation.rationale
                )
            elif observation.original_program_crashed:
                rationale = (
                    "original program crashed at a different primary location; "
                    "this does not prove the harness is faulty"
                )
            else:
                rationale = (
                    "original crash was not reproduced in this attempt; "
                    "the cause remains unconfirmed"
                )
            result.append(OriginalCrashReplay(
                replay_id=stable_id("crash-replay", harness_id, seed.name, status),
                harness_id=harness_id,
                seed=seed,
                lifted_steps=lifted,
                status=status,
                observation=observation,
                rationale=rationale,
                expected_signature=expected_signature,
                observed_signature=observed_signature,
                signature_matched=signature_matched,
                input_attributed=input_attributed,
            ))
        return result


def _crash_replay_has_exact_input_acquisition(
    witness: ScenarioWitness, fuzz_step_index: int,
) -> bool:
    """Only attribute a crash after the original acquired the fuzzed bytes.

    A breakpoint hit or a local socket write can coexist with an unrelated
    startup/background crash. The request trace checks the exact byte digest
    and Entry identity; a crash may occur before a handler/result event.
    """
    return any(
        step.index == fuzz_step_index
        and step.entry_reached
        and step.target_probe.startswith("request-correlated-jsonl-v1")
        and step.request_hex == next(
            (item.request_hex for item in witness.steps
             if item.index == fuzz_step_index), None,
        )
        for step in witness.observations
    )


class _GdbTargetProbe:
    """Record an ordered Entry-to-handler trace without altering protocol bytes."""

    mechanism = "GDB ordered Entry-to-handler breakpoint trace"

    def __init__(
        self,
        project: ProjectSpec,
        graph: GraphStore,
        actions: Iterable[ExternalActionSchema],
        *,
        redirect_inferior_stdio: bool,
    ) -> None:
        gdb = shutil.which("gdb")
        if gdb is None:
            raise RuntimeError("GDB is unavailable")
        self.gdb = gdb
        self.project = project
        self.graph = graph
        self._temporary = tempfile.TemporaryDirectory(
            prefix="harnesscreator-target-"
        )
        root = Path(self._temporary.name)
        self.trace_path = root / "hits.log"
        self.script_path = root / "target.gdb"
        self.stdin_fd: int | None = None
        self.stdout_fd: int | None = None
        inferior_stdin: Path | None = None
        inferior_stdout: Path | None = None
        if redirect_inferior_stdio:
            inferior_stdin = root / "inferior.stdin"
            inferior_stdout = root / "inferior.stdout"
            os.mkfifo(inferior_stdin, 0o600)
            os.mkfifo(inferior_stdout, 0o600)
            # O_RDWR prevents either side's open(2) from deadlocking during
            # GDB startup.  The verifier still uses each descriptor in only
            # one direction.
            self.stdin_fd = os.open(inferior_stdin, os.O_RDWR)
            self.stdout_fd = os.open(inferior_stdout, os.O_RDWR)
        self.trace_path.touch()
        lines = [
            "set pagination off",
            "set confirm off",
            "set breakpoint pending on",
            "set follow-fork-mode child",
            "set print thread-events off",
        ]
        self._chains: dict[str, list[str]] = {}
        locations: dict[tuple[str, int], list[str]] = {}
        for action in actions:
            entry_sites = _probe_sites(
                action.entry_probe_evidence,
                graph,
                required_function_id=action.entry_function_id,
            )
            handler = graph.bundle.functions.get(action.handler_function_id)
            if not entry_sites or handler is None:
                raise RuntimeError(
                    "action lacks an exact acquisition site or graph-resolved "
                    f"handler: {action.action_id}"
                )
            sequence = [self._marker(action.action_id, "entry")]
            for site in entry_sites:
                locations.setdefault(site, []).append(sequence[0])
            # A source citation in the dispatcher can precede the acquisition
            # (for example the caller's call into recvcmd). Requiring that
            # citation between Entry and handler incorrectly rejects an
            # observed path. GDB supplies only a diagnostic same-thread
            # Entry-to-handler order, never request-specific causal proof.
            handler_marker = self._marker(action.action_id, "handler")
            sequence.append(handler_marker)
            if action.handler_function_id == action.entry_function_id:
                handler_sites = [
                    site for site in _probe_sites(
                        action.success_evidence, graph,
                        required_function_id=handler.function_id,
                    ) if site not in entry_sites
                ]
            else:
                handler_sites = [(handler.file, handler.start_line)]
            for site in handler_sites:
                locations.setdefault(site, []).append(handler_marker)
            self._chains[action.action_id] = sequence
        for (file_name, line), markers in sorted(locations.items()):
            location = _gdb_source_location(file_name, line)
            lines.extend([f"break {location}", "commands", "silent"])
            for marker in dict.fromkeys(markers):
                lines.append(
                    "python open("
                    f"{str(self.trace_path)!r}, 'a', encoding='utf-8'"
                    ").write("
                    f"{marker + ':T'!r} + str(gdb.selected_thread().global_num)"
                    " + '\\n')"
                )
            lines.extend(["continue", "end"])
        run = "run"
        if inferior_stdin is not None and inferior_stdout is not None:
            run += (
                f" < {shlex.quote(str(inferior_stdin))}"
                f" > {shlex.quote(str(inferior_stdout))}"
            )
        # A normal inferior exit leaves no selected frame. Unconditional
        # `bt` makes GDB itself exit with status 1 ("No stack"), which the
        # verifier could mistake for a product failure. Keep a backtrace
        # only when GDB actually stopped with a live thread.
        lines.extend([
            run,
            "python",
            "if gdb.selected_thread() is not None:",
            "    gdb.execute('bt 32')",
            "end",
        ])
        self.script_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def launch_argv(self, argv: list[str]) -> list[str]:
        return [
            self.gdb,
            "--quiet",
            "--nx",
            "--batch",
            "-x",
            str(self.script_path),
            "--args",
            *argv,
        ]

    def offset(self) -> int:
        try:
            return self.trace_path.stat().st_size
        except OSError:
            return 0

    def ordered_chain_reached(
        self,
        action: ExternalActionSchema,
        after_offset: int,
    ) -> tuple[bool, bool]:
        entry_reached, target_reached, _trace = self.ordered_chain_observation(
            action,
            after_offset,
        )
        return entry_reached, target_reached

    def ordered_chain_observation(
        self,
        action: ExternalActionSchema,
        after_offset: int,
    ) -> tuple[bool, bool, list[str]]:
        """Return whether Entry was hit and target followed it in this step.

        Reading from ``after_offset`` prevents a hit from an earlier request
        from satisfying a later request.  Merely finding both markers is not
        sufficient: the handler marker must occur at or after the Entry
        marker in the same trace slice.
        """

        try:
            with self.trace_path.open("rb") as stream:
                stream.seek(after_offset)
                output = stream.read()
        except OSError:
            return False, False, []
        sequence = self._chains.get(action.action_id, [])
        if not sequence:
            return False, False, []
        trace = [
            line.decode("utf-8", errors="replace")
            for line in output.splitlines()
            if line.startswith(b"__HARNESSCREATOR_TARGET__:")
        ]
        # Ordinary GDB breakpoints fire in every thread. Two ordered hits in
        # different threads are not even a same-thread path observation. A
        # cross-thread handoff can be real, but without a request identity it
        # remains unknown rather than being inferred from temporal order.
        entry_reached, target_reached = _ordered_thread_trace_sequence(
            output, sequence
        )
        return entry_reached, target_reached, trace

    def close(self) -> None:
        for descriptor in (self.stdin_fd, self.stdout_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        self.stdin_fd = None
        self.stdout_fd = None
        self._temporary.cleanup()

    @staticmethod
    def _marker(action_id: str, role: str) -> str:
        return f"__HARNESSCREATOR_TARGET__:{role}:{action_id}"


def _ordered_trace_hits(
    output: bytes,
    entry_marker: str,
    target_marker: str,
) -> tuple[bool, bool]:
    """Evaluate one request-local GDB trace slice.

    The first result reports acquisition reach.  The second reports the
    stronger ordered chain.  When Entry and handler are the same function a
    single hit establishes both facts.
    """

    if entry_marker == target_marker:
        return _ordered_trace_sequence(output, [entry_marker])
    return _ordered_trace_sequence(output, [entry_marker, target_marker])


def _ordered_trace_sequence(
    output: bytes,
    markers: list[str],
) -> tuple[bool, bool]:
    """Match role-specific markers as an ordered subsequence."""

    if not markers:
        return False, False
    lines = output.splitlines()
    encoded = [marker.encode("utf-8") for marker in markers]
    position = 0
    entry_reached = False
    for line in lines:
        if line != encoded[position]:
            continue
        if position == 0:
            entry_reached = True
        position += 1
        if position == len(encoded):
            return entry_reached, True
    return entry_reached, False


def _ordered_thread_trace_sequence(
    output: bytes,
    markers: list[str],
) -> tuple[bool, bool]:
    """Match a GDB observation within one thread, never across threads.

    This is still only a navigation observation: a thread can process several
    requests or unrelated work between the two hits. It is not request proof.
    """

    if not markers:
        return False, False
    positions: dict[int, int] = {}
    entry_reached = False
    for raw_line in output.splitlines():
        line = raw_line.decode("ascii", errors="ignore")
        marker, separator, raw_thread = line.rpartition(":T")
        if not separator or not raw_thread.isdecimal():
            continue
        thread = int(raw_thread)
        position = positions.get(thread, 0)
        if marker != markers[position]:
            continue
        if position == 0:
            entry_reached = True
        position += 1
        if position == len(markers):
            return entry_reached, True
        positions[thread] = position
    return entry_reached, False


def _probe_evidence_error(
    evidence: list,
    graph: GraphStore | None,
    *,
    required_function_id: str,
    label: str,
) -> str:
    if graph is None:
        return f"{label} probe has no analysis graph"
    if not _probe_sites(
        evidence,
        graph,
        required_function_id=required_function_id,
    ):
        return (
            f"{label} probe has no valid source line in "
            f"{required_function_id!r}"
        )
    return ""


def _probe_sites(
    evidence: list,
    graph: GraphStore,
    *,
    required_function_id: str,
) -> list[tuple[str, int]]:
    function = graph.bundle.functions.get(required_function_id)
    if function is None:
        return []
    result: list[tuple[str, int]] = []
    for item in evidence:
        if item.function_id != required_function_id or item.line is None:
            continue
        if not function.start_line <= item.line <= function.end_line:
            continue
        if Path(item.file) != Path(function.file):
            continue
        site = (function.file, item.line)
        if site not in result:
            result.append(site)
    return result


def _gdb_source_location(file_name: str, line: int) -> str:
    if "\n" in file_name or "\r" in file_name or line < 1:
        raise RuntimeError("target breakpoint has an invalid source location")
    escaped = file_name.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}':{line}"


def _write_all_fd(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise BrokenPipeError("inferior stdin pipe accepted no bytes")
        view = view[written:]


def _process_descendants(parent_pid: int) -> list[int]:
    """Best-effort Linux descendant snapshot for debugger-wrapped targets."""

    result: list[int] = []
    pending = [parent_pid]
    seen = {parent_pid}
    while pending:
        current = pending.pop()
        children_file = Path(f"/proc/{current}/task/{current}/children")
        try:
            children = [
                int(value) for value in children_file.read_text().split()
                if value.isdigit()
            ]
        except OSError:
            continue
        for child in children:
            if child in seen:
                continue
            seen.add(child)
            result.append(child)
            pending.append(child)
    return result


def _signal_processes(process_ids: Iterable[int], value: signal.Signals) -> None:
    for process_id in reversed(list(process_ids)):
        try:
            os.kill(process_id, value)
        except (ProcessLookupError, PermissionError):
            pass


def _read_fd_until_oracle(
    descriptor: int,
    markers: list[bytes],
    limit: int,
    timeout: float,
    minimum_size: int,
) -> bytes:
    deadline = time.monotonic() + timeout
    output = bytearray()
    while len(output) < limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ResponseReadTimeout("inferior stdout response timed out", bytes(output))
        readable, _, _ = select.select([descriptor], [], [], remaining)
        if not readable:
            raise ResponseReadTimeout("inferior stdout response timed out", bytes(output))
        chunk = os.read(descriptor, min(4096, limit - len(output)))
        if not chunk:
            break
        output.extend(chunk)
        if not markers and minimum_size == 0:
            # This is an exploratory observation of one available chunk, not
            # a complete protocol response or a successful request.
            break
        if len(output) >= minimum_size and any(
            _response_marker_matches(bytes(output), marker) for marker in markers
        ):
            break
    return bytes(output)


def _materialize_runtime_request(
    step: ScenarioStep,
    runtime_bindings: dict[str, bytes],
) -> tuple[bytes, str]:
    template_hex = step.request_template_hex or step.request_hex
    try:
        request = bytearray.fromhex(template_hex)
    except ValueError:
        return b"", f"step {step.index} has an invalid request template"
    for use in step.request_binding_uses:
        value = runtime_bindings.get(use.binding)
        if value is None:
            return bytes(request), (
                f"step {step.index} is missing runtime binding {use.binding!r} "
                f"from producer step {use.producer_step_index}"
            )
        if len(value) != use.width:
            return bytes(request), (
                f"step {step.index} runtime binding {use.binding!r} has "
                f"{len(value)} bytes, expected {use.width}"
            )
        if use.offset < 0 or use.offset + use.width > len(request):
            return bytes(request), (
                f"step {step.index} runtime binding {use.binding!r} patch is "
                "outside the request template"
            )
        request[use.offset:use.offset + use.width] = value
    return bytes(request), ""


def _extract_response_bindings(
    step: ScenarioStep,
    response: bytes,
) -> tuple[dict[str, bytes], str]:
    result: dict[str, bytes] = {}
    for extractor in step.response_binding_extractors:
        end = extractor.offset + extractor.width
        if extractor.offset < 0 or extractor.width < 1 or end > len(response):
            return {}, (
                f"step {step.index} response was too short to extract binding "
                f"{extractor.binding!r} at {extractor.offset}+{extractor.width}"
            )
        result[extractor.binding] = response[extractor.offset:end]
    return result, ""


def _minimum_response_size(step: ScenarioStep) -> int:
    return max(
        (item.offset + item.width for item in step.response_binding_extractors),
        default=0,
    )


class ResponseReadTimeout(TimeoutError):
    """A response deadline expired after some bytes had already arrived."""

    def __init__(self, message: str, partial: bytes) -> None:
        super().__init__(message)
        self.partial = partial


async def _read_line_prelude(
    reader: asyncio.StreamReader,
    marker: bytes,
    *,
    limit: int,
    timeout: float,
) -> bytes:
    """Observe a source-proposed line before any request bytes are sent.

    The server may send several complete lines (for example FTP 120 then
    220). A matched prefix is only pre-request ordering evidence; it is not
    an Action response or request-to-handler proof.
    """
    if not marker or not limit:
        raise ValueError("line prelude requires a nonempty marker and byte limit")
    deadline = time.monotonic() + timeout
    output = bytearray()
    while len(output) < limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ResponseReadTimeout("pre-request line timed out", bytes(output))
        try:
            line = await asyncio.wait_for(reader.readuntil(b"\n"), timeout=remaining)
        except asyncio.TimeoutError as exc:
            raise ResponseReadTimeout("pre-request line timed out", bytes(output)) from exc
        output.extend(line)
        if len(output) > limit:
            raise ValueError("pre-request line exceeds response byte limit")
        if line.startswith(marker):
            return bytes(output)
    raise ValueError("pre-request line marker not observed within response byte limit")


async def _read_until_oracle(
    reader: asyncio.StreamReader,
    markers: list[bytes],
    *,
    limit: int,
    timeout: float,
    minimum_size: int = 0,
) -> bytes:
    deadline = time.monotonic() + timeout
    output = bytearray()
    while len(output) < limit:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ResponseReadTimeout("response read timed out", bytes(output))
        try:
            chunk = await asyncio.wait_for(
                reader.read(min(4096, limit - len(output))),
                timeout=remaining,
            )
        except asyncio.TimeoutError as exc:
            raise ResponseReadTimeout("response read timed out", bytes(output)) from exc
        if not chunk:
            break
        output.extend(chunk)
        if not markers and minimum_size == 0:
            # No framing oracle exists. One chunk is useful input-format
            # feedback, but it cannot establish response completeness.
            break
        if len(output) >= minimum_size and any(
            _response_marker_matches(bytes(output), marker) for marker in markers
        ):
            break
    return bytes(output)


async def _drain_stream(
    reader: asyncio.StreamReader,
    limit: int,
) -> bytes:
    """Drain a diagnostic pipe without allowing it to block the child.

    Only the tail is retained because sanitizers normally emit the decisive
    report immediately before termination.
    """

    output = bytearray()
    while True:
        chunk = await reader.read(8192)
        if not chunk:
            return bytes(output)
        output.extend(chunk)
        if len(output) > limit:
            del output[:-limit]


async def _bounded_drain_result(task: asyncio.Task[bytes]) -> bytes:
    try:
        return await asyncio.wait_for(task, timeout=1.0)
    except asyncio.TimeoutError:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        return b"[diagnostic stream remained open after verifier shutdown]"


_EXPERIMENTAL_INPUT_ORIGINS = frozenset({
    "source_literal_runtime_hypothesis",
    "model_input_hypothesis",
    "user_request_fixture",
    "configured_protocol_smoke_hypothesis",
    "transport_smoke_hypothesis",
})


def _is_experimental_input_origin(origin: str) -> bool:
    return origin in _EXPERIMENTAL_INPUT_ORIGINS


def _action_transport(action: ExternalActionSchema) -> str:
    """Map evidence-backed Entry channel to a supported execution adapter.

    Ambiguous FDs, FILE* or callbacks must remain unknown instead of being
    silently classified as stdin/TCP. TLS and unsupported transports have no
    raw executor and will remain UNPROVEN.
    """
    transport = classify_external_transport(action.channel_kind, action.source_api)
    return "" if transport == "unknown" else transport


def _assert_endpoint_available(host: str, port: int, channel: str) -> None:
    kind = socket.SOCK_STREAM if channel == "tcp" else socket.SOCK_DGRAM
    probe = socket.socket(socket.AF_INET, kind)
    try:
        if channel == "tcp":
            # A completed earlier trial may leave this address in TIME_WAIT.
            # Match the usual listener bind check without treating that stale
            # connection as a live server. An active TCP listener still
            # prevents this bind; the original program performs its own bind.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
    except OSError as exc:
        raise OSError(
            f"configured {channel} endpoint {host}:{port} was already occupied "
            "before the original program started"
        ) from exc
    finally:
        probe.close()


def _udp_exchange_with_startup_retry(
    udp_socket: socket.socket,
    request: bytes,
    host: str,
    port: int,
    limit: int,
    timeout: float,
    write_observation: list[bool] | None = None,
) -> bytes:
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        udp_socket.settimeout(min(0.25, max(0.01, deadline - time.monotonic())))
        sent = udp_socket.sendto(request, (host, port))
        if sent == len(request) and write_observation is not None:
            write_observation.append(True)
        try:
            response, _ = udp_socket.recvfrom(limit)
            return response
        except (TimeoutError, OSError) as exc:
            last_error = exc
    raise TimeoutError(f"UDP response did not arrive before startup/step deadline: {last_error}")
    ObservedActionBinding,
