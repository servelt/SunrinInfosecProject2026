"""Original-program input trials without Action/Scenario representations.

These trials establish only what actually happened at a *trusted local*
process boundary. A response, clean exit, or chronological debugger hit is
never by itself proof that a particular handler consumed the same bytes.
"""

from __future__ import annotations

import asyncio
import errno
import ipaddress
import os
import signal
import socket
import tempfile
import time
from dataclasses import dataclass
from dataclasses import replace
from pathlib import Path

from ..agents.input_surfaces import InputSurfaceCase
from ..agents.execution_contract import ExecutionContract
from ..input_transport import source_transport
from ..models import EntryRecord, ProjectSpec, stable_id


@dataclass(slots=True)
class BoundaryTrial:
    trial_id: str
    case_id: str
    entry_id: str
    transport: str
    input_hex: str
    input_origin: str
    status: str
    response_hex: str = ""
    stderr: str = ""
    process_returncode: int | None = None
    handler_attributed: bool = False
    failure_reason: str = ""
    elapsed_seconds: float = 0.0
    entry_reached: bool = False
    target_reached: bool = False
    trace_mechanism: str = ""
    trace_events: list[str] | None = None


@dataclass(slots=True)
class BoundaryEnginePlan:
    contract_id: str
    required_execution: str
    selected_backend: str
    backend_implemented: bool
    rationale: str


def select_backend(contract: ExecutionContract) -> BoundaryEnginePlan:
    """Name the required engine before generating any harness source.

    Only in-process libFuzzer is implemented in this project. An unfulfilled
    process/network backend is a visible gap, never a silently coerced mode.
    """
    transport = contract.transport
    if contract.isolation == "in_process_reset" and contract.evidence_complete:
        return BoundaryEnginePlan(
            contract.contract_id, "in_process_repeated_calls",
            "libfuzzer", True,
            "source-cited repeatability candidate; real repeated sanitizer replay still required",
        )
    if transport in {"tcp", "udp", "stdin", "argv", "env", "file"}:
        stateful = transport in {"tcp", "udp"}
        return BoundaryEnginePlan(
            contract.contract_id,
            "stateful_network_sequence" if stateful else "fresh_process_per_input",
            "external_stateful_fuzzer" if stateful else "external_process_fuzzer",
            False,
            "in-process repeatability was not established; conservative external "
            "execution is required, but its fuzzing backend is not implemented",
        )
    return BoundaryEnginePlan(
        contract.contract_id, "undetermined", "none", False,
        "source evidence did not establish isolation and per-input repeatability",
    )


class BoundaryTrialRunner:
    def __init__(self, project: ProjectSpec):
        self.project = project

    async def run_attributed(
        self, case: InputSurfaceCase, entry: EntryRecord,
        target_function_id: str, trace_path: Path,
    ) -> BoundaryTrial:
        """Require an exact request identity in product-emitted trace events."""
        trial = BoundaryTrial(
            trial_id=stable_id("boundary-attributed-trial", case.case_id, target_function_id),
            case_id=case.case_id, entry_id=entry.entry_id,
            transport=source_transport(entry), input_hex=case.data_hex,
            input_origin=case.origin, status="UNEXECUTED",
        )
        if self.project.scenario_attribution != "trace":
            trial.failure_reason = "request-correlated product instrumentation not configured"
            return trial
        trace_path.parent.mkdir(parents=True, exist_ok=True)
        trace_path.write_bytes(b"")
        trial_project = replace(
            self.project,
            scenario_environment={
                **self.project.scenario_environment,
                "HARNESSCREATOR_TRACE_JSONL": str(trace_path),
            },
        )
        trial = await BoundaryTrialRunner(trial_project).run(case, entry)
        from .request_trace import RequestTraceJournal
        observation = RequestTraceJournal(trace_path).observe(
            0, bytes.fromhex(case.data_hex), entry.entry_function_id,
            target_function_id,
            response=bytes.fromhex(trial.response_hex) if trial.response_hex else None,
        )
        trial.entry_reached = observation.entry_reached
        trial.target_reached = observation.target_reached
        trial.handler_attributed = observation.target_reached
        trial.trace_mechanism = "request-correlated-jsonl-v1"
        trial.trace_events = list(observation.trace)
        if not observation.target_reached:
            trial.failure_reason = observation.problem or "source target not reached"
        return trial

    async def run(self, case: InputSurfaceCase, entry: EntryRecord) -> BoundaryTrial:
        transport = source_transport(entry)
        trial = BoundaryTrial(
            trial_id=stable_id("boundary-trial", case.case_id, transport),
            case_id=case.case_id, entry_id=entry.entry_id,
            transport=transport, input_hex=case.data_hex,
            input_origin=case.origin, status="UNEXECUTED",
        )
        if not self.project.scenario_command:
            trial.failure_reason = "trusted original-program command not configured"
            return trial
        if transport == "unknown":
            trial.failure_reason = "external acquisition transport is not source-resolved"
            return trial
        selected = self.project.scenario_channel
        if selected not in {"auto", transport}:
            trial.failure_reason = f"source transport {transport} conflicts with configured {selected}"
            return trial
        try:
            data = bytes.fromhex(case.data_hex)
        except ValueError:
            trial.failure_reason = "invalid input hex"
            return trial
        if (self.project.max_input_trial_bytes
            and len(data) > self.project.max_input_trial_bytes):
            trial.status = "INCOMPATIBLE_INPUT"
            trial.failure_reason = (
                "input exceeds operator-selected trial limit of "
                f"{self.project.max_input_trial_bytes} bytes"
            )
            return trial
        start = time.monotonic()
        try:
            if transport in {"stdin", "argv", "env", "file"}:
                await self._run_local(trial, transport, data)
            else:
                await self._run_network(trial, transport, data)
        except (OSError, ValueError, asyncio.TimeoutError) as exc:
            trial.status = "EXECUTOR_ERROR"
            trial.failure_reason = f"{type(exc).__name__}: {exc}"
        finally:
            trial.elapsed_seconds = round(time.monotonic() - start, 6)
        return trial

    def _trusted_command(self) -> list[str]:
        return [
            token.replace("{source_root}", str(self.project.source_root))
            for token in self.project.scenario_command
        ]

    def _environment(self) -> dict[str, str]:
        result = os.environ.copy()
        result.update(self.project.scenario_environment)
        return result

    async def _run_local(self, trial: BoundaryTrial, transport: str, data: bytes) -> None:
        argv = self._trusted_command()
        env = self._environment()
        if transport in {"argv", "env"} and b"\x00" in data:
            trial.status = "INCOMPATIBLE_INPUT"
            trial.failure_reason = "argv and environment strings cannot contain NUL"
            return
        if transport == "argv":
            # The model cannot edit the command or launch a shell. Only its
            # designated raw argument is inserted at the trusted placeholder
            # or appended when argv delivery was explicitly selected.
            argument = data.decode("utf-8", "surrogateescape")
            if any("{input}" in token for token in argv):
                argv = [token.replace("{input}", argument) for token in argv]
            else:
                argv.append(argument)
        elif transport == "env":
            name = self.project.scenario_input_env
            if not name:
                trial.status = "UNEXECUTED"
                trial.failure_reason = "environment input needs trusted scenario_input_env"
                return
            env[name] = data.decode("utf-8", "surrogateescape")
        if transport == "file":
            if not any("{input}" in token for token in argv):
                trial.status = "UNEXECUTED"
                trial.failure_reason = "file execution requires an explicit {input} command placeholder"
                return
            with tempfile.TemporaryDirectory(prefix="hc-boundary-") as temporary:
                filename = Path(temporary) / "fuzz-input"
                filename.write_bytes(data)
                argv = [token.replace("{input}", str(filename)) for token in argv]
                await self._exec_once(trial, argv, env, b"")
        else:
            await self._exec_once(trial, argv, env, data if transport == "stdin" else b"")

    async def _exec_once(
        self, trial: BoundaryTrial, argv: list[str], env: dict[str, str], stdin_bytes: bytes,
    ) -> None:
        process = await asyncio.create_subprocess_exec(
            *argv, cwd=str(self.project.source_root), env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(stdin_bytes),
                timeout=self.project.scenario_step_timeout,
            )
            trial.response_hex = stdout[:self.project.scenario_response_limit].hex()
            trial.stderr = stderr[:8192].decode("utf-8", "replace")
            trial.process_returncode = process.returncode
            trial.status = "OBSERVED_EXIT"
        except asyncio.TimeoutError:
            trial.status = "TIMED_OUT"
            trial.failure_reason = "original process exceeded per-trial timeout"
        finally:
            await _stop_process_group(process)

    async def _run_network(self, trial: BoundaryTrial, transport: str, data: bytes) -> None:
        if self.project.scenario_port is None:
            trial.status = "UNEXECUTED"
            trial.failure_reason = f"{transport} requires trusted scenario_port"
            return
        host = self.project.scenario_host
        if not _is_loopback(host):
            trial.status = "UNEXECUTED"
            trial.failure_reason = "boundary trials launch only against local loopback endpoints"
            return
        port = self.project.scenario_port
        # Prevent accidentally sending an experiment to an unrelated daemon.
        if await asyncio.to_thread(_endpoint_is_active, host, port, transport):
            trial.status = "UNEXECUTED"
            trial.failure_reason = "the trusted port is occupied before starting the original process"
            return
        argv = self._trusted_command()
        process = await asyncio.create_subprocess_exec(
            *argv, cwd=str(self.project.source_root), env=self._environment(),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        try:
            response = await asyncio.to_thread(
                _socket_trial, host, port, transport, data,
                self.project.scenario_startup_timeout,
                self.project.scenario_step_timeout,
                self.project.scenario_response_limit,
            )
            trial.response_hex = response.hex()
            trial.status = "OBSERVED_RESPONSE" if response else "OBSERVED_NO_RESPONSE"
            trial.process_returncode = process.returncode
        except (OSError, TimeoutError) as exc:
            trial.status = "EXECUTOR_ERROR"
            trial.failure_reason = f"{type(exc).__name__}: {exc}"
        finally:
            await _stop_process_group(process)
            # The stdout/stderr pipes are not read concurrently. Once killed,
            # drain bounded diagnostics with a short timeout.
            try:
                out, err = await asyncio.wait_for(process.communicate(), timeout=1)
                trial.stderr = (out[:2048] + err[:6144]).decode("utf-8", "replace")
            except asyncio.TimeoutError:
                trial.stderr = "could not drain daemon output"


def _is_loopback(host: str) -> bool:
    if host.casefold() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _endpoint_is_active(host: str, port: int, transport: str) -> bool:
    if transport == "udp":
        # Probe local bind ownership without sending data to a possibly
        # unrelated service. A bind failure is conservatively occupied.
        try:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            with socket.socket(family, socket.SOCK_DGRAM) as probe:
                probe.bind((host, port))
            return False
        except OSError:
            return True
    try:
        with socket.create_connection((host, port), timeout=0.15):
            return True
    except OSError:
        return False


def _socket_trial(
    host: str, port: int, transport: str, data: bytes,
    startup_timeout: float, step_timeout: float, response_limit: int,
) -> bytes:
    deadline = time.monotonic() + startup_timeout
    if transport == "tcp":
        connection: socket.socket | None = None
        while time.monotonic() < deadline:
            try:
                connection = socket.create_connection((host, port), timeout=0.3)
                break
            except (ConnectionRefusedError, TimeoutError, OSError):
                time.sleep(0.04)
        if connection is None:
            raise TimeoutError("daemon did not open the trusted TCP port")
        with connection:
            connection.settimeout(step_timeout)
            connection.sendall(data)
            try:
                return connection.recv(response_limit)
            except socket.timeout:
                return b""
    # Linux reports ECONNREFUSED when no UDP receiver exists. A fresh socket
    # carries only this attempt, so that error can identify startup loss.
    # A plain timeout cannot: the daemon may have consumed the datagram and
    # chosen not to reply. Never duplicate a request after that ambiguity.
    while time.monotonic() < deadline:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as connection:
            connection.settimeout(step_timeout)
            try:
                connection.connect((host, port))
                connection.send(data)
                return connection.recv(response_limit)
            except OSError as exc:
                if exc.errno == errno.ECONNREFUSED:
                    time.sleep(min(0.04, max(0.0, deadline - time.monotonic())))
                    continue
                if isinstance(exc, socket.timeout):
                    return b""
                raise
    raise TimeoutError("daemon did not open the trusted UDP port")


async def _stop_process_group(process: asyncio.subprocess.Process) -> None:
    if process.pid is None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        pass
