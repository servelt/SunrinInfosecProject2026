"""Memcached-only original-process protocol checks.

These confirm external behavior, never internal handler attribution.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import socket
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from ..agents.input_surfaces import InputSurfaceCase
from ..models import EntryRecord, ProjectSpec, stable_id, unique_strings
from .boundary import _endpoint_is_active, _is_loopback, _stop_process_group


@dataclass(slots=True)
class MemcachedCheck:
    name: str
    status: str
    requests_hex: list[str]
    responses_hex: list[str]
    same_server_pid: int | None
    handler_attributed: bool = False
    reason: str = ""
    trace_hits_by_request: list[list[str]] | None = None


_PROTOCOL_CHECKS = {
    "tcp": ("tcp_version", "tcp_set_get_same_connection"),
    "udp": ("udp_version",),
}


def runtime_hints_for_entry(
    function_name: str, transport: str, checks: list[dict],
    ids_by_name: dict[str, list[str]],
) -> tuple[bool, list[str]]:
    """Scope temporal trace hints to the matching Memcached protocol trial.

    Hits in a request window help choose source to inspect; they do not prove
    that the request bytes caused a particular handler to run.
    """
    allowed = set(_PROTOCOL_CHECKS.get(transport, ()))
    if not allowed or (transport == "tcp" and function_name != "tcp_read") or (
        transport == "udp" and function_name != "try_read_udp"
    ):
        return False, []
    matched = [check for check in checks if check.get("name") in allowed]
    reached = any(
        function_name in hits
        for check in matched for hits in (check.get("trace_hits_by_request") or [])
    )
    opposite_acquisition = "try_read_udp" if transport == "tcp" else "tcp_read"
    hints = unique_strings([
        fid for check in matched if check.get("status") == "OBSERVED_EXPECTED"
        for hits in (check.get("trace_hits_by_request") or [])
        for hit in hits if hit not in {function_name, opposite_acquisition}
        for fid in ids_by_name.get(hit, [])
    ])
    return reached, hints


def regression_cases_for_entry(
    entry: EntryRecord, function_name: str, checks: list[dict],
) -> list[InputSurfaceCase]:
    """Reuse only observed fixed protocol vectors for the matching Entry.

    These vectors are Memcached test fixtures. They are not a generic C
    protocol inference and do not establish byte-to-handler causality.
    """
    check_name = {
        "tcp_read": _PROTOCOL_CHECKS["tcp"],
        "try_read_udp": _PROTOCOL_CHECKS["udp"],
    }.get(function_name, ())
    cases = []
    for check in checks:
        name = check.get("name", "")
        if name not in check_name or check.get("status") != "OBSERVED_EXPECTED":
            continue
        requests = check.get("requests_hex", [])
        if not requests:
            continue
        data_hex = "".join(requests)
        cases.append(InputSurfaceCase(
            case_id=stable_id("memcached-regression-vector", entry.entry_id, name),
            entry_id=entry.entry_id,
            entry_function_id=entry.entry_function_id,
            source_api=entry.source_api, channel_kind=entry.channel_kind,
            data_hex=data_hex, origin="memcached_fixed_regression",
            rationale=(
                f"{name}: fixed bytes observed against the original daemon; "
                "a temporal GDB hit does not establish per-byte handler attribution"
            ),
            evidence=list(entry.evidence),
            inspected_function_ids=list(entry.inspected_function_ids),
        ))
    return cases


async def run_memcached_regression(
    project: ProjectSpec, *, gdb_trace: bool = False,
) -> list[MemcachedCheck]:
    """Send TCP, UDP, and set→get to one trusted local server instance."""
    host, port = project.scenario_host, project.scenario_port
    if not project.scenario_command or port is None or not _is_loopback(host):
        return [MemcachedCheck("preflight", "BLOCKED_CONFIGURATION", [], [], None,
                               reason="trusted loopback memcached command and port required")]
    if await asyncio.to_thread(_endpoint_is_active, host, port, "tcp"):
        return [MemcachedCheck("preflight", "BLOCKED_CONFIGURATION", [], [], None,
                               reason="TCP port already occupied before launching trusted server")]
    command = [token.replace("{source_root}", str(project.source_root))
               for token in project.scenario_command]
    temporary: tempfile.TemporaryDirectory[str] | None = None
    trace_path: Path | None = None
    if gdb_trace:
        debugger = shutil.which("gdb")
        if not debugger:
            return [MemcachedCheck("preflight", "BLOCKED_UNSUPPORTED_BACKEND", [], [], None,
                                   reason="GDB source path tracing unavailable")]
        temporary = tempfile.TemporaryDirectory(prefix="hc-memcached-path-")
        folder = Path(temporary.name)
        trace_path = folder / "hits.log"
        trace_path.touch()
        script = folder / "trace.gdb"
        lines = [
            "set pagination off", "set confirm off", "set breakpoint pending on",
            "set print thread-events off",
        ]
        for symbol in ("tcp_read", "try_read_udp", "process_command_ascii",
                       "process_update_command", "process_get_command",
                       "process_get_cmd"):
            lines.extend([
                f"break {symbol}", "commands", "silent",
                f"shell printf '%s\\n' {shlex.quote('HC_PATH:' + symbol)} >> {shlex.quote(str(trace_path))}",
                "continue", "end",
            ])
        lines.append("run")
        script.write_text("\n".join(lines) + "\n", encoding="utf-8")
        command = [debugger, "--quiet", "--nx", "--batch", "-x", str(script), "--args", *command]

    def trace_offset() -> int:
        return trace_path.stat().st_size if trace_path else 0

    def trace_since(offset: int) -> list[str]:
        if not trace_path:
            return []
        with trace_path.open("rb") as stream:
            stream.seek(offset)
            return [line.decode("ascii", "replace").removeprefix("HC_PATH:")
                    for line in stream.read().splitlines()
                    if line.startswith(b"HC_PATH:")]

    process = await asyncio.create_subprocess_exec(
        *command, cwd=str(project.source_root),
        env={**os.environ, **project.scenario_environment},
        stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, start_new_session=True,
    )
    results: list[MemcachedCheck] = []
    try:
        deadline = time.monotonic() + project.scenario_startup_timeout + (10 if gdb_trace else 0)
        while time.monotonic() < deadline:
            if process.returncode is not None:
                break
            if await asyncio.to_thread(_endpoint_is_active, host, port, "tcp"):
                break
            await asyncio.sleep(0.05)
        else:
            return [MemcachedCheck("preflight", "BLOCKED_RUNTIME", [], [], process.pid,
                                   reason="server did not open configured TCP port")]
        if process.returncode is not None:
            return [MemcachedCheck("preflight", "BLOCKED_RUNTIME", [], [], process.pid,
                                   reason=f"server exited with {process.returncode}")]

        async def tcp_one(name: str, requests: list[bytes], expected: list[bytes]) -> None:
            responses: list[bytes] = []
            traces: list[list[str]] = []
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), project.scenario_step_timeout,
                )
                try:
                    for request in requests:
                        offset = trace_offset()
                        writer.write(request)
                        await writer.drain()
                        # The fixed checks below have one-line or two-line
                        # responses. No generic protocol conclusion follows.
                        response = await asyncio.wait_for(
                            reader.readuntil(b"\r\n"), project.scenario_step_timeout,
                        )
                        if request.startswith(b"get ") and response.startswith(b"VALUE "):
                            response += await asyncio.wait_for(
                                reader.readuntil(b"END\r\n"), project.scenario_step_timeout,
                            )
                        responses.append(response)
                        traces.append(trace_since(offset))
                finally:
                    writer.close()
                    await writer.wait_closed()
                status = "OBSERVED_EXPECTED" if all(
                    marker in response for marker, response in zip(expected, responses)
                ) and len(responses) == len(requests) else "MISMATCH"
                reason = "" if status == "OBSERVED_EXPECTED" else "unexpected response bytes"
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError,
                    asyncio.LimitOverrunError) as exc:
                status, reason = "BLOCKED_RUNTIME", f"{type(exc).__name__}: {exc}"
            results.append(MemcachedCheck(
                name, status, [request.hex() for request in requests],
                [response.hex() for response in responses], process.pid,
                reason=reason, trace_hits_by_request=traces if gdb_trace else None,
            ))

        await tcp_one("tcp_version", [b"version\r\n"], [b"VERSION "])
        await tcp_one("tcp_set_get_same_connection", [
            b"set hc_boundary_key 0 0 3\r\nabc\r\n",
            b"get hc_boundary_key\r\n",
        ], [b"STORED\r\n", b"VALUE hc_boundary_key 0 3\r\nabc\r\nEND\r\n"])
        if "-U" in command and command[command.index("-U") + 1] == "0":
            results.append(MemcachedCheck("udp_version", "DEFERRED_CONFIGURATION", [], [],
                                          process.pid, reason="-U 0 disables UDP"))
        else:
            packet = b"\x31\x42\x00\x00\x00\x01\x00\x00version\r\n"
            response = b""
            offset = trace_offset()
            try:
                def udp() -> bytes:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.settimeout(project.scenario_step_timeout)
                        sock.sendto(packet, (host, port))
                        return sock.recvfrom(project.scenario_response_limit)[0]
                response = await asyncio.to_thread(udp)
                valid = response[:2] == packet[:2] and response[8:].startswith(b"VERSION ")
                status, reason = ("OBSERVED_EXPECTED", "") if valid else (
                    "MISMATCH", "unexpected UDP request-id or payload")
            except (OSError, TimeoutError) as exc:
                status, reason = "BLOCKED_RUNTIME", f"{type(exc).__name__}: {exc}"
            results.append(MemcachedCheck("udp_version", status, [packet.hex()],
                                          [response.hex()] if response else [],
                                          process.pid, reason=reason,
                                          trace_hits_by_request=[trace_since(offset)] if gdb_trace else None))
    finally:
        await _stop_process_group(process)
        try:
            await asyncio.wait_for(process.communicate(), timeout=1)
        except asyncio.TimeoutError:
            pass
        if temporary is not None:
            temporary.cleanup()
    return results
