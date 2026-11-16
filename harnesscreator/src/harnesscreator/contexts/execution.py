from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RunObservation:
    responses: list[bytes] = field(default_factory=list)
    exit_status: str = ""      # exited:<code> | signalled:<n> | killed_after_timeout | not_started
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error


@dataclass
class ProgramSpec:
    """How to start the original program and how one seed reaches it.

    ``command`` is an argv template.  ``{input_file}`` is replaced by a file
    holding the seed for the ``file`` delivery.
    """

    command: list[str]
    cwd: Path
    delivery: str                      # stream | datagram | stdin | file
    host: str = "127.0.0.1"
    port: int = 0
    environment: dict[str, str] = field(default_factory=dict)
    startup_timeout: float = 10.0
    datagram_startup_delay: float = 0.5
    step_timeout: float = 1.0
    response_limit: int = 65536
    run_timeout: float = 30.0
    stop_signal: int = signal.SIGTERM
    stop_timeout: float = 5.0


class ProgramRunner:
    """Runs the original program once per seed and delivers the seed to it."""

    def __init__(self, spec: ProgramSpec):
        if spec.delivery not in ("stream", "datagram", "peer_stream", "stdin", "file"):
            raise ValueError(f"unsupported delivery for original execution: {spec.delivery!r}")
        if spec.delivery in ("stream", "datagram") and not spec.port:
            raise ValueError("stream and datagram deliveries need --port")
        self.spec = spec

    async def run(self, messages: list[bytes], *, paced: bool = True) -> RunObservation:
        """Deliver one seed.

        ``paced`` (stream only): each message is written and the reply is read
        before the next one, like an interactive client.  Unpaced delivery
        writes the whole seed at once and then closes the sending side, which is
        how a fuzz harness delivers an input.
        """

        spec = self.spec
        self._paced = paced
        observation = RunObservation()
        input_file = None
        argv = list(spec.command)
        if spec.delivery == "file":
            handle = tempfile.NamedTemporaryFile(prefix="hc-seed-", delete=False)
            handle.write(b"".join(messages))
            handle.close()
            input_file = handle.name
            if not any("{input_file}" in part for part in argv):
                observation.error = "file delivery needs {input_file} in the command"
                observation.exit_status = "not_started"
                os.unlink(input_file)
                return observation
            argv = [part.replace("{input_file}", input_file) for part in argv]
        environment = dict(os.environ)
        environment.update(spec.environment)
        try:
            process = await asyncio.create_subprocess_exec(
                *argv, cwd=spec.cwd, env=environment, start_new_session=True,
                stdin=asyncio.subprocess.PIPE if spec.delivery == "stdin" else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE if spec.delivery in ("stdin", "file") else asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL)
        except (OSError, ValueError) as exc:
            observation.error = f"could not start the program: {exc}"
            observation.exit_status = "not_started"
            if input_file:
                os.unlink(input_file)
            return observation
        try:
            if spec.delivery == "stream":
                await self._stream(process, messages, observation)
            elif spec.delivery == "peer_stream":
                await self._peer_stream(process, messages, observation)
            elif spec.delivery == "datagram":
                await self._datagram(process, messages, observation)
            else:
                await self._one_shot(process, messages, observation)
        except Exception as exc:  # delivery problems are data for the caller, not crashes of the tool
            observation.error = f"{type(exc).__name__}: {exc}"
        finally:
            observation.exit_status = await self._stop(process)
            if input_file:
                with contextlib.suppress(OSError):
                    os.unlink(input_file)
        return observation

    async def _read_available(self, reader: asyncio.StreamReader) -> bytes:
        data = b""
        while len(data) < self.spec.response_limit:
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=self.spec.step_timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            data += chunk
        return data

    async def _stream(self, process: asyncio.subprocess.Process, messages: list[bytes],
                      observation: RunObservation) -> None:
        spec = self.spec
        deadline = asyncio.get_running_loop().time() + spec.startup_timeout
        while True:
            if process.returncode is not None:
                raise RuntimeError(f"program exited during startup with code {process.returncode}")
            try:
                reader, writer = await asyncio.open_connection(spec.host, spec.port)
                break
            except OSError:
                if asyncio.get_running_loop().time() >= deadline:
                    raise RuntimeError(f"no listener on {spec.host}:{spec.port} within {spec.startup_timeout}s")
                await asyncio.sleep(0.05)
        try:
            if getattr(self, "_paced", True):
                # Bytes the server sends before any request (greeting) are kept apart.
                observation.responses.append(await self._read_available(reader))
                for message in messages:
                    writer.write(message)
                    await writer.drain()
                    observation.responses.append(await self._read_available(reader))
            else:
                writer.write(b"".join(messages))
                await writer.drain()
                if writer.can_write_eof():
                    writer.write_eof()
                observation.responses.extend([b"", await self._read_available(reader)])
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _peer_stream(self, process: asyncio.subprocess.Process, messages: list[bytes],
                           observation: RunObservation) -> None:
        """Play the server the program connects to.

        Message 1 (the trigger) is sent to the program's own endpoint with
        {PEER_HOST}/{PEER_PORT} naming a listener opened here; the program's
        connection to that listener receives the remaining messages.  Recorded
        responses: what the program sent to the peer before each peer message,
        then what the program sent back on the trigger connection.
        """

        spec = self.spec
        accepted: asyncio.Queue = asyncio.Queue()

        async def on_connect(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            await accepted.put((reader, writer))

        server = await asyncio.start_server(on_connect, spec.host, 0)
        peer_port = server.sockets[0].getsockname()[1]
        client_writer = client_reader = None
        try:
            trigger = messages[0] if messages else b""
            trigger = trigger.replace(b"{PEER_HOST}", spec.host.encode()).replace(b"{PEER_PORT}", str(peer_port).encode())
            if spec.port:
                deadline = asyncio.get_running_loop().time() + spec.startup_timeout
                while True:
                    if process.returncode is not None:
                        raise RuntimeError(f"program exited during startup with code {process.returncode}")
                    try:
                        client_reader, client_writer = await asyncio.open_connection(spec.host, spec.port)
                        break
                    except OSError:
                        if asyncio.get_running_loop().time() >= deadline:
                            raise RuntimeError(f"no listener on {spec.host}:{spec.port} within {spec.startup_timeout}s")
                        await asyncio.sleep(0.05)
                if trigger:
                    client_writer.write(trigger)
                    await client_writer.drain()
            if len(messages) < 2:
                # No peer bytes (the run with no input): behave like a stream client that sends nothing.
                observation.responses.append(await self._read_available(client_reader) if client_reader else b"")
                return
            try:
                reader, writer = await asyncio.wait_for(accepted.get(), timeout=spec.startup_timeout)
            except asyncio.TimeoutError:
                raise RuntimeError("the program did not connect to the peer listener "
                                   f"{spec.host}:{peer_port} after the trigger") from None
            try:
                if getattr(self, "_paced", True):
                    for message in messages[1:]:
                        observation.responses.append(await self._read_available(reader))
                        writer.write(message)
                        await writer.drain()
                else:
                    observation.responses.append(b"")
                    writer.write(b"".join(messages[1:]))
                    await writer.drain()
                if writer.can_write_eof():
                    writer.write_eof()
                observation.responses.append(await self._read_available(reader))
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            if client_reader is not None:
                observation.responses.append(await self._read_available(client_reader))
        finally:
            if client_writer is not None:
                client_writer.close()
                with contextlib.suppress(Exception):
                    await client_writer.wait_closed()
            server.close()
            with contextlib.suppress(Exception):
                await server.wait_closed()

    async def _datagram(self, process: asyncio.subprocess.Process, messages: list[bytes],
                        observation: RunObservation) -> None:
        spec = self.spec
        await asyncio.sleep(spec.datagram_startup_delay)
        if process.returncode is not None:
            raise RuntimeError(f"program exited during startup with code {process.returncode}")
        loop = asyncio.get_running_loop()
        family = socket.AF_INET6 if ":" in spec.host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect((spec.host, spec.port))
            sock.setblocking(False)
            observation.responses.append(b"")
            for message in messages:
                await loop.sock_sendall(sock, message)
                try:
                    observation.responses.append(
                        await asyncio.wait_for(loop.sock_recv(sock, spec.response_limit), timeout=spec.step_timeout))
                except (asyncio.TimeoutError, ConnectionError):
                    observation.responses.append(b"")

    async def _one_shot(self, process: asyncio.subprocess.Process, messages: list[bytes],
                        observation: RunObservation) -> None:
        payload = b"".join(messages) if self.spec.delivery == "stdin" else None
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(payload), timeout=self.spec.run_timeout)
        except asyncio.TimeoutError:
            stdout = b""
            observation.error = f"program did not finish within {self.spec.run_timeout}s"
        observation.responses.extend([b"", (stdout or b"")[: self.spec.response_limit]])

    async def _stop(self, process: asyncio.subprocess.Process) -> str:
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, self.spec.stop_signal)
            try:
                await asyncio.wait_for(process.wait(), timeout=self.spec.stop_timeout)
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                await process.wait()
                return "killed_after_timeout"
        code = process.returncode
        return f"signalled:{-code}" if code is not None and code < 0 else f"exited:{code}"
