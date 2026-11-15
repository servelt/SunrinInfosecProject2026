"""Run model-authored seed generators outside the FBv2 host process.

This is deliberately opt-in.  There is no fallback to host ``exec`` when the
local pinned Docker image or its cleanup cannot be certified.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import selectors
import shutil
import subprocess
import time
from typing import Any


MAX_GENERATOR_BYTES = 32 * 1024
MAX_SEEDS = 16
MAX_SEED_BYTES = 64 * 1024
MAX_TOTAL_SEED_BYTES = 256 * 1024
MAX_CAPTURE_BYTES = 512 * 1024
DOCKER_TIMEOUT_SECONDS = 15.0
DOCKER_CLEANUP_SECONDS = 6.0
IMAGE_ID_ENV = "FBV2_SEED_DOCKER_IMAGE_ID"
DOCKER_CLI_SHA_ENV = "FBV2_SEED_DOCKER_CLI_SHA256"
_IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class SeedSandboxError(RuntimeError):
    """No seed bytes are accepted unless the sandbox and cleanup succeed."""


class SeedSandboxCleanupError(SeedSandboxError):
    """A model-code container may still exist; stop the whole campaign."""


class SeedSandboxOutputLimitError(SeedSandboxError):
    """The bounded capture limit was reached after certified cleanup."""


_WORKER = r'''
import base64
import inspect
import json
import sys

def main():
    payload = json.loads(sys.stdin.buffer.read(40000))
    code = payload["code"]
    count = payload["num_seeds"]
    namespace = {"__builtins__": __builtins__, "__name__": "__seed_generator__"}
    exec(compile(code, "<seed_generator>", "exec"), namespace)
    generator = namespace.get("generate")
    if not callable(generator):
        raise ValueError("generator must define generate")
    accepts_param = len(inspect.signature(generator).parameters) > 0
    seeds = []
    total = 0
    for number in range(1, count + 1):
        seed = generator(number) if accepts_param else generator()
        if type(seed) is not bytes:
            raise TypeError("generate must return bytes")
        if len(seed) > 65536:
            raise ValueError("seed exceeds byte limit (max 65536 bytes)")
        total += len(seed)
        if total > 262144:
            raise ValueError("total seed bytes exceed limit")
        seeds.append(base64.b64encode(seed).decode("ascii"))
    sys.stdout.write(json.dumps({"seeds": seeds}, separators=(",", ":")))

try:
    main()
except BaseException as exc:
    sys.stderr.write(type(exc).__name__ + ": " + str(exc)[:500] + "\n")
    sys.exit(2)
'''


def _command_output(command: list[str], *, timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                              check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SeedSandboxError("Docker inspection or cleanup could not finish") from exc


def _docker_binary_and_image() -> tuple[str, str]:
    docker = shutil.which("docker")
    image_id = os.environ.get(IMAGE_ID_ENV, "")
    if not _IMAGE_ID.fullmatch(image_id):
        raise SeedSandboxError(f"pinned local image ID required in {IMAGE_ID_ENV}")
    if docker is None:
        raise SeedSandboxError("Docker is unavailable; seed generator was not run")
    expected_cli_sha = os.environ.get(DOCKER_CLI_SHA_ENV, "")
    if not _SHA256.fullmatch(expected_cli_sha):
        raise SeedSandboxError(f"pinned Docker CLI SHA-256 required in {DOCKER_CLI_SHA_ENV}")
    try:
        with open(os.path.realpath(docker), "rb") as stream:
            actual_cli_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    except OSError as exc:
        raise SeedSandboxError("Docker CLI identity could not be checked") from exc
    if actual_cli_sha != expected_cli_sha:
        raise SeedSandboxError("Docker CLI identity changed")
    result = _command_output(
        [docker, "image", "inspect", "--format", "{{.Id}}", image_id], timeout=5.0
    )
    if result.returncode != 0 or result.stdout.strip() != image_id:
        raise SeedSandboxError("pinned local Python image is unavailable")
    return docker, image_id


def _container_absent(docker: str, name: str) -> bool:
    result = _command_output([docker, "container", "inspect", name],
                             timeout=DOCKER_CLEANUP_SECONDS)
    return result.returncode != 0 and "No such" in result.stderr


def _remove_container(docker: str, name: str) -> None:
    result = _command_output([docker, "rm", "--force", name],
                             timeout=DOCKER_CLEANUP_SECONDS)
    if result.returncode != 0 and not _container_absent(docker, name):
        raise SeedSandboxError("Docker container cleanup failed")
    if not _container_absent(docker, name):
        raise SeedSandboxError("Docker container remains after cleanup")


def _capture_bounded(command: list[str], payload: bytes) -> tuple[int, bytes, bytes]:
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
    except OSError as exc:
        raise SeedSandboxError("Docker launch failed") from exc
    assert process.stdin and process.stdout and process.stderr
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    deadline = time.monotonic() + DOCKER_TIMEOUT_SECONDS
    try:
        os.set_blocking(process.stdin.fileno(), False)
        pending = memoryview(payload)
        selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        for stream, target in ((process.stdout, stdout), (process.stderr, stderr)):
            selector.register(stream, selectors.EVENT_READ, target)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SeedSandboxError("seed generator timed out")
            for key, _ in selector.select(min(remaining, 0.1)):
                if key.data == "stdin":
                    try:
                        written = os.write(key.fileobj.fileno(), pending)
                    except BrokenPipeError:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    pending = pending[written:]
                    if not pending:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                key.data.extend(chunk)
                if len(stdout) + len(stderr) > MAX_CAPTURE_BYTES:
                    raise SeedSandboxOutputLimitError(
                        "seed generator output exceeded byte limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SeedSandboxError("seed generator timed out")
        return process.wait(timeout=remaining), bytes(stdout), bytes(stderr)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            raise SeedSandboxCleanupError("Docker CLI did not terminate")
        process.stdout.close()
        process.stderr.close()
        if not process.stdin.closed:
            process.stdin.close()


def execute_seed_generator(code: str, num_seeds: int) -> list[bytes]:
    """Return validated bytes, or fail closed after verifying container cleanup."""
    if type(code) is not str or not code.strip() or len(code.encode("utf-8")) > MAX_GENERATOR_BYTES:
        raise SeedSandboxError("invalid or oversized seed generator code")
    if type(num_seeds) is not int or not 1 <= num_seeds <= MAX_SEEDS:
        raise SeedSandboxError("invalid seed count")
    docker, image_id = _docker_binary_and_image()
    name = "fbv2-seed-" + secrets.token_hex(12)
    command = [
        docker, "run", "--pull", "never", "--rm", "--name", name,
        "--network", "none", "--read-only", "--user", "65534:65534",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "32", "--memory", "128m", "--memory-swap", "128m",
        "--cpus", "0.5", "--ulimit", "nofile=64:64",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
        "--workdir", "/tmp", "--entrypoint", "python", "--interactive",
        image_id, "-I", "-B", "-c", _WORKER,
    ]
    payload = json.dumps({"code": code, "num_seeds": num_seeds},
                         separators=(",", ":")).encode("utf-8")
    outcome: tuple[int, bytes, bytes] | None = None
    original_error: BaseException | None = None
    try:
        outcome = _capture_bounded(command, payload)
    except BaseException as exc:
        original_error = exc
    try:
        _remove_container(docker, name)
    except BaseException as cleanup_error:
        raise SeedSandboxCleanupError(
            "seed sandbox cleanup could not be certified"
        ) from cleanup_error
    if original_error is not None:
        if isinstance(original_error, (SeedSandboxCleanupError,
                                       SeedSandboxOutputLimitError)):
            raise original_error
        raise SeedSandboxError(str(original_error)) from original_error
    assert outcome is not None
    returncode, stdout, stderr = outcome
    if returncode != 0:
        message = stderr.decode("utf-8", errors="replace").strip()[:500]
        raise SeedSandboxError("seed generator failed: " + message)
    try:
        result: Any = json.loads(stdout)
        encoded = result["seeds"]
        if type(encoded) is not list or len(encoded) != num_seeds:
            raise ValueError("seed count mismatch")
        seeds = [base64.b64decode(item, validate=True) for item in encoded]
        if any(len(seed) > MAX_SEED_BYTES for seed in seeds) or sum(map(len, seeds)) > MAX_TOTAL_SEED_BYTES:
            raise ValueError("seed bytes exceeded limit")
        return seeds
    except (ValueError, KeyError, TypeError) as exc:
        raise SeedSandboxError("seed sandbox returned invalid or oversized bytes") from exc
