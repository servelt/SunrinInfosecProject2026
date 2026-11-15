"""The original PoV tool must not execute model code in the host process."""

import hashlib
import os
import shutil
import subprocess
from unittest.mock import patch

import pytest

from fuzzingbrain.fuzzer.seed_sandbox import (
    DOCKER_CLI_SHA_ENV, IMAGE_ID_ENV, SeedSandboxCleanupError,
)
from fuzzingbrain.tools.pov import _execute_generator_code, trace_pov_impl


@pytest.fixture
def pinned_local_python(monkeypatch):
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("local Docker CLI unavailable")
    result = subprocess.run(
        [docker, "image", "inspect", "--format", "{{.Id}}", "python:3.14-slim"],
        capture_output=True, text=True, timeout=5, check=False)
    if result.returncode:
        pytest.skip("local Python sandbox image unavailable")
    monkeypatch.setenv(IMAGE_ID_ENV, result.stdout.strip())
    with open(os.path.realpath(docker), "rb") as stream:
        monkeypatch.setenv(
            DOCKER_CLI_SHA_ENV, hashlib.file_digest(stream, "sha256").hexdigest())


def test_pov_generator_runs_in_local_sandbox(pinned_local_python, tmp_path):
    sentinel = tmp_path / "secret"
    sentinel.write_bytes(b"private")
    code = (
        "def generate(variant):\n"
        f"    try: open({str(sentinel)!r}, 'rb').read()\n"
        "    except OSError: return b'blocked-' + bytes([variant])\n"
        "    return b'leaked'\n"
    )
    blobs, error = _execute_generator_code(code, 2)
    assert error is None
    assert blobs == [b"blocked-\x01", b"blocked-\x02"]
    assert sentinel.read_bytes() == b"private"


def test_pov_generator_cleanup_uncertainty_is_not_plain_invalid_input():
    with patch("fuzzingbrain.fuzzer.seed_sandbox.execute_seed_generator",
               side_effect=SeedSandboxCleanupError("cleanup unconfirmed")):
        with pytest.raises(SeedSandboxCleanupError, match="cleanup unconfirmed"):
            _execute_generator_code("def generate(n): return b'x'", 1)


def test_pov_tool_marks_uncertain_sandbox_cleanup_as_fatal():
    with patch("fuzzingbrain.tools.pov._ensure_context", return_value=None), \
         patch("fuzzingbrain.tools.pov._execute_generator_code",
               side_effect=SeedSandboxCleanupError("cleanup unconfirmed")):
        result = trace_pov_impl("def generate(n): return b'x'")
    assert result["success"] is False
    assert result["fatal_sandbox_cleanup"] is True
