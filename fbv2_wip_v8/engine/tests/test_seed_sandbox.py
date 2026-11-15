"""Provider-free containment checks for model-authored SeedAgent code."""

from __future__ import annotations

import os
import hashlib
import shutil
import subprocess
from unittest.mock import patch

import pytest

from fuzzingbrain.fuzzer.seed_sandbox import (
    IMAGE_ID_ENV,
    DOCKER_CLI_SHA_ENV,
    SeedSandboxCleanupError,
    SeedSandboxError,
    execute_seed_generator,
)
from fuzzingbrain.fuzzer.seed_tools import (
    clear_seed_context,
    create_seed_impl,
    set_seed_context,
)


@pytest.fixture
def local_python_image(monkeypatch):
    docker = shutil.which("docker")
    if docker is None:
        pytest.skip("local Docker CLI unavailable")
    try:
        result = subprocess.run(
            [docker, "image", "inspect", "--format", "{{.Id}}", "python:3.14-slim"],
            capture_output=True, text=True, timeout=5.0, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pytest.skip("local Python sandbox image unavailable")
    if result.returncode != 0:
        pytest.skip("local Python sandbox image unavailable")
    image_id = result.stdout.strip()
    monkeypatch.setenv(IMAGE_ID_ENV, image_id)
    with open(os.path.realpath(docker), "rb") as stream:
        monkeypatch.setenv(
            DOCKER_CLI_SHA_ENV, hashlib.file_digest(stream, "sha256").hexdigest())
    return image_id


def test_no_pinned_image_fails_closed(monkeypatch):
    monkeypatch.delenv(IMAGE_ID_ENV, raising=False)
    with pytest.raises(SeedSandboxError, match="pinned local image ID"):
        execute_seed_generator("def generate(n): return b'x'", 1)


def test_wrong_docker_cli_pin_fails_before_execution(local_python_image,
                                                     monkeypatch):
    monkeypatch.setenv(DOCKER_CLI_SHA_ENV, "0" * 64)
    with pytest.raises(SeedSandboxError, match="Docker CLI identity changed"):
        execute_seed_generator("def generate(n): return b'x'", 1)


def test_seed_tool_produces_bytes_in_local_container(local_python_image,
                                                     tmp_path):
    worker_id = "sandbox-seed-context"
    set_seed_context(task_id="sandbox-task", worker_id=worker_id,
                     direction_id="sandbox-direction", fuzzer_manager=None,
                     workspace_path=tmp_path)
    try:
        result = create_seed_impl(
            "def generate(seed_num): return b'seed' + str(seed_num).encode()",
            num_seeds=2, worker_id=worker_id)
        assert result["success"] is True
        assert result["seeds_generated"] == 2
        assert result["seed_sizes"] == [5, 5]
    finally:
        clear_seed_context(worker_id)


def test_host_sentinel_cannot_be_read_or_written(local_python_image, tmp_path):
    sentinel = tmp_path / "host-secret"
    sentinel.write_bytes(b"host-private-data")
    code = f'''
def generate(seed_num):
    try:
        with open({str(sentinel)!r}, 'rb') as handle:
            value = handle.read()
        with open({str(sentinel)!r}, 'wb') as handle:
            handle.write(b'breach')
        return value
    except OSError:
        return b'BLOCKED'
'''
    assert execute_seed_generator(code, 1) == [b"BLOCKED"]
    assert sentinel.read_bytes() == b"host-private-data"


def test_infinite_loop_times_out_and_container_is_removed(local_python_image,
                                                          monkeypatch):
    monkeypatch.setattr("fuzzingbrain.fuzzer.seed_sandbox.DOCKER_TIMEOUT_SECONDS", 3.0)
    with pytest.raises(SeedSandboxError, match="timed out"):
        execute_seed_generator("def generate(seed_num):\n    while True: pass", 1)


def test_oversized_seed_is_rejected(local_python_image):
    with pytest.raises(SeedSandboxError, match="seed exceeds byte limit"):
        execute_seed_generator("def generate(seed_num): return b'A' * 65537", 1)


def test_excessive_generator_output_is_rejected(local_python_image):
    code = "print('A' * 600000)\ndef generate(seed_num): return b'x'"
    with pytest.raises(SeedSandboxError, match="output exceeded byte limit"):
        execute_seed_generator(code, 1)


def test_cleanup_failure_never_returns_seed(monkeypatch):
    monkeypatch.setenv(IMAGE_ID_ENV, "sha256:" + "a" * 64)
    with patch("fuzzingbrain.fuzzer.seed_sandbox._docker_binary_and_image",
               return_value=("/usr/bin/docker", "sha256:" + "a" * 64)), \
         patch("fuzzingbrain.fuzzer.seed_sandbox._capture_bounded",
               return_value=(0, b'{"seeds":["eA=="]}', b"")), \
         patch("fuzzingbrain.fuzzer.seed_sandbox._remove_container",
               side_effect=SeedSandboxError("cleanup failed")):
        with pytest.raises(SeedSandboxError, match="cleanup could not be certified"):
            execute_seed_generator("def generate(n): return b'x'", 1)


def test_cleanup_failure_is_fatal_in_seed_mcp_result(monkeypatch):
    worker_id = "sandbox-cleanup-context"
    set_seed_context(task_id="sandbox-task", worker_id=worker_id,
                     direction_id="sandbox-direction", fuzzer_manager=None)
    monkeypatch.setattr(
        "fuzzingbrain.fuzzer.seed_tools.execute_seed_generator",
        lambda *_: (_ for _ in ()).throw(
            SeedSandboxCleanupError("seed sandbox cleanup could not be certified")),
    )
    try:
        result = create_seed_impl("def generate(n): return b'x'",
                                  num_seeds=1, worker_id=worker_id)
        assert result["success"] is False
        assert result["fatal_sandbox_cleanup"] is True
    finally:
        clear_seed_context(worker_id)
