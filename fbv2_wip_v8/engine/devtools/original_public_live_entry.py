"""Fresh-process, explicit public-development entry for original FBv2.

Run this file through the pinned launcher with ``python -I -S -B``. It imports no FBv2 or
product code before checking an externally pinned spec and runtime source
trees. It never runs Blind 3 or Oracle. This is a development execution path;
its output is not a VERIFIED vulnerability verdict.
"""

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_HISTORICAL_ANSWER_NAME = re.compile(
    r"(?:^|[._-])(oob|uaf|pov|crash|exploit|root[._-]?cause|answer)"
    r"(?:[._-]|$)", re.IGNORECASE)
_CANONICAL_TASK_MTIME_NS = 946684800_000_000_000
_TRUSTED_GIT = Path("/usr/bin/git")
_TRUSTED_GIT_SHA256 = (
    "eb54b535467e0975c1284d4c4d08eea779aeb248a5d34b02e2ee171382e22201")
_TRUSTED_MD4C_HP_BUILDER = Path(
    "/home/dawne/SunrinInfosecProject2026/reference/"
    "blind2_v2_preparation_20261027/tools/multi_tu_assertion_build.py")
_TRUSTED_MD4C_HP_BUILDER_SHA256 = (
    "fbe9616f102d76205bb6d20b49c225f7043f5393d675c6387ea965d423139ffc")
_TRUSTED_MD4C_HP_MANIFEST_SHA256 = (
    "200d5248f835e3942dcd853934d309949b9b73354cb64956ca15cf5750539dd1")
_TRUSTED_CJSON_HP_BUILDER = Path(
    "/home/dawne/SunrinInfosecProject2026/reference/"
    "hp_cjson_official_qualification_toctou_v2_20261108/"
    "cjson_assertion_build.py")
_TRUSTED_CJSON_HP_BUILDER_SHA256 = (
    "6e6f22fd6e70197e2ee6773c564af8c742e1db8fba1e8c9f272cf988baddd3f4")
_TRUSTED_CJSON_HP_MANIFEST_SHA256 = (
    "c5ed78a9a37b438bcb501f8698e959a888486fe9572825b6d5ebc49f562a44dc")
_TRUSTED_SP_APPROVAL_PUBLIC_KEY_SHA256 = frozenset({
    "8d68a3290a43e29ad4834269d1a9843ac9fac0fdc617910780c278f557b852c5",
})
_TRUSTED_SITE_PACKAGES = Path(
    "/home/dawne/.venvs/fbv2-live-v11/lib/python3.13/site-packages")
_BOOTSTRAP_PYTHON = Path("/usr/bin/python3.12")
_RUNTIME_HANDOFF_NAMES = frozenset({
    "FBV2_RUNTIME_CLOSURE_BOOTSTRAP_SHA256",
    "FBV2_RUNTIME_CLOSURE_MANIFEST_PATH",
    "FBV2_RUNTIME_CLOSURE_MANIFEST_SHA256",
    "FBV2_RUNTIME_CLOSURE_SPEC_PATH", "FBV2_RUNTIME_CLOSURE_SPEC_SHA256",
    "FBV2_RUNTIME_CLOSURE_SUPERVISOR_PATH",
    "FBV2_RUNTIME_CLOSURE_SUPERVISOR_SHA256",
    "FBV2_RUNTIME_CLOSURE_SUPERVISOR_PID",
})
_COMBINED_SP_HP_KIND = (
    "SP_PERSISTENT_CONCURRENT_QUEUE_HP_POST_WORKER_DEV_V1")
_PARALLEL_SP_HP_KIND = (
    "SP_PERSISTENT_CONCURRENT_QUEUE_HP_PARALLEL_DEV_V1")


def _combined_sp_hp(spec: object) -> bool:
    """Recognize only the versioned concurrent-SP/post-Worker-HP profile."""
    return (type(spec) is dict and
            type(spec.get("development_seed_scope")) is dict and
            spec["development_seed_scope"].get("kind") ==
                _COMBINED_SP_HP_KIND)


def _parallel_sp_hp(spec: object) -> bool:
    return (type(spec) is dict and
            type(spec.get("development_seed_scope")) is dict and
            spec["development_seed_scope"].get("kind") ==
                _PARALLEL_SP_HP_KIND)


_SIGNED_SP_KINDS = {
    "sp": {
        "admission": "SP_SIGNED_LIVE_ADMISSION_V1",
        "approval": "FBV2_SP_NOHINT_LIVE_APPROVAL_V1",
        "check": "FBV2_SP_SIGNED_CHECK_ONLY_RECEIPT_V1",
        "authorization": "FBV2_SP_CHECK_ONLY_LIVE_AUTHORIZATION_V1",
        "claim": "FBV2_SP_SIGNED_LIVE_CLAIM_V1",
        "database_claim": "FBV2_SP_SIGNED_LIVE_DATABASE_CLAIM_V1",
        "database_collection": "__fbv2_sp_signed_live_claim_v1",
        "internal_preflight": "FBV2_SP_LIVE_INTERNAL_PREFLIGHT_RECEIPT_V1",
    },
    "post_worker": {
        "admission": "SP_HP_POST_WORKER_SIGNED_LIVE_ADMISSION_V2",
        "approval": "FBV2_SP_HP_POST_WORKER_LIVE_APPROVAL_V2",
        "check": "FBV2_SP_HP_POST_WORKER_CHECK_ONLY_RECEIPT_V2",
        "authorization": "FBV2_SP_HP_POST_WORKER_LIVE_AUTHORIZATION_V2",
        "claim": "FBV2_SP_HP_POST_WORKER_LIVE_CLAIM_V2",
        "database_claim": "FBV2_SP_HP_POST_WORKER_LIVE_DATABASE_CLAIM_V2",
        "database_collection": "__fbv2_sp_hp_post_worker_live_claim_v2",
        "internal_preflight": "FBV2_SP_HP_POST_WORKER_INTERNAL_PREFLIGHT_RECEIPT_V2",
    },
    "parallel": {
        "admission": "SP_HP_PARALLEL_SIGNED_LIVE_ADMISSION_V1",
        "approval": "FBV2_SP_HP_PARALLEL_LIVE_APPROVAL_V1",
        "check": "FBV2_SP_HP_PARALLEL_CHECK_ONLY_RECEIPT_V1",
        "authorization": "FBV2_SP_HP_PARALLEL_LIVE_AUTHORIZATION_V1",
        "claim": "FBV2_SP_HP_PARALLEL_LIVE_CLAIM_V1",
        "database_claim": "FBV2_SP_HP_PARALLEL_LIVE_DATABASE_CLAIM_V1",
        "database_collection": "__fbv2_sp_hp_parallel_live_claim_v1",
        "internal_preflight": "FBV2_SP_HP_PARALLEL_INTERNAL_PREFLIGHT_RECEIPT_V1",
    },
}


def _signed_sp_kind(spec: object, field: str) -> str:
    profile = ("parallel" if _parallel_sp_hp(spec) else
               "post_worker" if _combined_sp_hp(spec) else "sp")
    return _SIGNED_SP_KINDS[profile][field]


def _consume_runtime_closure_handoff() -> dict[str, str]:
    values = {name: os.environ.pop(name, None)
              for name in _RUNTIME_HANDOFF_NAMES}
    if (any(type(value) is not str or not value for value in values.values()) or
            not values["FBV2_RUNTIME_CLOSURE_SUPERVISOR_PID"].isdigit()):
        raise ValueError("signed SP runtime closure handoff is absent")
    parent = int(values["FBV2_RUNTIME_CLOSURE_SUPERVISOR_PID"])
    supervisor = Path(values["FBV2_RUNTIME_CLOSURE_SUPERVISOR_PATH"])
    if os.getppid() != parent:
        raise ValueError("signed SP runtime closure parent changed")
    try:
        parent_exe = Path(f"/proc/{parent}/exe").resolve()
        parent_argv = Path(f"/proc/{parent}/cmdline").read_bytes().split(b"\0")
    except OSError as exc:
        raise ValueError("signed SP runtime closure parent is unavailable") from exc
    bootstrap_source = parent_argv[5] if len(parent_argv) > 5 else b""
    if (parent_exe != _BOOTSTRAP_PYTHON or len(parent_argv) < 9 or
            parent_argv[0] != str(_BOOTSTRAP_PYTHON).encode() or
            parent_argv[1:4] != [b"-I", b"-S", b"-B"] or
            parent_argv[4] != b"-c" or
            hashlib.sha256(bootstrap_source).hexdigest() !=
                values["FBV2_RUNTIME_CLOSURE_BOOTSTRAP_SHA256"] or
            parent_argv[6] != str(supervisor).encode() or
            parent_argv[7] != values[
                "FBV2_RUNTIME_CLOSURE_SUPERVISOR_SHA256"].encode() or
            parent_argv[8] != b"exec"):
        raise ValueError("signed SP runtime closure parent identity changed")
    _plain_pin(supervisor,
               values["FBV2_RUNTIME_CLOSURE_SUPERVISOR_SHA256"],
               "runtime closure supervisor")
    manifest_path = Path(values["FBV2_RUNTIME_CLOSURE_MANIFEST_PATH"])
    try:
        manifest = json.loads(_plain_pin_bytes(
            manifest_path,
            values["FBV2_RUNTIME_CLOSURE_MANIFEST_SHA256"],
            "runtime closure manifest"))
    except (UnicodeError, ValueError) as exc:
        raise ValueError("signed SP runtime closure manifest is invalid") from exc
    if (type(manifest) is not dict or
            manifest.get("kind") != "FBV2_SP_RUNTIME_CLOSURE_V1" or
            manifest.get("supervisor_path") != str(supervisor) or
            manifest.get("supervisor_sha256") !=
                values["FBV2_RUNTIME_CLOSURE_SUPERVISOR_SHA256"] or
            manifest.get("bootstrap_source_sha256") !=
                values["FBV2_RUNTIME_CLOSURE_BOOTSTRAP_SHA256"] or
            manifest.get("runtime_python_path") != sys.executable or
            manifest.get("trusted_site_packages") !=
                str(_TRUSTED_SITE_PACKAGES) or
            list(sys.path) != manifest.get("initial_sys_path") or
            type(manifest.get("sanitized_sys_path")) is not list):
        raise ValueError("signed SP runtime closure process identity changed")
    sys.path[:] = list(manifest["sanitized_sys_path"])
    globals()["_SIGNED_RUNTIME_CLOSURE_IDENTITY"] = {
        **values,
        "runtime_python_path": manifest["runtime_python_path"],
        "runtime_python_sha256": manifest["runtime_python_sha256"],
        "trusted_site_packages": manifest["trusted_site_packages"],
    }
    return values


def _consume_sealed_launcher_image() -> None:
    """Authenticate the immutable entry image before any signed-live claim."""
    names = {
        "FBV2_PINNED_ENTRY_FD", "FBV2_PINNED_ENTRY_PATH",
        "FBV2_PINNED_ENTRY_SHA256", "FBV2_PINNED_LAUNCHER_PATH",
        "FBV2_PINNED_LAUNCHER_SHA256",
    }
    values = {name: os.environ.pop(name, None) for name in names}
    if (any(type(value) is not str or not value for value in values.values()) or
            not str(values["FBV2_PINNED_ENTRY_FD"]).isdigit()):
        raise ValueError("public live development sealed launcher image is absent")
    fd = int(values["FBV2_PINNED_ENTRY_FD"])
    proc_path = Path(f"/proc/self/fd/{fd}")
    if Path(__file__) != proc_path:
        raise ValueError("public live development is not running sealed entry")
    required_seals = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW |
                      fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or
                info.st_size > 16 * 1024 * 1024 or
                fcntl.fcntl(fd, fcntl.F_GET_SEALS) & required_seals !=
                    required_seals):
            raise ValueError
        raw = os.pread(fd, info.st_size, 0)
        if len(raw) != info.st_size:
            raise ValueError
    except (OSError, ValueError):
        raise ValueError("public live development sealed entry is invalid") from None
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    entry = Path(values["FBV2_PINNED_ENTRY_PATH"])
    entry_sha = values["FBV2_PINNED_ENTRY_SHA256"]
    launcher = Path(values["FBV2_PINNED_LAUNCHER_PATH"])
    launcher_sha = values["FBV2_PINNED_LAUNCHER_SHA256"]
    expected_launcher = entry.with_name("sp_signed_live_pinned_launcher.py")
    if (not _SHA.fullmatch(entry_sha) or hashlib.sha256(raw).hexdigest() != entry_sha or
            not entry.is_absolute() or entry.is_symlink() or
            entry != entry.resolve() or launcher != expected_launcher or
            hashlib.sha256(_plain_pin_bytes(entry, entry_sha,
                                            "launcher entry image")).hexdigest() !=
                entry_sha):
        raise ValueError("public live development sealed entry identity changed")
    _plain_pin(launcher, launcher_sha, "launcher source image")
    if any(name in os.environ for name in _RUNTIME_HANDOFF_NAMES):
        _consume_runtime_closure_handoff()
    if (not _TRUSTED_SITE_PACKAGES.is_absolute() or
            _TRUSTED_SITE_PACKAGES.is_symlink() or
            not _TRUSTED_SITE_PACKAGES.is_dir() or
            _TRUSTED_SITE_PACKAGES.resolve() != _TRUSTED_SITE_PACKAGES):
        raise ValueError("public live dependency path is not canonical")
    globals()["__file__"] = str(entry)
    sys.argv[0] = str(entry)
    sys.path.append(str(_TRUSTED_SITE_PACKAGES))


def _trusted_hp_physical_pair(builder: Path, builder_sha256: object,
                              manifest: Path,
                              manifest_sha256: object) -> bool:
    """Recognize only byte-pinned builders reviewed for this entry path."""
    recipes = (
        (_TRUSTED_MD4C_HP_BUILDER, _TRUSTED_MD4C_HP_BUILDER_SHA256,
         "multi_tu_assertion_build_manifest.json",
         _TRUSTED_MD4C_HP_MANIFEST_SHA256),
        (_TRUSTED_CJSON_HP_BUILDER, _TRUSTED_CJSON_HP_BUILDER_SHA256,
         "cjson_assertion_build_manifest.json",
         _TRUSTED_CJSON_HP_MANIFEST_SHA256),
    )
    return any(
        builder == expected_builder and
        builder_sha256 == expected_builder_sha and
        manifest == expected_builder.with_name(expected_manifest_name) and
        manifest_sha256 == expected_manifest_sha
        for (expected_builder, expected_builder_sha, expected_manifest_name,
             expected_manifest_sha) in recipes)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _requires_seed_sandbox(spec: dict) -> bool:
    """Original no-hint Worker enters Direction Seed; controls do not."""
    return (spec.get("manual_sp_control") is None and
            spec.get("hp_only") is None)


def _preflight_seed_sandbox() -> None:
    """Check that the pinned image can execute the actual isolated worker."""
    from fuzzingbrain.fuzzer.seed_sandbox import execute_seed_generator

    expected = b"fbv2-seed-image-preflight"
    result = execute_seed_generator(
        "def generate():\n    return b'fbv2-seed-image-preflight'\n", 1)
    if result != [expected]:
        raise ValueError("pinned Seed image failed its execution preflight")


def _plain_pin_bytes(path: Path, wanted: str, label: str) -> bytes:
    """Read and authenticate one canonical file from the same open handle."""
    if (not _SHA.fullmatch(wanted or "") or not path.is_absolute() or
            path.is_symlink() or path != path.resolve() or
            not path.is_file()):
        raise ValueError(f"{label} pin changed before importing runtime")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        current = path.stat(follow_symlinks=False)
        raw = b"".join(chunks)
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                row.st_mtime_ns, row.st_ctime_ns)
        if (identity(before) != identity(after) or
                (current.st_dev, current.st_ino) !=
                    (after.st_dev, after.st_ino) or
                hashlib.sha256(raw).hexdigest() != wanted):
            raise ValueError
        return raw
    except (OSError, ValueError):
        raise ValueError(
            f"{label} pin changed before importing runtime") from None


def _plain_pin(path: Path, wanted: str, label: str) -> None:
    _plain_pin_bytes(path, wanted, label)


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _stable_plain_bytes(path: Path, label: str) -> bytes:
    """Read one canonical regular file once, rejecting concurrent mutation."""
    if (not path.is_absolute() or path.is_symlink() or
            path != path.resolve() or not path.is_file()):
        raise ValueError(f"{label} is not a canonical plain file")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError
            chunks = []
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            after = os.fstat(fd)
        finally:
            os.close(fd)
        current = path.stat(follow_symlinks=False)
        identity = lambda row: (row.st_dev, row.st_ino, row.st_size,
                                row.st_mtime_ns, row.st_ctime_ns)
        if (identity(before) != identity(after) or
                (current.st_dev, current.st_ino) !=
                    (after.st_dev, after.st_ino)):
            raise ValueError
        return b"".join(chunks)
    except (OSError, ValueError):
        raise ValueError(f"{label} changed while being read") from None


def _raise_walk_error(error: OSError) -> None:
    raise error


def _reject_hidden_node_metadata(path: Path, info: os.stat_result,
                                 *, directory: bool) -> None:
    """Require traversable plain nodes and reject unaccounted xattr/ACL data."""
    required = ((stat.S_IRUSR | stat.S_IXUSR) if directory else stat.S_IRUSR)
    try:
        attributes = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("prepared Task node metadata is unreadable") from exc
    if attributes:
        raise ValueError("prepared Task contains extended attributes")
    if stat.S_IMODE(info.st_mode) & required != required:
        raise ValueError("prepared Task contains inaccessible node")


def _verified_plain_tree_paths(root: Path) -> list[Path]:
    """Fully enumerate a tree without silently dropping traversal failures."""
    root_info = root.lstat()
    _reject_hidden_node_metadata(root, root_info, directory=True)
    rows = []
    for current, directories, files in os.walk(
            root, followlinks=False, onerror=_raise_walk_error):
        current_path = Path(current)
        for name in sorted([*directories, *files]):
            path = current_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("prepared Task contains symlink")
            if stat.S_ISDIR(info.st_mode):
                _reject_hidden_node_metadata(path, info, directory=True)
            elif stat.S_ISREG(info.st_mode):
                _reject_hidden_node_metadata(path, info, directory=False)
            else:
                raise ValueError("prepared Task contains special node")
            rows.append(path)
    return rows


def _git_tracked_executable_paths(task: Path) -> set[str]:
    """Return exact Git-index executable paths without mutating the index."""
    repo = task / "repo"
    git_dir = repo / ".git"
    index = git_dir / "index"
    _plain_pin(_TRUSTED_GIT, _TRUSTED_GIT_SHA256, "Git executable")
    if (not repo.is_absolute() or repo.is_symlink() or repo != repo.resolve() or
            not git_dir.is_dir() or git_dir.is_symlink() or
            not index.is_file() or index.is_symlink()):
        raise ValueError("prepared Task Git identity is not canonical")
    environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_DIR": str(git_dir),
        "GIT_INDEX_FILE": str(index),
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_WORK_TREE": str(repo),
        "LC_ALL": "C",
    }
    try:
        completed = subprocess.run(
            [str(_TRUSTED_GIT), "--no-optional-locks", "--literal-pathspecs",
             f"--git-dir={git_dir}", f"--work-tree={repo}",
             "ls-files", "--stage", "-z", "--"],
            cwd=repo, capture_output=True, check=True, env=environment)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("prepared Task Git executable inventory failed") from exc
    result: set[str] = set()
    seen: set[str] = set()
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_id, stage = metadata.split(b" ")
            relative_text = raw_path.decode("utf-8")
        except (UnicodeError, ValueError) as exc:
            raise ValueError(
                "prepared Task Git executable inventory is malformed") from exc
        relative = Path(relative_text)
        if (stage != b"0" or mode not in {b"100644", b"100755"} or
                not re.fullmatch(rb"[0-9a-f]{40}|[0-9a-f]{64}", object_id) or
                relative.is_absolute() or not relative.parts or
                any(part in {"", ".", ".."} for part in relative.parts) or
                relative_text in seen):
            raise ValueError(
                "prepared Task Git executable inventory is ineligible")
        seen.add(relative_text)
        source = repo.joinpath(*relative.parts)
        info = source.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("prepared Task tracked source is not a plain file")
        if mode == b"100755":
            result.add((Path("repo") / relative).as_posix())
    _plain_pin(_TRUSTED_GIT, _TRUSTED_GIT_SHA256, "Git executable")
    return result


def _task_executable_paths(task: Path, manifest_sha256: str,
                           manifest: dict) -> set[str]:
    fuzzer = manifest.get("fuzzer_name")
    if (not _SHA.fullmatch(manifest_sha256 or "") or
            type(fuzzer) is not str or Path(fuzzer).name != fuzzer):
        raise ValueError("prepared Task executable identity is malformed")
    return _git_tracked_executable_paths(task) | {
        f".fbv2_prebuilt/{manifest_sha256}/binaries/address/{fuzzer}",
        f".fbv2_prebuilt/{manifest_sha256}/binaries/coverage/{fuzzer}",
    }


def _canonicalize_task_metadata(root: Path,
                                executable_paths: set[str]) -> None:
    """Remove writable metadata channels before the prepared Task is frozen."""
    nodes = _verified_plain_tree_paths(root)
    for path in sorted(nodes, key=lambda item: len(item.parts), reverse=True):
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISREG(info.st_mode):
            path.chmod(0o555 if relative in executable_paths else 0o444,
                       follow_symlinks=False)
            os.utime(path, ns=(_CANONICAL_TASK_MTIME_NS,
                               _CANONICAL_TASK_MTIME_NS),
                     follow_symlinks=False)
        else:
            path.chmod(0o755, follow_symlinks=False)
            os.utime(path, ns=(_CANONICAL_TASK_MTIME_NS,
                               _CANONICAL_TASK_MTIME_NS),
                     follow_symlinks=False)
            path.chmod(0o555, follow_symlinks=False)
    root.chmod(0o755, follow_symlinks=False)
    os.utime(root, ns=(_CANONICAL_TASK_MTIME_NS,
                       _CANONICAL_TASK_MTIME_NS), follow_symlinks=False)
    root.chmod(0o555, follow_symlinks=False)


def _verify_canonical_task_metadata(root: Path,
                                    executable_paths: set[str]) -> None:
    expected_owner = (os.geteuid(), os.getegid())
    rows = [root, *_verified_plain_tree_paths(root)]
    for path in rows:
        info = path.lstat()
        relative = ("" if path == root else
                    path.relative_to(root).as_posix())
        directory = stat.S_ISDIR(info.st_mode)
        expected_mode = (0o555 if directory or relative in executable_paths
                         else 0o444)
        if ((info.st_uid, info.st_gid) != expected_owner or
                stat.S_IMODE(info.st_mode) != expected_mode or
                info.st_mtime_ns != _CANONICAL_TASK_MTIME_NS or
                (not directory and info.st_nlink != 1)):
            raise ValueError("prepared Task metadata is not canonical")


def _full_plain_tree_sha256(root: Path) -> str:
    """Hash every directory and regular file; reject all special nodes."""
    if (not root.is_absolute() or root.is_symlink() or
            root != root.resolve() or not root.is_dir()):
        raise ValueError("prepared Task is not a canonical directory")
    rows = []
    for path in _verified_plain_tree_paths(root):
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISDIR(info.st_mode):
            rows.append((relative, b"D", b""))
        else:
            raw = _stable_plain_bytes(path, "prepared Task member")
            rows.append((relative, b"F", hashlib.sha256(raw).digest()))
    digest = hashlib.sha256()
    for relative, kind, content_sha in sorted(rows):
        name = relative.encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(kind)
        digest.update(content_sha)
    return digest.hexdigest()


def _clean_repo_tree_sha256(root: Path) -> str:
    """Hash the no-hint source tree using the clean-task receipt contract."""
    if (not root.is_absolute() or root.is_symlink() or
            root != root.resolve() or not root.is_dir()):
        raise ValueError("prepared source repository is not canonical")
    rows = []
    root_info = root.lstat()
    _reject_hidden_node_metadata(root, root_info, directory=True)
    for current, directories, files in os.walk(
            root, followlinks=False, onerror=_raise_walk_error):
        current_path = Path(current)
        relative_current = current_path.relative_to(root)
        if ".git" in relative_current.parts:
            directories[:] = []
            continue
        for name in sorted(directories):
            path = current_path / name
            info = path.lstat()
            if path.is_symlink():
                raise ValueError("prepared source repository contains symlink")
            _reject_hidden_node_metadata(path, info, directory=True)
        for name in sorted(files):
            path = current_path / name
            info = path.lstat()
            if (stat.S_ISLNK(info.st_mode) or
                    not stat.S_ISREG(info.st_mode)):
                raise ValueError(
                    "prepared source repository contains non-plain file")
            _reject_hidden_node_metadata(path, info, directory=False)
            relative = path.relative_to(root)
            if ".git" in relative.parts:
                continue
            rows.append((relative.as_posix(), hashlib.sha256(
                _stable_plain_bytes(path, "prepared source member")).digest()))
    digest = hashlib.sha256()
    for relative, content_sha in sorted(rows):
        name = relative.encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(content_sha)
    return digest.hexdigest()


def _source_git_inventory_sha256(root: Path) -> str:
    """Pin the complete Git namespace and every metadata byte."""
    if (not root.is_absolute() or root.is_symlink() or
            root != root.resolve() or not root.is_dir()):
        raise ValueError("prepared Git inventory is not canonical")
    rows = []
    for path in _verified_plain_tree_paths(root):
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        if stat.S_ISDIR(info.st_mode):
            rows.append((relative, b"D", b""))
        else:
            content_sha = hashlib.sha256(
                _stable_plain_bytes(path, "prepared Git member")).digest()
            rows.append((relative, b"F", content_sha))
    digest = hashlib.sha256()
    for relative, kind, content_sha in sorted(rows):
        name = relative.encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(kind)
        digest.update(content_sha)
    return digest.hexdigest()


def _lock_task_readonly(root: Path, expected_sha256: str) -> None:
    """Reverify, remove write bits, and erase mutable atime hints."""
    if _full_plain_tree_sha256(root) != expected_sha256:
        raise ValueError("prepared Task changed before read-only lock")
    nodes = sorted(_verified_plain_tree_paths(root),
                   key=lambda path: len(path.parts), reverse=True)
    for path in nodes:
        info = path.lstat()
        if stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode):
            path.chmod(info.st_mode & ~0o222, follow_symlinks=False)
        else:
            raise ValueError("prepared Task contains a non-lockable node")
    root_info = root.lstat()
    root.chmod(root_info.st_mode & ~0o222, follow_symlinks=False)
    if _full_plain_tree_sha256(root) != expected_sha256:
        raise ValueError("prepared Task changed during read-only lock")
    # Hashing and admission necessarily read Task files and can update atime.
    # More importantly, an owner could otherwise encode post-signature hints
    # in atime without changing any pinned bytes, modes, or mtimes.  Reset the
    # complete verified inventory only after the final content read, then use
    # lstat-only checks so the model starts from one canonical value.
    for path in [*nodes, root]:
        info = path.lstat()
        os.utime(path, ns=(_CANONICAL_TASK_MTIME_NS, info.st_mtime_ns),
                 follow_symlinks=False)
    for path in [*nodes, root]:
        info = path.lstat()
        if (info.st_atime_ns != _CANONICAL_TASK_MTIME_NS or
                info.st_mtime_ns != _CANONICAL_TASK_MTIME_NS):
            raise ValueError("prepared Task time metadata could not be locked")


def _verify_prepared_task_clean_inventory(
        task: Path, manifest_sha256: str, manifest: dict,
        *, source_git_inventory_sha256: str) -> None:
    """Reject pre-hash answer material outside the independently pinned inputs."""
    if (not _SHA.fullmatch(source_git_inventory_sha256 or "") or
            {path.name for path in task.iterdir()} != {"repo", ".fbv2_prebuilt"}):
        raise ValueError("prepared Task top-level inventory is not eligible")
    git = task / "repo" / ".git"
    if _source_git_inventory_sha256(git) != source_git_inventory_sha256:
        raise ValueError("prepared source Git inventory changed")
    root = task / ".fbv2_prebuilt"
    fuzzer = manifest.get("fuzzer_name")
    if (not _SHA.fullmatch(manifest_sha256 or "") or
            type(fuzzer) is not str or Path(fuzzer).name != fuzzer):
        raise ValueError("prepared prebuilt inventory identity is malformed")
    prefix = manifest_sha256
    expected_directories = {
        prefix,
        f"{prefix}/binaries",
        f"{prefix}/binaries/address",
        f"{prefix}/binaries/coverage",
        f"{prefix}/mongodb",
    }
    expected_files = {
        f"{prefix}/binaries/address/{fuzzer}":
            manifest.get("asan_binary", {}).get("sha256"),
        f"{prefix}/binaries/coverage/{fuzzer}":
            manifest.get("coverage_binary", {}).get("sha256"),
        f"{prefix}/mongodb/callgraph.json": None,
        f"{prefix}/mongodb/functions.json": None,
    }
    actual_directories = set()
    actual_files = {}
    root_info = root.lstat()
    _reject_hidden_node_metadata(root, root_info, directory=True)
    for current, directories, files in os.walk(
            root, followlinks=False, onerror=_raise_walk_error):
        current_path = Path(current)
        for name in sorted(directories):
            path = current_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ValueError("prepared prebuilt inventory has unsafe node")
            _reject_hidden_node_metadata(path, info, directory=True)
            actual_directories.add(path.relative_to(root).as_posix())
        for name in sorted(files):
            path = current_path / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise ValueError("prepared prebuilt inventory has unsafe node")
            _reject_hidden_node_metadata(path, info, directory=False)
            actual_files[path.relative_to(root).as_posix()] = hashlib.sha256(
                _stable_plain_bytes(path, "prepared prebuilt member")).hexdigest()
    if (actual_directories != expected_directories or
            set(actual_files) != set(expected_files) or
            any(expected is not None and actual_files[path] != expected
                for path, expected in expected_files.items())):
        raise ValueError("prepared prebuilt inventory contains unapproved content")
    _verify_canonical_task_metadata(
        task, _task_executable_paths(task, manifest_sha256, manifest))
    for path in _verified_plain_tree_paths(task):
        if _HISTORICAL_ANSWER_NAME.search(path.name):
            raise ValueError("prepared Task contains historical-answer-like name")


def _verify_signed_sp_runtime(spec: dict, spec_path: Path,
                              spec_sha256: str) -> None:
    """Bind the fresh interpreter itself before signed SP admission."""
    optin = spec.get("sp_live_admission")
    if type(optin) is not dict:
        return
    identity = globals().get("_SIGNED_RUNTIME_CLOSURE_IDENTITY")
    runtime_python = Path(optin.get("runtime_python_path", ""))
    expected = {
        "FBV2_RUNTIME_CLOSURE_MANIFEST_PATH":
            optin.get("runtime_closure_manifest_path"),
        "FBV2_RUNTIME_CLOSURE_MANIFEST_SHA256":
            optin.get("runtime_closure_manifest_sha256"),
        "FBV2_RUNTIME_CLOSURE_SPEC_PATH": str(spec_path),
        "FBV2_RUNTIME_CLOSURE_SPEC_SHA256": spec_sha256,
        "FBV2_RUNTIME_CLOSURE_SUPERVISOR_PATH":
            optin.get("runtime_closure_supervisor_path"),
        "FBV2_RUNTIME_CLOSURE_SUPERVISOR_SHA256":
            optin.get("runtime_closure_supervisor_sha256"),
    }
    if (type(identity) is not dict or
            any(identity.get(key) != value for key, value in expected.items()) or
            identity.get("runtime_python_path") != str(runtime_python) or
            identity.get("runtime_python_sha256") !=
                optin.get("runtime_python_sha256") or
            identity.get("trusted_site_packages") !=
                str(_TRUSTED_SITE_PACKAGES) or
            Path(sys.executable) != runtime_python):
        raise ValueError("signed SP runtime Python path changed")
    _plain_pin(runtime_python, optin.get("runtime_python_sha256"),
               "signed SP runtime Python")


def _sp_support_rows(spec: dict) -> tuple[dict, dict, dict, dict]:
    optin = spec.get("sp_live_admission")
    expected = {
        "enabled", "contract_kind", "one_attempt",
        "approval_public_key_path", "approval_public_key_sha256",
        "preregistration_path", "preregistration_sha256",
        "qualification_path", "qualification_sha256",
        "selection_receipt_path", "selection_receipt_sha256",
        "clean_task_audit_path", "clean_task_audit_sha256",
        "provider_free_preflight_path", "provider_free_preflight_sha256",
        "task_prepared_tree_sha256", "live_entry_sha256",
        "pinned_launcher_path", "pinned_launcher_sha256",
        "runtime_python_path", "runtime_python_sha256",
        "runtime_closure_manifest_path", "runtime_closure_manifest_sha256",
        "runtime_closure_supervisor_path",
        "runtime_closure_supervisor_sha256",
        "check_receipt_path", "live_authorization_path",
        "internal_preflight_receipt_path", "claim_path",
    }
    expected_contract_kind = _signed_sp_kind(spec, "admission")
    if (type(optin) is not dict or set(optin) != expected or
            optin.get("enabled") is not True or
            optin.get("contract_kind") != expected_contract_kind or
            optin.get("one_attempt") is not True):
        raise ValueError("signed SP live admission is absent or malformed")
    _plain_pin(Path(__file__).resolve(), optin.get("live_entry_sha256"),
               "SP live entry")
    _plain_pin(Path(optin["pinned_launcher_path"]),
               optin["pinned_launcher_sha256"], "SP pinned launcher")
    _plain_pin(Path(optin["runtime_python_path"]),
               optin["runtime_python_sha256"], "SP runtime Python")
    _plain_pin(Path(optin["runtime_closure_manifest_path"]),
               optin["runtime_closure_manifest_sha256"],
               "SP runtime closure manifest")
    _plain_pin(Path(optin["runtime_closure_supervisor_path"]),
               optin["runtime_closure_supervisor_sha256"],
               "SP runtime closure supervisor")
    support = {}
    for label in ("preregistration", "qualification", "selection_receipt",
                  "clean_task_audit", "provider_free_preflight"):
        path = Path(optin[label + "_path"])
        raw = _plain_pin_bytes(path, optin[label + "_sha256"],
                               "SP " + label)
        try:
            support[label] = json.loads(raw)
        except (UnicodeError, ValueError) as exc:
            raise ValueError(f"SP {label} is malformed") from exc
    prereg = support["preregistration"]
    qualification = support["qualification"]
    selection = support["selection_receipt"]
    clean = support["clean_task_audit"]
    preflight = support["provider_free_preflight"]
    policy = prereg.get("additional_repository")
    identity = spec.get("identity")
    admission = spec.get("admission")
    caps = spec.get("caps")
    development = spec.get("development_seed_scope")
    if (type(identity) is not dict or type(admission) is not dict or
            type(caps) is not dict or type(development) is not dict):
        raise ValueError("SP signed spec support identity is malformed")
    manifest_raw = _plain_pin_bytes(
        Path(admission.get("manifest_path", "")),
        admission.get("manifest_sha256"), "SP prebuilt manifest")
    try:
        manifest = json.loads(manifest_raw)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("SP prebuilt manifest is malformed") from exc
    selected = selection.get("selected_tuple")
    family = policy.get("fixed_family") if type(policy) is dict else None
    task = Path(identity.get("task_path", ""))
    repo = task / "repo"
    exact_zero = lambda row, key: (type(row.get(key)) is int and
                                   row.get(key) == 0)
    combined_hp = _combined_sp_hp(spec) or _parallel_sp_hp(spec)
    if (prereg.get("external_calls_authorized") is not False or
            type(policy) is not dict or
            type(policy.get("maximum_campaign_attempts")) is not int or
            policy.get("maximum_campaign_attempts") != 1 or
            policy.get("historical_answer_material_allowed") is not False or
            policy.get("sp_fuzzer_enabled") is not False or
            policy.get("hp_enabled") is not combined_hp or
            (_parallel_sp_hp(spec) and
             policy.get("hp_execution_order") !=
                 "PARALLEL_AFTER_SHARED_DIRECTION_V1") or
            (_parallel_sp_hp(spec) and
             policy.get("hp_gate") != spec.get("hp_gate")) or
            (_parallel_sp_hp(spec) and
             (type(policy.get("seed_required_unique")) is not int or
              policy["seed_required_unique"] !=
                  caps.get("seed_required_unique") or
              policy.get("sp_gate_unsupported_crash_policy") !=
                  spec.get("sp_gate_unsupported_crash_policy"))) or
            (not _parallel_sp_hp(spec) and
             ("hp_execution_order" in policy or "hp_gate" in policy or
              "seed_required_unique" in policy or
              "sp_gate_unsupported_crash_policy" in policy)) or
            type(policy.get("source_git_inventory_sha256")) is not str or
            not _SHA.fullmatch(policy["source_git_inventory_sha256"]) or
            type(family) is not str or not family or
            type(selected) is not list or len(selected) != 3 or
            not all(type(value) is str and value for value in selected) or
            selection.get("selected_family") != family or
            selection.get("selected_family") !=
                caps.get("security_invariant_focus") or
            selection.get("selected_family") !=
                development.get("security_invariant_focus") or
            not exact_zero(selection, "model_calls") or
            not exact_zero(selection, "target_calls") or
            not exact_zero(clean, "historical_answer_material_count") or
            not exact_zero(clean, "provider_calls") or
            not exact_zero(clean, "target_calls") or
            preflight.get("status") != "PINNED_PROVIDER_FREE" or
            not exact_zero(preflight, "model_calls") or
            not exact_zero(preflight, "target_executions") or
            not exact_zero(preflight, "fuzzer_seconds") or
            preflight.get("product_issued") is not True or
            qualification.get("product_issued") is not True or
            manifest.get("schema") != "fbv2-prebuilt-v1"):
        raise ValueError("SP support evidence is not eligible")
    repo_sha = _clean_repo_tree_sha256(repo)
    if (selected != [manifest.get("project_name"),
                     manifest.get("source_commit"),
                     optin.get("qualification_sha256")] or
            clean.get("source_revision") != manifest.get("source_commit") or
            clean.get("source_tree_sha256") != repo_sha or
            clean.get("task_repo_tree_sha256") != repo_sha or
            clean.get("task_prepared_tree_sha256") !=
                optin.get("task_prepared_tree_sha256") or
            qualification.get("upstream_revision") !=
                manifest.get("source_commit") or
            qualification.get("source_tree_sha256") != repo_sha or
            qualification.get("contract_path") != admission.get("contract_path") or
            qualification.get("contract_sha256") !=
                admission.get("contract_sha256") or
            qualification.get("product_issuer_sha256") !=
                admission.get("product_issuer_sha256") or
            qualification.get("binary_sha256") !=
                manifest.get("asan_binary", {}).get("sha256") or
            preflight.get("project_name") != manifest.get("project_name") or
            preflight.get("fuzzer") != manifest.get("fuzzer_name") or
            preflight.get("binary_sha256") != qualification.get("binary_sha256") or
            preflight.get("contract_sha256") != admission.get("contract_sha256") or
            preflight.get("manifest_path") != admission.get("manifest_path") or
            preflight.get("manifest_sha256") != admission.get("manifest_sha256")):
        raise ValueError("SP support evidence identities do not match")
    _verify_prepared_task_clean_inventory(
        task, admission["manifest_sha256"], manifest,
        source_git_inventory_sha256=policy["source_git_inventory_sha256"])
    if (_full_plain_tree_sha256(task) !=
            optin.get("task_prepared_tree_sha256")):
        raise ValueError("prepared Task identity changed")
    return optin, selection, clean, preflight


def _expected_sp_approval_scope(spec: dict, spec_sha256: str, optin: dict,
                                selection: dict, clean: dict) -> dict:
    identity = spec["identity"]
    admission = spec["admission"]
    caps = spec["caps"]
    development = spec["development_seed_scope"]
    approval_caps = {key: caps[key] for key in (
            "calls_per_agent", "gate_aux_reservation_seconds_per_observation",
            "global_fuzz_seconds", "global_reservation_seconds",
            "model_turn_seconds", "model_wall_seconds", "physical_model_calls",
            "pov_attempts_per_candidate", "pov_timeout_seconds",
            "pov_wall_seconds", "sp_fuzz_max_items", "sp_fuzz_seconds",
            "sp_start_min_remaining_calls", "sp_start_min_remaining_wall_seconds",
            "total_fuzz_seconds", "total_wall_seconds")}
    if caps.get("sp_concurrent_queue") is True:
        approval_caps.update({key: caps[key] for key in (
            "sp_concurrent_queue", "sp_discovery_agents",
            "sp_verify_agents", "sp_pov_agents", "seed_required_unique")})
    selection_scope = {
        "direction_selection": development["direction_selection"],
        "function_hint": None,
        "historical_answer_material_allowed": False,
        "known_input_hint": False,
        "known_vulnerability_hint": False,
        "repository_tuple": selection["selected_tuple"],
        "security_invariant_focus": selection["selected_family"],
        "seed_directions": development["seed_directions"],
        "sp_function_limit": development["sp_function_limit"],
    }
    if caps.get("sp_concurrent_queue") is True:
        selection_scope.update({
            "sp_queue_policy": development["sp_queue_policy"],
            "worker_pool": development["worker_pool"],
        })
    combined_hp = _combined_sp_hp(spec) or _parallel_sp_hp(spec)
    scope = {
        "caps": approval_caps,
        "credit": {
            "automatic_discovery": True,
            "evaluation_class": "POST_FIX_CONTEXT_CLOSURE_NO_HINT",
            "lineage_verified_is_not_security_gate_verified": True,
            "one_campaign": True,
        },
        "execution": {
            "run_id": identity["run_id"],
            "signed_spec_sha256": spec_sha256,
            "task_id": identity["task_id"],
        },
        "human_approval": {
            "post_check_live_authorization_required": True,
            "public_key_sha256": optin["approval_public_key_sha256"],
            "signature_kind": "ED25519_CANONICAL_JSON_V1",
        },
        "modes": {
            "asan_runtime": True, "global_fuzzer": True, "hp": combined_hp,
            "independent_security_gate": True, "pov": True,
            "sp_fuzzer": False, "sp_generator": True, "verifier": True,
        },
        "pins": {
            "codex_executable_sha256": identity["codex_executable_sha256"],
            "contract_sha256": admission["contract_sha256"],
            "engine_py_sha256": identity["engine_py_sha256"],
            "evaluation_py_sha256": identity["evaluation_py_sha256"],
            "manifest_sha256": admission["manifest_sha256"],
            "live_entry_sha256": optin["live_entry_sha256"],
            "pinned_launcher_sha256": optin["pinned_launcher_sha256"],
            "runtime_python_sha256": optin["runtime_python_sha256"],
            "runtime_closure_manifest_sha256":
                optin["runtime_closure_manifest_sha256"],
            "runtime_closure_supervisor_sha256":
                optin["runtime_closure_supervisor_sha256"],
            "preregistration_sha256": optin["preregistration_sha256"],
            "product_py_sha256": identity["product_py_sha256"],
            "qualification_sha256": optin["qualification_sha256"],
            "selection_receipt_sha256": optin["selection_receipt_sha256"],
            "task_prepared_tree_sha256": optin["task_prepared_tree_sha256"],
            "task_repo_tree_sha256": clean["task_repo_tree_sha256"],
        },
        "selection": selection_scope,
    }
    if combined_hp:
        hp_parallel = _parallel_sp_hp(spec)
        scope["hp_parallel" if hp_parallel else "hp_post_worker"] = {
            "automatic_discovery": False,
            "concurrent_with_sp": hp_parallel,
            "max_items": spec["hp"]["max_items"],
            "max_model_calls": spec["hp"]["max_model_calls"],
            "model_budget_reserved": False,
            "assets": spec["hp"]["assets"],
            "physical": spec["hp"]["physical"],
            "selection_policy": (
                "PARALLEL_HP_PRE_SP_SELECTION_V1" if hp_parallel else
                "DIRECTION_ID_FUNCTION_ID_ASC_WRITE_ONCE_V1"),
            "security_gate_credit": (
                "HP_GATE_VERIFIED_ONLY_AFTER_REPROOF" if hp_parallel else
                "NOT_CREDITED"),
            "shared_campaign_model_gate": True,
            "shared_process_ledger": True,
        }
        if hp_parallel:
            scope["hp_parallel"]["gate_policy"] = spec["hp_gate"]
            scope["sp_gate_policy"] = {
                "unsupported_crash_type":
                    spec["sp_gate_unsupported_crash_policy"]}
    return scope


def _verify_sp_approval(spec: dict, spec_sha256: str, *,
                        approval_path: Path | None, approval_sha256: str | None,
                        public_key_path: Path | None,
                        public_key_sha256: str | None) -> tuple[dict, dict]:
    optin, selection, clean, _ = _sp_support_rows(spec)
    configured_key = Path(optin["approval_public_key_path"])
    if (approval_path is None or public_key_path != configured_key or
            public_key_sha256 != optin["approval_public_key_sha256"] or
            public_key_sha256 not in _TRUSTED_SP_APPROVAL_PUBLIC_KEY_SHA256):
        raise ValueError("trusted SP human approval arguments are required")
    approval_raw = _plain_pin_bytes(
        approval_path, approval_sha256, "SP human approval")
    public_raw = _plain_pin_bytes(
        public_key_path, public_key_sha256, "SP approval public key")
    try:
        approval = json.loads(approval_raw)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("SP human approval is malformed") from exc
    signature = approval.get("signature") if type(approval) is dict else None
    signed = ({key: value for key, value in approval.items()
               if key != "signature"} if type(approval) is dict else None)
    expected_scope = _expected_sp_approval_scope(
        spec, spec_sha256, optin, selection, clean)
    if (type(approval) is not dict or set(approval) != {
            "decision", "kind", "reviewed_at", "reviewer_id", "scope",
            "signature", "status"} or
            approval.get("kind") != _signed_sp_kind(spec, "approval") or
            approval.get("status") != "APPROVED" or
            approval.get("decision") is not True or
            type(approval.get("reviewer_id")) is not str or
            not approval["reviewer_id"].strip() or
            type(approval.get("reviewed_at")) is not str or
            not approval["reviewed_at"].strip() or
            _canonical_json(approval.get("scope")) !=
                _canonical_json(expected_scope) or
            type(signature) is not dict or
            set(signature) != {"kind", "key_id", "value_base64"} or
            signature.get("kind") != "ED25519_CANONICAL_JSON_V1" or
            signature.get("key_id") != public_key_sha256):
        raise ValueError("SP human approval scope is invalid")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey)
        key = serialization.load_pem_public_key(public_raw)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("SP approval key is not Ed25519")
        key.verify(base64.b64decode(signature["value_base64"], validate=True),
                   _canonical_json(signed))
    except Exception as exc:
        raise ValueError("SP human approval signature is invalid") from exc
    return optin, approval


def _exclusive_json(path: Path, value: dict) -> str:
    if (not path.is_absolute() or path.is_symlink() or
            path.parent.is_symlink() or path.parent != path.parent.resolve() or
            not path.parent.is_dir()):
        raise ValueError("SP admission receipt path is unsafe")
    data = (json.dumps(value, sort_keys=True, indent=2,
                       ensure_ascii=False) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return hashlib.sha256(data).hexdigest()


def _verify_sp_check_receipt(spec: dict, spec_sha256: str, optin: dict,
                             *, approval_sha256: str,
                             receipt_path: Path | None,
                             receipt_sha256: str | None) -> dict:
    expected_path = Path(optin["check_receipt_path"])
    if receipt_path != expected_path:
        raise ValueError("exact SP check-only receipt is required")
    raw = _plain_pin_bytes(expected_path, receipt_sha256,
                           "SP check-only receipt")
    try:
        receipt = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("SP check-only receipt is malformed") from exc
    expected = {
        "approval_sha256": approval_sha256,
        "engine_py_sha256": spec["identity"]["engine_py_sha256"],
        "evaluation_py_sha256": spec["identity"]["evaluation_py_sha256"],
        "kind": _signed_sp_kind(spec, "check"),
        "model_calls": 0,
        "product_py_sha256": spec["identity"]["product_py_sha256"],
        "run_id": spec["identity"]["run_id"],
        "runtime_python_sha256": optin["runtime_python_sha256"],
        "runtime_closure_manifest_sha256":
            optin["runtime_closure_manifest_sha256"],
        "runtime_closure_supervisor_sha256":
            optin["runtime_closure_supervisor_sha256"],
        "spec_sha256": spec_sha256,
        "status": "PREFLIGHT_READY",
        "target_calls": 0,
        "task_id": spec["identity"]["task_id"],
        "task_prepared_tree_sha256": optin["task_prepared_tree_sha256"],
    }
    if (type(receipt) is not dict or set(receipt) != {*expected, "nonce"} or
            any(receipt.get(key) != value or
                type(receipt.get(key)) is not type(value)
                for key, value in expected.items()) or
            type(receipt.get("nonce")) is not str or
            not re.fullmatch(r"[0-9a-f]{64}", receipt["nonce"])):
        raise ValueError("SP check-only receipt scope is invalid")
    return receipt


def _verify_sp_live_authorization(
        spec: dict, spec_sha256: str, optin: dict, *,
        approval_sha256: str, check_receipt_sha256: str,
        authorization_path: Path | None,
        authorization_sha256: str | None) -> dict:
    expected_path = Path(optin["live_authorization_path"])
    if authorization_path != expected_path:
        raise ValueError("post-check human live authorization is required")
    raw = _plain_pin_bytes(expected_path, authorization_sha256,
                           "SP post-check live authorization")
    public_path = Path(optin["approval_public_key_path"])
    public_sha = optin["approval_public_key_sha256"]
    public_raw = _plain_pin_bytes(public_path, public_sha,
                                  "SP approval public key")
    try:
        authorization = json.loads(raw)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("SP post-check live authorization is malformed") from exc
    signature = (authorization.get("signature")
                 if type(authorization) is dict else None)
    signed = ({key: value for key, value in authorization.items()
               if key != "signature"}
              if type(authorization) is dict else None)
    expected_scope = {
        "approval_sha256": approval_sha256,
        "check_receipt_sha256": check_receipt_sha256,
        "one_attempt": True,
        "public_key_sha256": public_sha,
        "run_id": spec["identity"]["run_id"],
        "spec_sha256": spec_sha256,
        "task_id": spec["identity"]["task_id"],
    }
    if (type(authorization) is not dict or set(authorization) != {
            "decision", "kind", "reviewed_at", "reviewer_id", "scope",
            "signature", "status"} or
            authorization.get("kind") !=
                _signed_sp_kind(spec, "authorization") or
            authorization.get("status") != "APPROVED" or
            authorization.get("decision") is not True or
            type(authorization.get("reviewer_id")) is not str or
            not authorization["reviewer_id"].strip() or
            type(authorization.get("reviewed_at")) is not str or
            not authorization["reviewed_at"].strip() or
            _canonical_json(authorization.get("scope")) !=
                _canonical_json(expected_scope) or
            type(signature) is not dict or
            set(signature) != {"kind", "key_id", "value_base64"} or
            signature.get("kind") != "ED25519_CANONICAL_JSON_V1" or
            signature.get("key_id") != public_sha):
        raise ValueError("SP post-check live authorization scope is invalid")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey)
        key = serialization.load_pem_public_key(public_raw)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("SP approval key is not Ed25519")
        key.verify(base64.b64decode(signature["value_base64"], validate=True),
                   _canonical_json(signed))
    except Exception as exc:
        raise ValueError(
            "SP post-check live authorization signature is invalid") from exc
    return authorization


def _claim_sp_live_once(spec: dict, spec_sha256: str, optin: dict, *,
                        approval_sha256: str, check_receipt_sha256: str,
                        live_authorization_sha256: str) -> str:
    return _exclusive_json(Path(optin["claim_path"]), {
        "approval_sha256": approval_sha256,
        "check_receipt_sha256": check_receipt_sha256,
        "kind": _signed_sp_kind(spec, "claim"),
        "live_authorization_sha256": live_authorization_sha256,
        "run_id": spec["identity"]["run_id"],
        "spec_sha256": spec_sha256,
        "status": "CLAIMED",
        "task_id": spec["identity"]["task_id"],
    })


def _claim_sp_live_database_once(spec: dict, spec_sha256: str, *,
                                 approval_sha256: str,
                                 check_receipt_sha256: str,
                                 live_authorization_sha256: str) -> None:
    """Require an empty live database, then atomically create its run claim."""
    identity = spec["identity"]
    database_name = identity.get("mongo_database")
    mongo_url = identity.get("mongo_url")
    if (type(database_name) is not str or not database_name or
            len(database_name.encode("utf-8")) > 63 or
            type(mongo_url) is not str or not mongo_url):
        raise ValueError("SP live Mongo identity is invalid")
    try:
        from pymongo import MongoClient
        client = MongoClient(mongo_url, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        database = client[database_name]
        if database.list_collection_names():
            raise ValueError("SP live Mongo database is not fresh")
        claim_name = _signed_sp_kind(spec, "database_collection")
        database.create_collection(claim_name)
        collection = database[claim_name]
        collection.insert_one({
            "_id": identity["task_id"] + ":" + identity["run_id"],
            "approval_sha256": approval_sha256,
            "check_receipt_sha256": check_receipt_sha256,
            "kind": _signed_sp_kind(spec, "database_claim"),
            "live_authorization_sha256": live_authorization_sha256,
            "run_id": identity["run_id"],
            "spec_sha256": spec_sha256,
            "task_id": identity["task_id"],
        })
        if (set(database.list_collection_names()) != {claim_name} or
                collection.count_documents({}) != 1):
            raise ValueError("SP live Mongo claim is not exclusive")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("SP live Mongo freshness claim failed") from exc
    finally:
        if "client" in locals():
            client.close()


def _reverify_sp_live_database_claim(spec: dict, spec_sha256: str, *,
                                     approval_sha256: str,
                                     check_receipt_sha256: str,
                                     live_authorization_sha256: str) -> None:
    """Recheck exact DB closed state immediately before AnalysisServer starts."""
    identity = spec["identity"]
    claim_name = _signed_sp_kind(spec, "database_collection")
    expected = {
        "_id": identity["task_id"] + ":" + identity["run_id"],
        "approval_sha256": approval_sha256,
        "check_receipt_sha256": check_receipt_sha256,
        "kind": _signed_sp_kind(spec, "database_claim"),
        "live_authorization_sha256": live_authorization_sha256,
        "run_id": identity["run_id"],
        "spec_sha256": spec_sha256,
        "task_id": identity["task_id"],
    }
    try:
        from pymongo import MongoClient
        client = MongoClient(identity["mongo_url"], serverSelectionTimeoutMS=5000)
        database = client[identity["mongo_database"]]
        rows = list(database[claim_name].find({}))
        if (set(database.list_collection_names()) != {claim_name} or
                len(rows) != 1 or
                _canonical_json(rows[0]) != _canonical_json(expected)):
            raise ValueError("SP live Mongo claim changed before execution")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("SP live Mongo claim revalidation failed") from exc
    finally:
        if "client" in locals():
            client.close()


def _runtime_tree_pin(root: Path, wanted: str, *, engine: bool) -> None:
    if (not _SHA.fullmatch(wanted or "") or not root.is_absolute() or
            root.is_symlink() or root != root.resolve() or not root.is_dir()):
        raise ValueError("runtime source root changed before import")
    try:
        all_paths = set(_verified_plain_tree_paths(root))
    except (OSError, ValueError) as exc:
        raise ValueError("runtime source tree is not completely readable") from exc
    for path in all_paths:
        if not path.is_file():
            continue
        lower = path.name.lower()
        if (lower.endswith((".so", ".pyd", ".dll", ".dylib", ".pyo")) or
                (lower.endswith(".pyc") and path.parent.name != "__pycache__")):
            raise ValueError("runtime source tree has unsigned importable bytes")
    files = {path for path in all_paths if path.is_file() and path.suffix == ".py"}
    if engine:
        prompts = root / "fuzzingbrain" / "agents" / "prompts"
        assets = {root / "fuzzingbrain" / "llm_config.yaml",
                  root / "fuzzingbrain" / "tools" / "tools.yaml"}
        if not prompts.is_dir():
            raise ValueError("original prompt directory missing")
        assets.update(prompts.glob("*.md"))
        if (len(assets) < 3 or
                any(not path.is_file() or path.is_symlink() for path in assets)):
            raise ValueError("original prompt/config assets missing")
        files.update(assets)
    if not files:
        raise ValueError("runtime source tree empty")
    digest = hashlib.sha256()
    for path in sorted(files):
        if not path.is_file() or path.is_symlink():
            raise ValueError("runtime source tree changed")
        name = path.relative_to(root).as_posix().encode()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    if digest.hexdigest() != wanted:
        raise ValueError("runtime source tree SHA-256 changed before import")


def _hp_preimport_admission(spec: dict, *, hp_mode: bool,
                            check_only: bool) -> bool:
    """Admit only fixed, pinned product HP assets before runtime imports."""
    hp = spec.get("hp")
    enabled = type(hp) is dict and hp.get("enabled") is True
    if not enabled:
        if hp_mode or hp not in (None, {"enabled": False}):
            raise ValueError("signed HP opt-in is absent")
        return False
    if not (hp_mode or check_only):
        raise ValueError("ordinary public development cannot enable HP")
    expected_keys = {"enabled", "max_items", "max_model_calls", "assets"}
    if "physical" in hp:
        expected_keys.add("physical")
    hp_only = spec.get("hp_only")
    hp_only_rounds = (hp_only.get("max_context_reanalyses", 2)
                      if type(hp_only) is dict else 2)
    expected_model_calls = (5 if spec.get("development_scope") is not None
                            else hp_only_rounds + 2
                            if hp_only is not None else 3)
    if (set(hp) != expected_keys or
            type(hp.get("max_items")) is not int or hp["max_items"] != 1 or
            type(hp.get("max_model_calls")) is not int or
            hp["max_model_calls"] != expected_model_calls or
            type(hp.get("assets")) is not dict or
            set(hp["assets"]) != {
                "function_analysis_prompt_sha256",
                "assertion_generator_prompt_sha256", "config_sha256"}):
        raise ValueError("signed HP item/model cap is invalid")
    root = Path(spec["identity"]["product_src"]).parent
    paths = {
        "function_analysis_prompt_sha256":
            root / "prompts" / "function_analysis.md",
        "assertion_generator_prompt_sha256":
            root / "prompts" / "assertion_generator.md",
        "config_sha256": root / "config" / "default.yaml",
    }
    for key, path in paths.items():
        _plain_pin(path, hp["assets"].get(key), "HP " + key)
    physical = hp.get("physical")
    if physical is not None:
        if (type(physical) is not dict or set(physical) != {
                "enabled", "builder_path", "builder_sha256",
                "manifest_path", "manifest_sha256", "guided_seconds",
                "total_wall_seconds", "output_limit_bytes"} or
                physical.get("enabled") is not True or
                type(physical.get("guided_seconds")) is not int or
                not 1 <= physical["guided_seconds"] <= 10 or
                type(physical.get("total_wall_seconds")) is not int or
                not 60 <= physical["total_wall_seconds"] <= 180 or
                type(physical.get("output_limit_bytes")) is not int or
                not 1 <= physical["output_limit_bytes"] <= 4_000_000 or
                type(physical.get("builder_path")) is not str or
                type(physical.get("manifest_path")) is not str):
            raise ValueError("signed HP physical recipe or cap is invalid")
        builder = Path(physical["builder_path"])
        manifest = Path(physical["manifest_path"])
        if not _trusted_hp_physical_pair(
                builder, physical.get("builder_sha256"), manifest,
                physical.get("manifest_sha256")):
            raise ValueError("signed HP physical builder is not trusted")
        _plain_pin(builder, physical.get("builder_sha256"), "HP physical builder")
        _plain_pin(manifest, physical.get("manifest_sha256"),
                   "HP physical builder manifest")
    return True


def _parallel_hp_gate_preimport_admission(spec: dict) -> None:
    """Check the bounded HP Gate envelope without importing engine code."""
    policy = spec.get("hp_gate")
    if not _parallel_sp_hp(spec):
        if (policy is not None or
                spec.get("sp_gate_unsupported_crash_policy") is not None):
            raise ValueError("HP Gate policy requires the parallel profile")
        return
    caps = spec.get("caps")
    hp = spec.get("hp")
    physical = hp.get("physical") if type(hp) is dict else None
    if (spec.get("sp_gate_unsupported_crash_policy") !=
            "PENDING_HUMAN_REVIEW_NO_TERMINAL_CREDIT_V1" or
            type(caps) is not dict or type(physical) is not dict or
            type(caps.get("seed_required_unique")) is not int or
            caps["seed_required_unique"] != 5 or
            type(policy) is not dict or set(policy) != {
                "enabled", "max_leads", "replay_timeout_seconds",
                "replay_wall_seconds", "source_wall_seconds",
                "output_limit_bytes"} or policy.get("enabled") is not True or
            type(policy.get("max_leads")) is not int or
            not 1 <= policy["max_leads"] <= 3 or
            type(policy.get("replay_timeout_seconds")) is not int or
            not 1 <= policy["replay_timeout_seconds"] <= 30 or
            policy["replay_timeout_seconds"] !=
                caps.get("pov_timeout_seconds") or
            type(policy.get("replay_wall_seconds")) is not int or
            not 30 <= policy["replay_wall_seconds"] <= 180 or
            type(policy.get("source_wall_seconds")) is not int or
            not 30 <= policy["source_wall_seconds"] <= 180 or
            type(policy.get("output_limit_bytes")) is not int or
            policy["output_limit_bytes"] !=
                physical.get("output_limit_bytes") or
            type(caps.get("gate_aux_reservation_seconds_per_observation"))
                not in (int, float) or
            not math.isfinite(
                caps["gate_aux_reservation_seconds_per_observation"]) or
            caps["gate_aux_reservation_seconds_per_observation"] <= 0 or
            policy["max_leads"] * (
                policy["replay_wall_seconds"] +
                policy["source_wall_seconds"]) >
                caps["gate_aux_reservation_seconds_per_observation"]):
        raise ValueError("parallel HP Gate policy is invalid")


def _manual_sp_preimport_admission(spec: dict, *, manual_mode: bool,
                                   function_name: str | None,
                                   check_only: bool) -> None:
    """Pin one manually selected function and a narrow model budget."""
    control = spec.get("manual_sp_control")
    if control is None:
        if manual_mode:
            raise ValueError("signed manual SP control is absent")
        return
    if (type(control) is not dict or set(control) != {
            "enabled", "function_name", "max_model_calls_by_role",
            "automatic_discovery"} or control.get("enabled") is not True or
            control.get("automatic_discovery") is not False or
            type(control.get("function_name")) is not str or
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",
                             control["function_name"]) or
            control.get("max_model_calls_by_role") !=
                {"sp": 6, "verifier": 6, "pov": 6}):
        raise ValueError("signed manual SP control is invalid")
    caps = spec.get("caps")
    if (type(caps) is not dict or caps.get("calls_per_agent") != 6 or
            caps.get("physical_model_calls") != 18):
        raise ValueError("manual SP physical model cap is invalid")
    if manual_mode:
        if function_name != control["function_name"]:
            raise ValueError("manual SP function differs from signed spec")
    elif not check_only:
        raise ValueError("manual SP spec requires its explicit entry mode")


def _hp_only_preimport_admission(spec: dict, *, hp_only_mode: bool,
                                 function_name: str | None,
                                 check_only: bool) -> None:
    """Pin manual HP selection before engine/product imports or model calls."""
    control = spec.get("hp_only")
    if control is None:
        if hp_only_mode:
            raise ValueError("signed HP-only control is absent")
        return
    allowed_keys = {
            "enabled", "function_name", "automatic_discovery",
            "source_tree_sha256", "functions_json_sha256"}
    if (type(control) is not dict or
            set(control) not in (allowed_keys,
                                 allowed_keys | {"max_context_reanalyses"},
                                 allowed_keys | {"assumption_evidence_closure"},
                                 allowed_keys | {"max_context_reanalyses",
                                                 "assumption_evidence_closure"}) or
            control.get("enabled") is not True or
            control.get("automatic_discovery") is not False or
            type(control.get("function_name")) is not str or
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",
                             control["function_name"]) or
            any(type(control.get(key)) is not str or
                not _SHA.fullmatch(control[key]) for key in
                ("source_tree_sha256", "functions_json_sha256")) or
            type(spec.get("hp")) is not dict or
            spec["hp"].get("enabled") is not True or
            type(spec["hp"].get("physical")) is not dict or
            spec.get("manual_sp_control") is not None or
            spec.get("sp_fuzz") is not None):
        raise ValueError("signed HP-only control is invalid")
    context_rounds = control.get("max_context_reanalyses", 2)
    if type(context_rounds) is not int or context_rounds not in (2, 3):
        raise ValueError("signed HP-only context round cap is invalid")
    expected_model_calls = context_rounds + 2
    caps = spec.get("caps")
    if (type(caps) is not dict or
            caps.get("physical_model_calls") != expected_model_calls or
            caps.get("calls_per_agent") != expected_model_calls or
            spec["hp"].get("max_model_calls") != expected_model_calls):
        raise ValueError("HP-only physical model cap is invalid")
    identity = spec.get("identity")
    admission = spec.get("admission")
    if type(identity) is not dict or type(admission) is not dict:
        raise ValueError("HP-only catalog identity is unavailable")
    task_path = Path(identity["task_path"])
    manifest_sha = admission.get("manifest_sha256")
    if type(manifest_sha) is not str or not _SHA.fullmatch(manifest_sha):
        raise ValueError("HP-only manifest pin is invalid")
    catalog = (task_path / ".fbv2_prebuilt" / manifest_sha /
               "mongodb" / "functions.json")
    _plain_pin(catalog, control["functions_json_sha256"],
               "HP-only function catalog")
    closure = control.get("assumption_evidence_closure")
    if closure is not None:
        if (type(closure) is not dict or set(closure) != {
                "enabled", "contract_kind", "one_attempt", "approval_path",
                "approval_sha256", "approval_public_key_path",
                "approval_public_key_sha256"} or
                closure.get("enabled") is not True or
                closure.get("contract_kind") !=
                    "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5" or
                closure.get("one_attempt") is not True or
                type(closure.get("approval_path")) is not str):
            raise ValueError("HP assumption lifecycle live opt-in is invalid")
        approval_path = Path(closure["approval_path"])
        _plain_pin(approval_path, closure.get("approval_sha256"),
                   "HP assumption lifecycle human approval")
        public_key_path = Path(closure["approval_public_key_path"])
        _plain_pin(public_key_path, closure.get("approval_public_key_sha256"),
                   "HP assumption lifecycle approval public key")
        try:
            approval = json.loads(approval_path.read_bytes())
        except (OSError, ValueError, UnicodeError) as exc:
            raise ValueError(
                "HP assumption lifecycle human approval is malformed") from exc
        scope = approval.get("scope") if type(approval) is dict else None
        selection = scope.get("selection") if type(scope) is dict else None
        execution = scope.get("execution") if type(scope) is dict else None
        if (type(approval) is not dict or set(approval) != {
                "kind", "status", "decision", "reviewer_id", "reviewed_at",
                "scope", "signature"} or
                approval.get("kind") !=
                    "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_APPROVAL_V2" or
                approval.get("status") != "APPROVED" or
                approval.get("decision") is not True or
                type(approval.get("reviewer_id")) is not str or
                not approval["reviewer_id"].strip() or
                type(approval.get("reviewed_at")) is not str or
                not approval["reviewed_at"].strip() or
                type(scope) is not dict or
                scope.get("kind") !=
                    "FBV2_HP_ASSUMPTION_LIFECYCLE_LIVE_SCOPE_V2" or
                scope.get("contract_kind") !=
                    "HP_PER_ASSUMPTION_EVIDENCE_CLOSURE_V5" or
                selection != {
                    "function_name": control["function_name"],
                    "automatic_discovery": False, "one_attempt": True} or
                type(selection.get("automatic_discovery")) is not bool or
                type(selection.get("one_attempt")) is not bool or
                type(execution) is not dict or
                execution != {
                    "task_id": identity.get("task_id"),
                    "run_id": identity.get("run_id"),
                    "signed_spec_subject_sha256": execution.get(
                        "signed_spec_subject_sha256")
                } or type(execution.get("signed_spec_subject_sha256")) is not str or
                not _SHA.fullmatch(execution["signed_spec_subject_sha256"])):
            raise ValueError(
                "HP assumption lifecycle human approval is invalid")
    if hp_only_mode:
        if function_name != control["function_name"]:
            raise ValueError("HP-only function differs from signed spec")
    elif not check_only:
        raise ValueError("HP-only spec requires its explicit entry mode")


def _sp_fuzz_preimport_admission(spec: dict, *, check_only: bool) -> bool:
    """Admit a pinned SP process cap without opening its live execution path."""
    caps = spec.get("caps")
    optin = spec.get("sp_fuzz")
    if caps is None and optin is None:
        # Preserve the older source-pin failure order for a deliberately
        # minimal malformed spec. PublicDevCaps rejects it after imports.
        return False
    if type(caps) is not dict:
        raise ValueError("SP fuzz physical caps are absent")
    seconds = caps.get("sp_fuzz_seconds", 0)
    items = caps.get("sp_fuzz_max_items", 0)
    if optin is None:
        if (type(seconds) is not int or seconds != 0 or
                type(items) is not int or items != 0):
            raise ValueError("SP fuzz cap lacks signed opt-in")
        return False
    if (type(optin) is not dict or
            set(optin) != {"enabled", "seconds_per_item", "max_items"} or
            optin.get("enabled") is not True or
            type(seconds) is not int or not 1 <= seconds <= 10 or
            type(items) is not int or items != 1 or
            type(optin.get("seconds_per_item")) is not int or
            optin.get("seconds_per_item") != seconds or
            type(optin.get("max_items")) is not int or
            optin.get("max_items") != items or
            spec.get("manual_sp_control") is not None or
            type(spec.get("hp")) is dict and
            spec["hp"].get("enabled") is True):
        raise ValueError("signed SP fuzz opt-in or physical cap is invalid")
    if not check_only and caps.get("full_nohint_sp") is not True:
        raise ValueError("SP_FUZZ_LIVE_MODE_NOT_CONNECTED")
    return True


def _bounded_nohint_preimport_admission(
        spec: dict, *, bounded_hp_mode: bool = False,
        check_only: bool = False) -> bool:
    """Bind the narrow automatic development scope before runtime imports."""
    caps = spec.get("caps")
    bounded = type(caps) is dict and caps.get("bounded_nohint_dev") is True
    scope = spec.get("development_scope")
    if not bounded:
        if bounded_hp_mode:
            raise ValueError("bounded no-hint HP requires bounded scope")
        if scope is not None or (type(caps) is dict and
                                 caps.get("bounded_nohint_dev") not in (None, False)):
            raise ValueError("unsigned bounded development scope")
        return False
    hp = spec.get("hp")
    hp_enabled = type(hp) is dict and hp.get("enabled") is True
    completion = (type(scope) is dict and
                  scope.get("kind") == "BOUNDED_NOHINT_COMPLETION_DEV_V1")
    expected_scope = {
            "kind": ("BOUNDED_NOHINT_COMPLETION_DEV_V1" if completion else
                     "BOUNDED_NOHINT_DEV_V1"),
            "seed_directions": 2,
            "sp_functions": 1 if hp_enabled else 3,
            "sp_max_iterations": 7,
        }
    if (type(scope) is not dict or
            {key: scope.get(key) for key in expected_scope} != expected_scope or
            scope.get("selection") not in {
                "DIRECTION_RISK_PHASE_CANONICAL_V1",
                "DIRECTION_RISK_PHASE_ROUND_ROBIN_MODEL_ORDER_V2",
                "DIRECTION_RISK_PHASE_ROUND_ROBIN_MODEL_ORDER_V3",
                "DIRECTION_RISK_PHASE_GENERIC_SURFACE_MODEL_TIE_V4"} or
            set(scope) != {*expected_scope, "selection"} or
            type(caps.get("physical_model_calls")) is not int or
            caps["physical_model_calls"] != (80 if completion else 48) or
            type(caps.get("calls_per_agent")) is not int or
            caps["calls_per_agent"] != (32 if completion else 20) or
            caps.get("model_wall_seconds") != (1200 if completion else 900) or
            caps.get("total_wall_seconds") != (2100 if completion else 1800) or
            caps.get("global_fuzz_seconds") != 30 or
            caps.get("sp_fuzz_max_items") != 0 or
            caps.get("sp_fuzz_seconds") != 0 or
            spec.get("manual_sp_control") is not None or
            spec.get("sp_fuzz") is not None):
        raise ValueError("bounded no-hint development scope or cap is invalid")
    if hp != {"enabled": False}:
        if (not (bounded_hp_mode or check_only) or type(hp) is not dict or
                completion or
                set(hp) != {"enabled", "max_items", "max_model_calls",
                            "assets", "physical"} or
                hp.get("enabled") is not True or
                hp.get("max_items") != 1 or
                type(hp.get("max_model_calls")) is not int or
                hp["max_model_calls"] != 5 or
                type(hp.get("physical")) is not dict):
            raise ValueError("bounded no-hint HP physical opt-in is invalid")
    elif bounded_hp_mode:
        raise ValueError("bounded no-hint HP requires signed HP work")
    return True


def _sp_priority_seed_preimport_admission(spec: dict) -> bool:
    """Admit a signed partial Seed phase without limiting original SP pools."""
    caps = spec.get("caps")
    scope = spec.get("development_seed_scope")
    if caps is None and scope is None:
        return False
    if type(caps) is not dict:
        raise ValueError("SP-priority development caps are absent")
    limit = caps.get("seed_direction_limit", 5)
    if type(limit) is not int:
        raise ValueError("SP-priority Seed limit must be an integer")
    if caps.get("full_nohint_sp") is True:
        if (limit != 5 or scope is not None or
                caps.get("physical_model_calls", "missing") is not None or
                caps.get("calls_per_agent", "missing") is not None or
                caps.get("model_wall_seconds", "missing") is not None or
                type(caps.get("total_wall_seconds")) is not int or
                caps["total_wall_seconds"] <= 0 or
                caps.get("bounded_nohint_dev") is not False or
                type(caps.get("sp_iteration_policy")) is not dict or
                caps["sp_iteration_policy"].get("kind") != "LINE_SCALED_V1" or
                spec.get("development_scope") is not None or
                spec.get("manual_sp_control") is not None or
                spec.get("hp_only") is not None or
                spec.get("hp") != {"enabled": False}):
            raise ValueError("full no-hint SP scope is invalid")
        return False
    if limit == 5:
        if scope is not None:
            raise ValueError("unsigned SP-priority Seed scope")
        return False
    completion = scope == {
        "kind": "SP_PRIORITY_ONE_SEED_COMPLETION_DEV_V1",
        "seed_directions": 1, "sp_function_limit": None,
        "sp_queue_policy": "DRAIN_CANDIDATES_BEFORE_NEXT_FUNCTION"}
    extended = scope == {
        "kind": "SP_PRIORITY_ONE_SEED_EXTENDED_DEV_V1",
        "seed_directions": 1, "sp_function_limit": None,
        "sp_queue_policy": "DRAIN_CANDIDATES_BEFORE_NEXT_FUNCTION"}
    standard = scope == {
        "kind": "SP_PRIORITY_ONE_SEED_DEV_V2",
        "seed_directions": 1, "sp_function_limit": None,
        "sp_queue_policy": "DRAIN_CANDIDATES_BEFORE_NEXT_FUNCTION"}
    focus = caps.get("security_invariant_focus")
    new_common = {
        "seed_directions": 1, "sp_function_limit": None,
        "sp_queue_policy": "DRAIN_CANDIDATES_BEFORE_NEXT_FUNCTION",
        "security_invariant_focus": focus,
        "direction_selection":
            "GENERIC_SECURITY_FAMILY_PRIORITY_MODEL_TIE_V1",
        "pov_attempts_per_candidate": 3,
    }
    standard_v3 = scope == {"kind": "SP_PRIORITY_ONE_SEED_DEV_V3",
                            **new_common}
    completion_v2 = scope == {
        "kind": "SP_PRIORITY_ONE_SEED_COMPLETION_DEV_V2", **new_common}
    extended_v2 = scope == {
        "kind": "SP_PRIORITY_ONE_SEED_EXTENDED_DEV_V2", **new_common}
    reserve_calls = caps.get("sp_start_min_remaining_calls")
    reserve_wall = caps.get("sp_start_min_remaining_wall_seconds")
    extended_v3 = scope == {
        "kind": "SP_PRIORITY_ONE_SEED_EXTENDED_DEV_V3", **new_common,
        "sp_start_min_remaining_calls": reserve_calls,
        "sp_start_min_remaining_wall_seconds": reserve_wall,
    }
    concurrent = scope == {
        "kind": "SP_PERSISTENT_CONCURRENT_QUEUE_DEV_V1",
        **{**new_common,
           "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1"},
        "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2},
    }
    combined_hp = scope == {
        "kind": _COMBINED_SP_HP_KIND,
        **{**new_common,
           "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1"},
        "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2},
    }
    parallel_hp = scope == {
        "kind": _PARALLEL_SP_HP_KIND,
        **{**new_common,
           "sp_queue_policy": "PERSISTENT_CONCURRENT_QUEUE_V1"},
        "worker_pool": {"discovery": 3, "verifier": 2, "pov": 2},
    }
    modern = (standard_v3 or completion_v2 or extended_v2 or extended_v3 or
              concurrent or combined_hp or parallel_hp)
    concurrent_profile = concurrent or combined_hp or parallel_hp
    hp_profile = combined_hp or parallel_hp
    concurrent_caps = (
        caps.get("sp_concurrent_queue", False),
        caps.get("sp_discovery_agents", 1),
        caps.get("sp_verify_agents", 1),
        caps.get("sp_pov_agents", 1),
    )
    if (limit != 1 or not (
            standard or completion or extended or modern) or
            (modern and (
                focus not in {"BOUNDS_EXTENT", "LIFETIME_OWNERSHIP",
                              "ARITHMETIC_RANGE", "INITIALIZATION",
                              "NULLABILITY", "STATE_CONSISTENCY"} or
                caps.get("pov_attempts_per_candidate") != 3)) or
            (extended_v3 and (
                type(reserve_calls) is not int or reserve_calls < 1 or
                reserve_calls > caps.get("physical_model_calls", 0) or
                type(reserve_wall) not in (int, float) or
                isinstance(reserve_wall, bool) or reserve_wall <= 0 or
                not math.isfinite(reserve_wall) or
                reserve_wall > caps.get("model_wall_seconds", 0))) or
            (not extended_v3 and (
                reserve_calls is not None or reserve_wall is not None)) or
            (not modern and (
                caps.get("security_invariant_focus") is not None or
                caps.get("pov_attempts_per_candidate", 20) != 20)) or
            (completion and (
                caps.get("physical_model_calls") != 80 or
                caps.get("calls_per_agent") != 32 or
                caps.get("model_wall_seconds") != 1200 or
                caps.get("total_wall_seconds") != 2100)) or
            (completion_v2 and (
                caps.get("physical_model_calls") != 80 or
                caps.get("calls_per_agent") != 32 or
                caps.get("model_wall_seconds") != 1200 or
                caps.get("total_wall_seconds") != 2100)) or
            (extended and (
                caps.get("physical_model_calls") != 120 or
                caps.get("calls_per_agent") != 64 or
                caps.get("model_wall_seconds") != 1500 or
                caps.get("total_wall_seconds") != 2400)) or
            ((extended_v2 or extended_v3 or concurrent or combined_hp) and (
                caps.get("physical_model_calls") != 120 or
                caps.get("calls_per_agent") != 64 or
                caps.get("model_wall_seconds") != 1500 or
                caps.get("total_wall_seconds") != 2400)) or
            (parallel_hp and (
                caps.get("physical_model_calls", "missing") is not None or
                caps.get("calls_per_agent", "missing") is not None or
                caps.get("model_wall_seconds") != 1500 or
                caps.get("total_wall_seconds") != 2400)) or
            ((standard or standard_v3) and (
                caps.get("physical_model_calls", 48) > 48 or
                           caps.get("calls_per_agent", 20) > 20)) or
            (concurrent_profile and
             concurrent_caps != (True, 3, 2, 2)) or
            (parallel_hp and (
                type(caps.get("model_turn_seconds")) is not int or
                not 300 <= caps["model_turn_seconds"] <= 600)) or
            (concurrent_profile and (
                type(caps.get("seed_required_unique")) is not int or
                # Pre-import copy of OriginalGlobalBridge.MAX_STAGED_SEEDS.
                not 1 <= caps["seed_required_unique"] <= 128)) or
            (not concurrent_profile and
             caps.get("seed_required_unique") is not None) or
            (not concurrent_profile and
             concurrent_caps != (False, 1, 1, 1)) or
            caps.get("bounded_nohint_dev") not in (None, False) or
            caps.get("sp_fuzz_seconds", 0) != 0 or
            caps.get("sp_fuzz_max_items", 0) != 0 or
            spec.get("development_scope") is not None or
            spec.get("manual_sp_control") is not None or
            spec.get("sp_fuzz") is not None or
            spec.get("hp_only") is not None or
            (hp_profile and not (
                type(spec.get("hp")) is dict and
                set(spec["hp"]) == {"enabled", "max_items",
                                    "max_model_calls", "assets", "physical"} and
                spec["hp"].get("enabled") is True and
                spec["hp"].get("max_items") == 1 and
                spec["hp"].get("max_model_calls") == 3 and
                type(spec["hp"].get("assets")) is dict and
                type(spec["hp"].get("physical")) is dict)) or
            (not hp_profile and spec.get("hp") != {"enabled": False})):
        raise ValueError("SP-priority Seed scope or opt-in is invalid")
    return True


def _bootstrap(spec_path: Path, spec_sha256: str, *, authorized: bool,
               hp_mode: bool = False, manual_mode: bool = False,
               bounded_hp_mode: bool = False,
               function_name: str | None = None,
               hp_only_mode: bool = False,
               hp_only_function_name: str | None = None,
               check_only: bool = False) -> dict:
    """Pin every import root before importing original/product/evaluation code."""
    if sys.flags.isolated != 1 or sys.flags.no_site != 1:
        raise ValueError("public live development requires python -I -S isolation")
    _consume_sealed_launcher_image()
    if authorized is not True:
        raise ValueError("explicit public development authorization is required")
    if any(name == "fuzzingbrain" or name.startswith("fuzzingbrain.") or
           name == "vulnerabilityanalysis" or
           name.startswith("vulnerabilityanalysis.") or
           name.startswith("dev_global_campaign") for name in sys.modules):
        raise ValueError("live development needs a fresh Python interpreter")
    spec_raw = _plain_pin_bytes(
        spec_path, spec_sha256, "public development spec")
    spec = json.loads(spec_raw)
    if (type(spec) is not dict or spec.get("kind") !=
            "FBV2_ORIGINAL_PUBLIC_DEV_LIVE_SPEC_V1" or
            spec.get("blind3_runs") != 0 or spec.get("oracle_queries") != 0 or
            spec.get("allow_synthetic_wire") is not False):
        raise ValueError("only explicit public development is admitted")
    _verify_signed_sp_runtime(spec, spec_path, spec_sha256)
    _manual_sp_preimport_admission(
        spec, manual_mode=manual_mode, function_name=function_name,
        check_only=check_only)
    _hp_only_preimport_admission(
        spec, hp_only_mode=hp_only_mode,
        function_name=hp_only_function_name, check_only=check_only)
    _sp_fuzz_preimport_admission(spec, check_only=check_only)
    _bounded_nohint_preimport_admission(
        spec, bounded_hp_mode=bounded_hp_mode, check_only=check_only)
    _sp_priority_seed_preimport_admission(spec)
    _parallel_hp_gate_preimport_admission(spec)
    identity = spec["identity"]
    pin_fields = {
        "engine_root": "engine_py_sha256",
        "product_src": "product_py_sha256",
        "evaluation_dir": "evaluation_py_sha256",
    }
    for key, pin_field in pin_fields.items():
        root = Path(identity[key])
        _runtime_tree_pin(root, identity[pin_field],
                          engine=key == "engine_root")
    engine = Path(identity["engine_root"])
    if engine != Path(__file__).resolve().parent.parent:
        raise ValueError("launcher is outside pinned original engine")
    _plain_pin(Path(identity["codex_executable"]),
               identity["codex_executable_sha256"], "Codex executable")
    admission = spec["admission"]
    for key in ("contract", "manifest"):
        _plain_pin(Path(admission[key + "_path"]),
                   admission[key + "_sha256"], key)
    _plain_pin(Path(identity["product_src"]) / "vulnerabilityanalysis" /
               "official_harness.py", admission["product_issuer_sha256"],
               "product V2 qualification issuer")
    _hp_preimport_admission(spec, hp_mode=hp_mode or hp_only_mode or
                            bounded_hp_mode,
                            check_only=check_only)
    return spec


def _require_signed_sp_live(spec: dict, *, ordinary_sp_live: bool) -> None:
    """Close the legacy caller-authorized path for every ordinary SP live run."""
    if ordinary_sp_live and type(spec.get("sp_live_admission")) is not dict:
        raise ValueError(
            "ordinary SP live requires signed SP live admission")


def _install_signed_parallel_hp(bound, spec: dict, *, spec_path: Path,
                                spec_sha256: str) -> None:
    if (not _parallel_sp_hp(spec) or
            type(spec.get("sp_live_admission")) is not dict or
            spec["sp_live_admission"].get("contract_kind") !=
                _signed_sp_kind(spec, "admission") or
            getattr(bound.executor, "parallel_hp_async_factory", None)
                is not None):
        raise ValueError("parallel HP factory admission is invalid")
    from devtools.parallel_hp_analysis import run_parallel_hp_analysis

    async def signed_parallel_hp_factory(strategy, directions):
        return await run_parallel_hp_analysis(
            bound=bound, strategy=strategy, directions=directions,
            hp=spec["hp"], spec_path=spec_path,
            spec_sha256=spec_sha256)

    bound.executor.parallel_hp_async_factory = signed_parallel_hp_factory


def _write_result_once(run_dir: Path, result: dict) -> None:
    """Preserve one final development receipt without replacing evidence."""
    if not run_dir.is_dir() or run_dir.is_symlink():
        return
    path = run_dir / "PUBLIC_DEV_RESULT.json"
    data = (json.dumps(result, sort_keys=True, default=str) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    parent_fd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _hp_only_runtime_preflight(bound, spec: dict, *, spec_path: Path,
                               spec_sha256: str):
    """Run the same complete HP-only approval validation used by live mode."""
    from devtools.original_hp_live_optin import (
        _validate_assumption_lifecycle_live_approval, validate_hp_spec)

    hp_only = spec.get("hp_only")
    if type(hp_only) is not dict:
        return None
    validate_hp_spec(
        spec["hp"], bound.identity.product_src, enabled=True, hp_only=True)
    if (hp_only["source_tree_sha256"] !=
            bound.admission.qualification.source_tree_sha256):
        raise ValueError("HP-only qualified source tree changed")
    catalog = (Path(bound.admission.prepared["prebuild_dir"]) /
               "mongodb" / "functions.json")
    rows = json.loads(catalog.read_bytes())
    if (hashlib.sha256(catalog.read_bytes()).hexdigest() !=
            hp_only["functions_json_sha256"] or
            type(rows) is not list or
            sum(type(row) is dict and
                row.get("name") == hp_only["function_name"] and
                type(row.get("reached_by_fuzzers")) is list and
                bound.executor.fuzzer in row.get("reached_by_fuzzers", [])
                for row in rows) != 1):
        raise ValueError("HP-only qualified function changed")
    if hp_only.get("assumption_evidence_closure") is None:
        return None
    return _validate_assumption_lifecycle_live_approval(
        bound, spec["hp"], hp_only, spec_path=spec_path,
        spec_sha256=spec_sha256)


def _live_result_exit_ok(result: dict, *, hp_required: bool,
                         hp_physical_required: bool = False,
                         parallel_hp_required: bool = False) -> bool:
    if (hp_required and result.get("hp_result", {}).get("status") !=
            "HP_POST_WORKER_COMPLETE"):
        return False
    if (hp_physical_required and result.get("hp_result", {}).get(
            "physical_execution_status") != "COMPLETE"):
        return False
    if parallel_hp_required:
        diagnostic = result.get("parallel_hp_diagnostic")
        if (type(diagnostic) is not dict or
                diagnostic.get("analysis_status") !=
                    "HP_PARALLEL_ANALYSIS_COMPLETE" or
                diagnostic.get("discovery_credit") != "NOT_CREDITED"):
            return False
        outcome = diagnostic.get("analysis_outcome")
        physical_status = diagnostic.get("physical_status")
        if outcome in {"NO_SAFE_ASSUMPTION", "NO_ASSERTION_PROPOSAL"}:
            if physical_status != "NOT_RUN":
                return False
        elif outcome == "ASSERTIONS_PROPOSED_UNVERIFIED":
            if (physical_status not in {
                    "HP_ASSERTION_HANDOFF_COMPLETE",
                    "HP_GUIDED_CRASH_OBSERVED_UNGATED"} or
                    type(diagnostic.get("assertion_observations")) is not dict):
                return False
        else:
            return False
        if (physical_status == "HP_ASSERTION_HANDOFF_COMPLETE" and
                diagnostic["assertion_observations"].get(
                    "guided_crash_observed_ungated") is True):
            return False
        if physical_status == "HP_GUIDED_CRASH_OBSERVED_UNGATED":
            if (diagnostic.get("gate_status") !=
                    "HP_GATE_VERIFIED_DISCOVERY_UNPROVEN" or
                    diagnostic.get("security_gate_credit") !=
                    "HP_GATE_VERIFIED" or
                    diagnostic.get("unprocessed_lead_count") != 0 or
                    diagnostic.get("rejected_lead_count") != 0 or
                    diagnostic.get("pending_lead_count") != 0):
                return False
        elif diagnostic.get("security_gate_credit") != "NOT_CREDITED":
            return False
    return result.get("status") in {
        "PREFLIGHT_READY", "HP_ONLY_PREFLIGHT_READY",
        "HP_ONLY_PHYSICAL_COMPLETE", "EXECUTED_UNVERIFIED",
        "EXECUTED_VERIFIED_EARLY_STOP",
        "EXECUTED_GATE_VERIFIED_DISCOVERY_UNPROVEN",
        "MANUAL_SP_CONTROL_EXECUTED", "MANUAL_SP_CONTROL_NO_CANDIDATE",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--spec-sha256", required=True)
    parser.add_argument("--sp-live-approval", type=Path)
    parser.add_argument("--sp-live-approval-sha256")
    parser.add_argument("--sp-live-public-key", type=Path)
    parser.add_argument("--sp-live-public-key-sha256")
    parser.add_argument("--sp-check-receipt", type=Path)
    parser.add_argument("--sp-check-receipt-sha256")
    parser.add_argument("--sp-live-authorization", type=Path)
    parser.add_argument("--sp-live-authorization-sha256")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--authorize-public-dev", action="store_true")
    mode.add_argument("--authorize-manual-sp-control", action="store_true")
    mode.add_argument("--authorize-public-dev-hp", action="store_true")
    mode.add_argument("--authorize-public-dev-hp-parallel", action="store_true")
    mode.add_argument("--authorize-bounded-nohint-hp", action="store_true")
    mode.add_argument("--authorize-public-dev-hp-only", action="store_true")
    mode.add_argument("--check-only", action="store_true")
    parser.add_argument("--function-name",
                        help="public development manual SP control, never discovery credit")
    parser.add_argument("--hp-only-function-name",
                        help="signed manual HP control, never discovery credit")
    args = parser.parse_args(argv)
    if args.authorize_manual_sp_control and not args.function_name:
        parser.error("--function-name is required for manual SP control")
    if args.function_name and not args.authorize_manual_sp_control:
        parser.error("--function-name is only valid for manual SP control")
    if args.authorize_public_dev_hp_only and not args.hp_only_function_name:
        parser.error("--hp-only-function-name is required for HP-only control")
    if args.hp_only_function_name and not args.authorize_public_dev_hp_only:
        parser.error("--hp-only-function-name is only valid for HP-only control")
    try:
        requested_profile = json.loads(_plain_pin_bytes(
            args.spec, args.spec_sha256, "public development spec"))
    except (OSError, UnicodeError, ValueError, TypeError):
        requested_profile = None
    if (_parallel_sp_hp(requested_profile) and
            not (args.authorize_public_dev_hp_parallel or args.check_only)):
        print(json.dumps({"status": "INCOMPLETE_ADMISSION",
                          "reason": "HP_PARALLEL_EXPLICIT_MODE_REQUIRED",
                          "model_physical_calls": 0}, sort_keys=True))
        return 2
    if (args.authorize_public_dev_hp_parallel and
            not _parallel_sp_hp(requested_profile)):
        print(json.dumps({"status": "INCOMPLETE_ADMISSION",
                          "reason": "HP_PARALLEL_PROFILE_REQUIRED",
                          "model_physical_calls": 0}, sort_keys=True))
        return 2
    # Generic HP remains closed. Only the exact versioned concurrent-SP then
    # post-Worker-HP profile may use this authorization flag.
    if args.authorize_public_dev_hp:
        try:
            requested = json.loads(_plain_pin_bytes(
                args.spec, args.spec_sha256, "public development spec"))
        except BaseException:
            requested = None
        if not _combined_sp_hp(requested):
            print(json.dumps({"status": "INCOMPLETE_ADMISSION",
                              "reason": "HP_LIVE_MODE_NOT_VALIDATED"},
                             sort_keys=True))
            return 2
    # HP-only has a separate signed manual selection and one-shot claim.
    # Its live path still passes the fresh-process bootstrap and HP role,
    # source, builder, model, and physical account checks below.
    try:
        spec = _bootstrap(args.spec, args.spec_sha256,
                          authorized=(args.authorize_public_dev or
                                      args.authorize_manual_sp_control or
                                      args.authorize_public_dev_hp or
                                      args.authorize_public_dev_hp_parallel or
                                      args.authorize_bounded_nohint_hp or
                                      args.authorize_public_dev_hp_only or
                                      args.check_only),
                          hp_mode=(args.authorize_public_dev_hp or
                                   args.authorize_public_dev_hp_parallel),
                          manual_mode=args.authorize_manual_sp_control,
                          function_name=args.function_name,
                          hp_only_mode=args.authorize_public_dev_hp_only,
                          bounded_hp_mode=args.authorize_bounded_nohint_hp,
                          hp_only_function_name=args.hp_only_function_name,
                          check_only=args.check_only)
        if (_parallel_sp_hp(spec) and
                type(spec.get("sp_live_admission")) is not dict):
            raise ValueError("parallel HP requires signed live admission")
        _require_signed_sp_live(
            spec, ordinary_sp_live=(args.authorize_public_dev or
                                    args.authorize_public_dev_hp or
                                    args.authorize_public_dev_hp_parallel))
        sp_optin = None
        sp_claim_sha256 = None
        sp_internal_preflight_sha256 = None
        sp_live_authorization_sha256 = None
        sp_args = (args.sp_live_approval, args.sp_live_approval_sha256,
                   args.sp_live_public_key, args.sp_live_public_key_sha256,
                   args.sp_check_receipt, args.sp_check_receipt_sha256,
                   args.sp_live_authorization,
                   args.sp_live_authorization_sha256)
        if spec.get("sp_live_admission") is not None:
            if (args.authorize_manual_sp_control or
                    args.authorize_bounded_nohint_hp or
                    args.authorize_public_dev_hp_only or
                    not (args.check_only or args.authorize_public_dev or
                         args.authorize_public_dev_hp or
                         args.authorize_public_dev_hp_parallel)):
                raise ValueError("SP signed admission requires ordinary SP mode")
            sp_optin, _ = _verify_sp_approval(
                spec, args.spec_sha256,
                approval_path=args.sp_live_approval,
                approval_sha256=args.sp_live_approval_sha256,
                public_key_path=args.sp_live_public_key,
                public_key_sha256=args.sp_live_public_key_sha256)
            if args.check_only:
                if (args.sp_check_receipt is not None or
                        args.sp_check_receipt_sha256 is not None or
                        args.sp_live_authorization is not None or
                        args.sp_live_authorization_sha256 is not None or
                        Path(sp_optin["check_receipt_path"]).exists() or
                        Path(sp_optin["live_authorization_path"]).exists() or
                        Path(sp_optin["claim_path"]).exists()):
                    raise ValueError("SP check-only is not a fresh first use")
            else:
                _verify_sp_check_receipt(
                    spec, args.spec_sha256, sp_optin,
                    approval_sha256=args.sp_live_approval_sha256,
                    receipt_path=args.sp_check_receipt,
                    receipt_sha256=args.sp_check_receipt_sha256)
                _verify_sp_live_authorization(
                    spec, args.spec_sha256, sp_optin,
                    approval_sha256=args.sp_live_approval_sha256,
                    check_receipt_sha256=args.sp_check_receipt_sha256,
                    authorization_path=args.sp_live_authorization,
                    authorization_sha256=
                        args.sp_live_authorization_sha256)
                sp_live_authorization_sha256 = (
                    args.sp_live_authorization_sha256)
                sp_claim_sha256 = _claim_sp_live_once(
                    spec, args.spec_sha256, sp_optin,
                    approval_sha256=args.sp_live_approval_sha256,
                    check_receipt_sha256=args.sp_check_receipt_sha256,
                    live_authorization_sha256=
                        args.sp_live_authorization_sha256)
                _claim_sp_live_database_once(
                    spec, args.spec_sha256,
                    approval_sha256=args.sp_live_approval_sha256,
                    check_receipt_sha256=args.sp_check_receipt_sha256,
                    live_authorization_sha256=
                        args.sp_live_authorization_sha256)
        elif any(value is not None for value in sp_args):
            raise ValueError("SP admission arguments lack a signed spec opt-in")
    except BaseException as exc:
        print(json.dumps({"status": "INCOMPLETE_ADMISSION",
                          "error_type": type(exc).__name__,
                          "reason": str(exc)}, sort_keys=True))
        return 2
    if (args.check_only and
            not (_combined_sp_hp(spec) or _parallel_sp_hp(spec)) and
            type(spec.get("hp")) is dict and
            spec["hp"].get("enabled") is True and
            spec.get("hp_only") is None and
            spec.get("development_scope") is None):
        print(json.dumps({"status": "INCOMPLETE_ADMISSION",
                          "reason": "HP_LIVE_MODE_NOT_VALIDATED",
                          "hp_preimport_pins_verified": True,
                          "hp_physical_recipe_files_pinned":
                              type(spec["hp"].get("physical")) is dict,
                          "model_physical_calls": 0}, sort_keys=True))
        return 2

    # This witness is created only after this fresh __main__ script checked
    # the external spec/source pins, before loading any engine/product module.
    globals()["_PINNED_PUBLIC_BOOTSTRAP"] = {
        "pid": os.getpid(), "spec_path": str(args.spec),
        "spec_sha256": args.spec_sha256,
        "token": object(), "used": False,
        "engine_py_sha256": spec["identity"]["engine_py_sha256"],
        "product_py_sha256": spec["identity"]["product_py_sha256"],
        "evaluation_py_sha256": spec["identity"]["evaluation_py_sha256"],
        "hp_mode": (args.authorize_public_dev_hp or
                    args.authorize_public_dev_hp_parallel or
                    _combined_sp_hp(spec) or _parallel_sp_hp(spec) or
                    args.authorize_bounded_nohint_hp or
                    args.authorize_public_dev_hp_only),
        "manual_sp_mode": args.authorize_manual_sp_control,
    }

    # A fresh bytecode cache prevents reuse of old pyc bytes from a prior run.
    # All roots are rechecked by the binder after import and before any call.
    with tempfile.TemporaryDirectory(prefix="fbv2-public-import-cache-") as cache:
        sys.pycache_prefix = cache
        identity_row = dict(spec["identity"])
        if args.check_only:
            identity_row["run_dir"] = str(Path(cache) / "preflight-run")
            identity_row["mongo_database"] += "_preflight"
        engine = Path(identity_row["engine_root"])
        product = Path(identity_row["product_src"])
        for root in (engine, product):
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
        from devtools.original_public_dev import admit_pinned
        from devtools.original_public_live import (
            PublicDevCaps, PublicDevIdentity, bind_original_public_dev,
            graceful_public_stop_signals, original_analysis_server_session,
            run_original_public_dev, finalize_public_claim_settlement)

        admission_row = spec["admission"]
        bound = None
        try:
            # No-hint Worker runs model-authored Direction Seed code. Check the
            # pinned local sandbox before model budget is spent. Manual SP and
            # HP-only controls do not enter the Seed phase.
            if _requires_seed_sandbox(spec):
                _preflight_seed_sandbox()
            admitted = admit_pinned(
                product_src=product,
                product_issuer_sha256=admission_row["product_issuer_sha256"],
                contract_path=Path(admission_row["contract_path"]),
                contract_sha256=admission_row["contract_sha256"],
                manifest_path=Path(admission_row["manifest_path"]),
                manifest_sha256=admission_row["manifest_sha256"],
                task_path=Path(identity_row["task_path"]),
                oss_fuzz_checkout=Path(admission_row["oss_fuzz_checkout"]),
                upstream_checkout=Path(admission_row["upstream_checkout"]))
            if sp_optin is not None and not args.check_only:
                _sp_support_rows(spec)
                _lock_task_readonly(
                    Path(identity_row["task_path"]),
                    sp_optin["task_prepared_tree_sha256"])
                _reverify_sp_live_database_claim(
                    spec, args.spec_sha256,
                    approval_sha256=args.sp_live_approval_sha256,
                    check_receipt_sha256=args.sp_check_receipt_sha256,
                    live_authorization_sha256=
                        args.sp_live_authorization_sha256)
            identity = PublicDevIdentity(**{
                key: Path(value) if key in {
                    "engine_root", "product_src", "evaluation_dir",
                    "codex_executable", "task_path", "run_dir"} else value
                for key, value in identity_row.items()})
            caps = PublicDevCaps(**spec["caps"])
            with original_analysis_server_session(admitted, identity) as server:
                bound = bind_original_public_dev(
                    admitted, identity, caps, server=server,
                    bootstrap_token=globals()["_PINNED_PUBLIC_BOOTSTRAP"]["token"],
                    automatic_sp_function_limit=(
                        spec["development_scope"]["sp_functions"]
                        if spec.get("development_scope") is not None else None))
                if sp_optin is not None and not args.check_only:
                    model_snapshot = bound.model_gate.snapshot()
                    process_snapshot = bound.process_ledger.snapshot()
                    if (model_snapshot.get("physical") != 0 or
                            process_snapshot.get("active") not in ([], {}) or
                            bound.global_campaign.ledger is not
                                bound.process_ledger or
                            bound.pov_adapter.ledger is not bound.process_ledger):
                        raise ValueError(
                            "SP live internal zero-call preflight failed")
                    sp_internal_preflight_sha256 = _exclusive_json(
                        Path(sp_optin["internal_preflight_receipt_path"]), {
                            "approval_sha256": args.sp_live_approval_sha256,
                            "check_receipt_sha256":
                                args.sp_check_receipt_sha256,
                            "kind": _signed_sp_kind(
                                spec, "internal_preflight"),
                            "live_authorization_sha256":
                                sp_live_authorization_sha256,
                            "model_calls": 0,
                            "process_active_count": 0,
                            "run_id": spec["identity"]["run_id"],
                            "spec_sha256": args.spec_sha256,
                            "status": "READY_BEFORE_MODEL_OR_TARGET",
                            "target_calls": 0,
                            "task_id": spec["identity"]["task_id"],
                        })
                if _parallel_sp_hp(spec) and not args.check_only:
                    if not args.authorize_public_dev_hp_parallel:
                        raise ValueError("parallel HP requires its explicit live mode")
                    _install_signed_parallel_hp(
                        bound, spec, spec_path=args.spec,
                        spec_sha256=args.spec_sha256)
                if args.check_only:
                    hp_only = spec.get("hp_only")
                    lifecycle_admission = _hp_only_runtime_preflight(
                        bound, spec, spec_path=args.spec,
                        spec_sha256=args.spec_sha256)
                    result = {
                        "status": ("HP_ONLY_PREFLIGHT_READY" if hp_only is not None
                                   else "PREFLIGHT_READY"),
                        "task_id": identity.task_id,
                        "run_id": identity.run_id,
                        "model_physical_calls": bound.model_gate.snapshot()["physical"],
                        "process_wall_seconds": bound.process_ledger.snapshot()
                            ["wall_spent_seconds"],
                        "global_accounted": bound.global_campaign.ledger is
                            bound.process_ledger,
                        "pov_accounted": bound.pov_adapter.ledger is
                            bound.process_ledger,
                        "hp_enabled": (type(spec.get("hp")) is dict and
                                       spec["hp"].get("enabled") is True),
                        "hp_asset_pins_verified": True,
                        "sp_fuzz_enabled": spec.get("sp_fuzz") is not None,
                        "sp_fuzz_seconds_max": caps.sp_fuzz_seconds,
                        "hp_only_manual_control": hp_only is not None,
                        "hp_assumption_lifecycle_scope_verified":
                            lifecycle_admission is not None,
                    }
                    if sp_optin is not None:
                        result["sp_live_approval_verified"] = True
                else:
                    if args.authorize_manual_sp_control:
                        from devtools.manual_sp_control import run_manual_sp_control
                        result = run_manual_sp_control(
                            bound, args.function_name,
                            explicit_public_dev_authorization=True)
                    elif args.authorize_public_dev_hp_only:
                        from devtools.original_hp_live_optin import (
                            run_signed_hp_only)
                        result = run_signed_hp_only(
                            bound, spec["hp"], spec["hp_only"],
                            spec_path=args.spec,
                            spec_sha256=args.spec_sha256)
                    else:
                        with graceful_public_stop_signals(
                                bound,
                                grace_seconds=caps.model_turn_seconds + 30.0):
                            result = run_original_public_dev(
                                bound, explicit_public_dev_authorization=True)
                    if args.authorize_bounded_nohint_hp and result.get(
                            "sp_analysis_status") not in {
                                "COMPLETED",
                                "PARTIAL_LOCAL_OPPORTUNITY_EXHAUSTED"}:
                        result = {**result, "hp_result": {
                            "status": "HP_POST_WORKER_BLOCKED",
                            "reason": "SP_ANALYSIS_NOT_COMPLETED",
                            "security_gate_credit": "NOT_CREDITED"}}
                    elif (args.authorize_public_dev_hp or
                            args.authorize_bounded_nohint_hp):
                        from devtools.original_hp_live_optin import (
                            run_signed_hp_after_worker)
                        try:
                            hp_result = run_signed_hp_after_worker(
                                bound, result, spec["hp"],
                                spec_path=args.spec,
                                spec_sha256=args.spec_sha256)
                        except BaseException as hp_exc:
                            hp_result = {"status": "HP_POST_WORKER_PARTIAL_BLOCKED",
                                         "reason": "HP_SIGNED_EXECUTION_INCOMPLETE",
                                         "error_type": type(hp_exc).__name__,
                                         "sp_global_effect": "UNCHANGED",
                                         "security_gate_credit": "NOT_CREDITED"}
                        result = {**result, "hp_result": hp_result}
                    if result.get("kind") == "FBV2_PUBLIC_DEV_ORIGINAL_RESULT_V1":
                        result = finalize_public_claim_settlement(
                            bound, result,
                            parallel_hp_spec_path=(args.spec if
                                args.authorize_public_dev_hp_parallel else None),
                            parallel_hp_spec_sha256=(args.spec_sha256 if
                                args.authorize_public_dev_hp_parallel else None))
        except BaseException as exc:
            incomplete_reason = getattr(exc, "reason", None)
            result_status = (
                "STOPPED_USER_REQUEST"
                if incomplete_reason in {
                    "user_stop_before_transport", "user_stop_settled"
                } else "INCOMPLETE")
            result = {"status": result_status,
                      "error_type": type(exc).__name__,
                      "reason": str(exc),
                      "claim_settlement_status": "UNPROVEN",
                      "claim_settlement_phase": "ABORTED_BEFORE_FINAL_SETTLEMENT",
                      "active_repository_claim_document_count": None,
                      "task_id": identity_row.get("task_id"),
                      "run_id": identity_row.get("run_id")}
            if isinstance(incomplete_reason, str) and incomplete_reason:
                from fuzzingbrain.worker.pipeline import public_incomplete_reason
                public_reason, internal = public_incomplete_reason(
                    incomplete_reason)
                result["incomplete_reason"] = public_reason
                detail = getattr(exc, "detail", None) or internal
                if detail:
                    # Diagnostic only; never interpreted as a public reason.
                    result["incomplete_reason_internal_detail"] = str(detail)[:256]
            if spec.get("development_scope", {}).get("kind") == "BOUNDED_NOHINT_DEV_V1":
                result["analysis_scope"] = "PARTIAL_SCOPE"
                receipt = (Path(identity_row["run_dir"]) / "worker" /
                           "results" / "BOUNDED_AUTO_SELECTION.json")
                if receipt.is_file() and not receipt.is_symlink():
                    try:
                        content = receipt.read_bytes()
                        selected = json.loads(content)
                        if (len(content) <= 1_000_000 and
                                type(selected) is dict and
                                selected.get("kind") ==
                                    "BOUNDED_NOHINT_SELECTION_V1" and
                                selected.get("status") in {
                                    "PARTIAL_SCOPE", "NO_FUNCTION_SELECTED"} and
                                selected.get("task_id") ==
                                    identity_row.get("task_id") and
                                selected.get("run_id") ==
                                    identity_row.get("run_id") and
                                type(selected.get("selected_functions")) is list and
                                selected.get("function_limit") ==
                                    spec["development_scope"]["sp_functions"] and
                                len(selected["selected_functions"]) <=
                                    spec["development_scope"]["sp_functions"]):
                            result["selection_receipt_path"] = str(receipt)
                            result["selection_receipt_sha256"] = (
                                hashlib.sha256(content).hexdigest())
                            result["selected_function_count"] = len(
                                selected["selected_functions"])
                            result["selection_status"] = selected["status"]
                    except (OSError, UnicodeError, ValueError, TypeError):
                        pass
            if bound is not None:
                try:
                    model = bound.model_gate.snapshot()
                    process = bound.process_ledger.snapshot()
                    result.update({
                        "model_physical_calls": model["physical"],
                        "process_wall_seconds": process["wall_spent_seconds"],
                        "process_fuzz_seconds": process["fuzz_spent_seconds"],
                        "process_stop_status": process["stop_status"],
                        "process_active_count": len(process["active"]),
                        "global_status": (bound.global_campaign.final_result or {})
                            .get("status"),
                    })
                except BaseException as accounting_exc:
                    result["accounting_error_type"] = type(accounting_exc).__name__
        if spec.get("development_seed_scope") is not None:
            result["seed_scope"] = "PARTIAL_SEED_SCOPE"
            result["sp_function_limit"] = None
        if (args.check_only and sp_optin is not None and
                result.get("status") == "PREFLIGHT_READY" and
                result.get("model_physical_calls") == 0):
            receipt = {
                "approval_sha256": args.sp_live_approval_sha256,
                "engine_py_sha256": spec["identity"]["engine_py_sha256"],
                "evaluation_py_sha256": spec["identity"]["evaluation_py_sha256"],
                "kind": _signed_sp_kind(spec, "check"),
                "model_calls": 0,
                "nonce": secrets.token_hex(32),
                "product_py_sha256": spec["identity"]["product_py_sha256"],
                "run_id": spec["identity"]["run_id"],
                "runtime_python_sha256":
                    sp_optin["runtime_python_sha256"],
                "runtime_closure_manifest_sha256":
                    sp_optin["runtime_closure_manifest_sha256"],
                "runtime_closure_supervisor_sha256":
                    sp_optin["runtime_closure_supervisor_sha256"],
                "spec_sha256": args.spec_sha256,
                "status": "PREFLIGHT_READY",
                "target_calls": 0,
                "task_id": spec["identity"]["task_id"],
                "task_prepared_tree_sha256":
                    sp_optin["task_prepared_tree_sha256"],
            }
            receipt_path = Path(sp_optin["check_receipt_path"])
            result["sp_check_only_receipt_path"] = str(receipt_path)
            result["sp_check_only_receipt_sha256"] = _exclusive_json(
                receipt_path, receipt)
        if sp_claim_sha256 is not None:
            result["sp_live_claim_sha256"] = sp_claim_sha256
        if sp_internal_preflight_sha256 is not None:
            result["sp_internal_preflight_receipt_sha256"] = (
                sp_internal_preflight_sha256)
        if sp_live_authorization_sha256 is not None:
            result["sp_live_authorization_sha256"] = (
                sp_live_authorization_sha256)
        try:
            _write_result_once(Path(identity_row["run_dir"]), result)
        except BaseException as receipt_exc:
            result["receipt_error_type"] = type(receipt_exc).__name__
            result["status"] = "INCOMPLETE"
        print(json.dumps(result, sort_keys=True, default=str))
        return 0 if _live_result_exit_ok(
            result, hp_required=(args.authorize_public_dev_hp or
                                 args.authorize_bounded_nohint_hp),
            hp_physical_required=args.authorize_bounded_nohint_hp,
            parallel_hp_required=
                args.authorize_public_dev_hp_parallel) else 1


if __name__ == "__main__":
    raise SystemExit(main())
