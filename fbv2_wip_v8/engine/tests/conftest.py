"""Shared fixtures for FuzzingBrain tests."""

import json
import os
from pathlib import Path
import sys

import pytest
import mongomock

# Tests must exercise the pinned audit-root product and evaluation sources,
# never another checkout on this machine.
AUDIT_ROOT = Path(__file__).resolve().parents[2]
PINNED_SOURCES = (AUDIT_ROOT / "product" / "src", AUDIT_ROOT / "evaluation_tools")
for _source in reversed(PINNED_SOURCES):
    while str(_source) in sys.path:
        sys.path.remove(str(_source))
    sys.path.insert(0, str(_source))

from fuzzingbrain.db.repository import RepositoryManager


def _project_module_origins() -> tuple[dict[str, str], dict[str, str]]:
    """(pinned, foreign) project modules by absolute origin.

    A module is a project module when it is loaded from a file under the
    user's home that is not an installed library. ``foreign`` ones come from a
    checkout other than this audit root.
    """
    home = Path.home().resolve()
    libraries = {Path(p).resolve() for p in (sys.prefix, sys.base_prefix)}
    pinned, foreign = {}, {}
    for name, module in sorted(sys.modules.items()):
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str):
            continue
        path = Path(origin).resolve()
        if path.is_relative_to(AUDIT_ROOT):
            pinned[name] = str(path)  # wherever the audit root lives
            continue
        if (not path.is_relative_to(home) or
                any(path.is_relative_to(lib) for lib in libraries) or
                "site-packages" in path.parts or "dist-packages" in path.parts):
            continue
        foreign[name] = str(path)
    return pinned, foreign


def pytest_sessionfinish(session, exitstatus):
    pinned, foreign = _project_module_origins()
    report = os.environ.get("FBV2_MODULE_ORIGIN_REPORT")
    if report:
        Path(report).write_text(json.dumps(
            {"audit_root": str(AUDIT_ROOT), "pinned": pinned, "foreign": foreign},
            indent=1, sort_keys=True))
    if foreign:
        sys.stderr.write("\nFOREIGN PROJECT MODULES LOADED (not the audit root):\n" +
                         "".join(f"  {k}: {v}\n" for k, v in sorted(foreign.items())))
        session.exitstatus = 1


@pytest.fixture
def mock_db():
    """In-memory MongoDB via mongomock."""
    client = mongomock.MongoClient()
    db = client["fuzzingbrain_test"]
    yield db
    client.close()


@pytest.fixture
def repos(mock_db):
    """RepositoryManager backed by mongomock."""
    return RepositoryManager(mock_db)
