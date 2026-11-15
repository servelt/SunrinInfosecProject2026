"""Run real-loop regressions and record every loaded local project module."""
import hashlib
import json
from pathlib import Path
import sys

engine = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2]).resolve()
for path in (engine.parent / "product/src", engine / "devtools", engine):
    sys.path.insert(0, str(path))
import pytest

result = pytest.main([
    "-q", str(engine / "tests/test_actual_verifier_ledger_loop.py"),
    str(engine / "tests/test_campaign_model_gate.py"),
    str(engine / "tests/test_fullscan_client_factory.py"),
    "--junitxml=" + str(output / "combined.junit.xml"),
])
modules = []
foreign = []
for name, module in sorted(sys.modules.items()):
    source = getattr(module, "__file__", None)
    if not source:
        continue
    path = Path(source).resolve()
    if "SunrinInfosecProject2026" not in str(path):
        continue
    modules.append({"module": name, "path": str(path),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    if not path.is_relative_to(engine.parent) and path != Path(__file__).resolve():
        foreign.append(str(path))
(output / "module_origins.json").write_text(json.dumps(
    {"modules": modules, "foreign": foreign, "pytest_exit": result}, indent=2) + "\n")
print("project_modules", len(modules), "foreign", len(foreign))
raise SystemExit(result or bool(foreign))
