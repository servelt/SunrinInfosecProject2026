"""Public, scripted HP refinement control with real Assertion and Guided runs.

The FA/AG responses are fixed evaluation inputs, not model output. This control
tests the existing product's runtime/triage/refinement wiring, never vulnerability
detection, official V2 qualification, or Blind 3 performance.
"""
from __future__ import annotations

import asyncio
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from typing import Any

from vulnerabilityanalysis.models import Assertion, FunctionAnalysis
from vulnerabilityanalysis.runtime import RuntimeExecutor
from vulnerabilityanalysis.scan import run_assertions_for_scan, refine_overstrong_assertions


PREP = Path(__file__).resolve().parents[1]
CLANG = PREP / "review_tools" / "local_clang" / "clang"
OLD = "value <= 200"
REVISED = "value <= 200 || value == 255"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")


class ScriptedHPReanalysis:
    """Two pinned role responses; each role call remains visible in the receipt."""

    def __init__(self, guard_line: int):
        self.guard_line = guard_line
        self.roles: list[str] = []

    async def analyze_function(self, *args: Any, **kwargs: Any) -> FunctionAnalysis:
        self.roles.append("function_analysis")
        return FunctionAnalysis("toy-target", "target", "target.c",
                                "Harness maps each byte into [0,200] or 255",
                                "fuzzer input byte", [], [], [REVISED], [])

    async def generate_assertions(self, *args: Any, **kwargs: Any) -> list[Assertion]:
        self.roles.append("assertion_generator")
        return [Assertion("a-refined", "w", "d", "target",
                          f"target.c:{self.guard_line}", REVISED, REVISED, [])]


def make_public_fixture(output: Path) -> dict[str, Path | int]:
    if output.exists() and any(output.iterdir()):
        raise ValueError("public toy output must start empty")
    output.mkdir(parents=True, exist_ok=True)
    source = output / "target.c"
    source.write_text(
        "#include <stdint.h>\n"
        "void target(unsigned value) {\n"
        "  if (value > 200) return;\n"
        "  volatile unsigned bounded = value;\n"
        "  (void)bounded;\n"
        "}\n", encoding="utf-8")
    harness = output / "fuzz.c"
    harness.write_text(
        "#include <stdint.h>\n#include <stddef.h>\n"
        "void target(unsigned);\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) {\n"
        "  if (n < 1) return 0;\n"
        "  unsigned b = d[0];\n"
        "  unsigned value = b <= 200 ? b : 255;\n"
        "  target(value);\n"
        "  return 0;\n"
        "}\n", encoding="utf-8")
    normal = output / "normal_seed.bin"
    normal.write_bytes(b"\x00")
    injected = output / "injected_violation_control.bin"
    injected.write_bytes(b"\xff")
    guard_line = next(index for index, line in
                      enumerate(source.read_text().splitlines(), 1)
                      if "if (value > 200) return;" in line)
    return {"source": source, "harness": harness, "normal": normal,
            "injected": injected, "guard_line": guard_line}


async def run_control(output: Path, *, fuzz_seconds: int = 1) -> dict[str, Any]:
    if type(fuzz_seconds) is not int or fuzz_seconds < 1 or fuzz_seconds > 2:
        raise ValueError("public toy Guided duration must be 1 or 2 seconds")
    if not CLANG.is_file() or not CLANG.stat().st_mode & 0o111:
        raise FileNotFoundError("pinned local Clang wrapper unavailable")
    fixture = make_public_fixture(output)
    source, harness = fixture["source"], fixture["harness"]
    normal, injected = fixture["normal"], fixture["injected"]
    guard_line = fixture["guard_line"]
    assert isinstance(source, Path) and isinstance(harness, Path)
    assert isinstance(normal, Path) and isinstance(injected, Path)
    assert isinstance(guard_line, int)
    # Prove the revised property for every one-byte Harness input independently
    # of the model and the product's Assertion quality heuristic.
    if not all((b if b <= 200 else 255) <= 200 or
               (b if b <= 200 else 255) == 255 for b in range(256)):
        raise AssertionError("revised toy property does not hold for all inputs")

    run = output / "run"
    (run / "assertions").mkdir(parents=True)
    write_json(run / "run.json", {"run_id": "public-hp-refinement-control",
                                  "scope": "PUBLIC_TOY_SCRIPTED_ROLES_ONLY"})
    analysis = run / "function_analysis.json"
    write_json(analysis, {"function_name": "target", "safe_assumptions": [OLD],
                          "input_sources": ["external fuzzer byte value"],
                          "security_sensitive_operations": []})
    original = Assertion("a-original", "w", "d", "target",
                         f"target.c:{guard_line}", OLD, OLD, [])
    original.source_function_analysis = str(analysis)
    write_json(run / "assertions" / "proposed.json", [asdict(original)])
    build = [str(CLANG), "-fsanitize=fuzzer,address", "-g", "-O0",
             "{source}", str(harness), "-o", "{binary}"]
    command = ["{binary}", "{input}"]
    old_outcomes = run_assertions_for_scan(
        run, source, injected, build, command, fuzz_seconds=fuzz_seconds)
    if len(old_outcomes) != 1 or old_outcomes[0].status != "VIOLATED":
        raise AssertionError("original scripted Assertion did not violate")
    old_runtime = Path(old_outcomes[0].execution_result or "")
    old_triage = json.loads((old_runtime.parent / "triage.json").read_text())
    if old_triage.get("classification") != "OVERSTRONG_ASSUMPTION":
        raise AssertionError("benign source-reviewed violation was not confirmed")
    original_binary = old_runtime.parent / "original-target"
    executor = RuntimeExecutor(timeout_seconds=20)
    original_replays = {}
    for label, seed in (("normal", normal), ("injected", injected)):
        replay = executor.run([str(original_binary), "{input}"], seed)
        replay_record = {
            "kind": "PUBLIC_TOY_ORIGINAL_REPLAY",
            "binary_sha256": digest(original_binary),
            "exit_code": replay.exit_code,
            "sanitizer": replay.sanitizer,
            "input_sha256": digest(seed),
        }
        replay_path = output / f"original_{label}_replay.json"
        write_json(replay_path, replay_record)
        original_replays[label] = {
            **replay_record,
            "runtime_artifact": str(replay_path.relative_to(output)),
        }
        if replay.exit_code != 0 or replay.sanitizer:
            raise AssertionError("original public toy replay was not clean")

    roles = ScriptedHPReanalysis(guard_line)
    refinement = await refine_overstrong_assertions(
        run, roles, function_id="toy-target", function_name="target",
        source_file="target.c", source=source.read_text(),
        original_source=source, source_start_line=2, context=[],
        build_command=build, run_command=command,
        fuzz_seconds=fuzz_seconds, max_llm_calls=2,
        harness_source=harness.read_text(), harness_source_path=harness)
    if roles.roles != ["function_analysis", "assertion_generator"] or \
            refinement.get("llm_calls") != 2:
        raise AssertionError("scripted HP role accounting changed")
    lineages = refinement.get("refinements", [])
    if len(lineages) != 1:
        raise AssertionError("expected one source-reviewed refinement lineage")
    lineage = lineages[0]
    if lineage.get("status") != "REFINED_AND_TESTED":
        raise AssertionError("revised Assertion did not pass product checks")
    revisions = lineage.get("revisions", [])
    if len(revisions) != 1:
        raise AssertionError("expected exactly one revised Assertion runtime")
    revision = revisions[0]
    guided_path = Path(revision.get("guided_fuzz") or "")
    if not guided_path.is_file():
        raise AssertionError("second real Guided report missing")
    guided = json.loads(guided_path.read_text())
    if guided.get("status") != "RAN":
        raise AssertionError("second real Guided job did not run")
    revised_runtime = json.loads(Path(revision["runtime"]).read_text())
    if revised_runtime.get("exit_code") != 0 or revised_runtime.get("sanitizer"):
        raise AssertionError("revised Assertion did not hold for injected control")

    first_guided_paths = sorted((run / "assertions" / "a-original").glob(
        "executions/*/guided_fuzz/guided_fuzz.json"))
    if len(first_guided_paths) != 1:
        raise AssertionError("first real Guided report missing")
    first_guided = json.loads(first_guided_paths[0].read_text())
    if (first_guided.get("status") != "ASSERTION_WITNESS_OBSERVED" or
            not first_guided.get("violation_witnesses") or
            (first_guided.get("violation_triage") or {}).get("assertion_status") != "VIOLATED"):
        raise AssertionError("first real Guided job did not produce a triaged witness")

    pins = {str(path.relative_to(output)): digest(path)
            for path in (source, harness, normal, injected)}
    # Hash every generated evidence file, including instrumented source,
    # binaries, corpus, analysis/proposal, triage and both Guided jobs. The
    # receipt itself is created only after this map is final.
    root = output.resolve()
    all_paths = list(output.rglob("*"))
    if any(path.is_symlink() or not path.resolve().is_relative_to(root)
           for path in all_paths):
        raise ValueError("public toy evidence contains a symlink or external path")
    evidence_files = sorted(path for path in all_paths if path.is_file())
    artifacts = {str(path.relative_to(output)): digest(path)
                 for path in evidence_files if path not in (source, harness, normal, injected)}
    receipt = {
        "kind": "PUBLIC_TOY_HP_SCRIPTED_REFINEMENT_CONTROL_V2",
        "status": "CONTROLLED_POSITIVE_ONLY",
        "model_calls": 0,
        "oracle_opened": False,
        "vulnerability_verified": False,
        "source_and_input_sha256": pins,
        "artifact_sha256": artifacts,
        "clang_wrapper_sha256": digest(CLANG),
        "guard_line": guard_line,
        "first_assertion": {"status": old_outcomes[0].status,
                            "triage": old_triage["classification"],
                            "guided_artifact": str(first_guided_paths[0].relative_to(output)),
                            "guided_status": first_guided["status"],
                            "guided_physical_seconds": first_guided.get("fuzz_seconds_actual")},
        "reanalysis_roles": roles.roles,
        "revised_assertion": {"status": revision["assertion"]["status"],
                              "guided_artifact": str(guided_path.relative_to(output)),
                              "guided_status": guided["status"],
                              "guided_physical_seconds": guided.get("fuzz_seconds_actual")},
        "original_replays": original_replays,
        "limitation": "Fixed FA/AG answers and an injected violating seed; not autonomous model/Fuzzer discovery",
    }
    write_json(output / "CONTROL_RECEIPT.json", receipt)
    return receipt


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    receipt = asyncio.run(run_control(args.output))
    print(json.dumps({"status": receipt["status"],
                      "first": receipt["first_assertion"],
                      "second": receipt["revised_assertion"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
