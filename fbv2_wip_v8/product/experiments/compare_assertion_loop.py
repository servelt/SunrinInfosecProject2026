"""Bounded, non-blind C fixture comparison for Code-Augur assertion feedback.

The same one-byte input is used in plain and guided campaigns. This checks
mechanics and triage; it is not a vulnerability-discovery benchmark.
"""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import argparse
import json
import subprocess

from vulnerabilityanalysis.assertions import guided_fuzz_assertion
from vulnerabilityanalysis.models import Assertion
from vulnerabilityanalysis.runtime import fuzz_locally


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[2]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = (args.output or project / "result" / "vulnerabilityanalysis" /
              f"{stamp}-assertion-loop-fixture").resolve()
    output.mkdir(parents=True, exist_ok=False)
    result = {"run_id": output.name, "fixture": True, "blind": False,
              "initial_input_hex": "ff", "fuzz_seconds_per_campaign": 2,
              "cases": {}}
    cases = {
        "security_defect_possible": "if (value > 200) { volatile int *p = 0; *p = 1; }",
        "overstrong_assumption": "if (value > 200) return;",
        "insufficient_evidence": "(void)value;",
    }
    for label, statement in cases.items():
        folder = output / label
        folder.mkdir()
        source = folder / "target.c"
        source.write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "void target(const uint8_t *data, size_t size) {\n"
            "  if (!size) return;\n"
            "  size_t value = data[0];\n"
            f"  {statement}\n"
            "}\n", encoding="utf-8")
        harness = folder / "harness.c"
        harness.write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "void target(const uint8_t*, size_t);\n"
            "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n) "
            "{ target(d,n); return 0; }\n", encoding="utf-8")
        seed = folder / "seed"
        seed.write_bytes(b"\xff")
        build = ["clang", "-fsanitize=fuzzer,address", "-g", "-O0", "{source}",
                 str(harness), "-o", "{binary}"]
        baseline = folder / "plain-target"
        built = subprocess.run([part.replace("{source}", str(source)).replace(
            "{binary}", str(baseline)) for part in build], capture_output=True, text=True)
        (folder / "plain-build.log").write_text(built.stdout + built.stderr, encoding="utf-8")
        if built.returncode:
            result["cases"][label] = {"status": "BUILD_FAILED"}
            continue
        corpus = folder / "plain-corpus"
        corpus.mkdir()
        (corpus / "initial-seed").write_bytes(seed.read_bytes())
        plain = fuzz_locally(baseline, corpus, seconds=2, single_process=True)
        (folder / "plain-runtime.json").write_text(
            json.dumps(asdict(plain), ensure_ascii=False, indent=2) + "\n")
        assertion = Assertion(f"fixture-{label}", "fixture-worker", "fixture-direction",
                              "target", "target.c:6", "value <= 200", "value <= 200", [])
        guided = guided_fuzz_assertion(assertion, source, 6, seed, folder / "guided",
                                       build, ["{binary}", "{input}"], seconds=2)
        triage_file = (guided.get("violation_triage") or {}).get("triage_artifact")
        triage = json.loads(Path(triage_file).read_text()) if triage_file else None
        result["cases"][label] = {
            "status": "EXECUTED", "plain_runtime": str(folder / "plain-runtime.json"),
            "plain_exit_code": plain.exit_code, "plain_sanitizer": plain.sanitizer,
            "plain_coverage": plain.coverage,
            "plain_corpus_count": sum(p.is_file() for p in corpus.iterdir()),
            "guided_report": str(folder / "guided/guided_fuzz.json"),
            "guided_status": guided["status"],
            "guided_coverage": guided.get("coverage_feedback"),
            "guided_retained_mutations": guided.get("retained_mutations"),
            "continuation": guided.get("continuation"),
            "violation_triage": triage.get("classification") if triage else "NOT_OBSERVED",
            "security_verdict": triage.get("security_verdict") if triage else "UNKNOWN",
        }
    (output / "comparison.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(output / "comparison.json")


if __name__ == "__main__":
    main()
