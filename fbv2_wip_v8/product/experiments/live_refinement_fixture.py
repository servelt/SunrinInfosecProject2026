"""Two-call Codex diagnostic of existing Function Analyzer/Assertion roles.

This is an explicitly non-blind fixture, not a target vulnerability scan.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
import argparse
import json
import yaml

from vulnerabilityanalysis.__main__ import configured_client
from vulnerabilityanalysis.agents import AgentPipeline
from vulnerabilityanalysis.models import Assertion
from vulnerabilityanalysis.scan import run_assertions_for_scan, refine_overstrong_assertions
from vulnerabilityanalysis.workflow import write_json


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path, help="overstrong_assumption fixture folder")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[2]
    fixture = args.fixture.resolve()
    run = (project / "result/vulnerabilityanalysis" /
           (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-assertion-refine-live"))
    (run / "assertions").mkdir(parents=True)
    write_json(run / "run.json", {"run_id": run.name, "fixture": True, "blind": False,
                                  "purpose": "bounded invariant refinement"})
    source, seed, harness = (fixture / "target.c", fixture / "seed", fixture / "harness.c")
    analysis_path = run / "analysis.json"
    write_json(analysis_path, {"function_name": "target",
                               "safe_assumptions": ["value <= 200"],
                               "summary": "fixture premise"})
    original = Assertion("fixture-old", "fixture-worker", "fixture-direction", "target",
                         "target.c:6", "value <= 200", "value <= 200", [],
                         source_function_analysis=str(analysis_path))
    write_json(run / "assertions/proposed.json", [original.__dict__])
    build = ["clang", "-fsanitize=fuzzer,address", "-g", "-O0", "{source}",
             str(harness), "-o", "{binary}"]
    run_assertions_for_scan(run, source, seed, build, ["{binary}", "{input}"])
    config = yaml.safe_load((project / "vulnerabilityanalysis/config/default.yaml").read_text())
    client, roles = configured_client(config, cwd=project, model=None, effort=None,
                                      provider_override="codex")
    async def go():
        async with client:
            pipeline = AgentPipeline(client, role_models=roles,
                                     schema_error_dir=run / "logs")
            return await refine_overstrong_assertions(
                run, pipeline, function_id="target", function_name="target",
                source_file="target.c", source=source.read_text(), original_source=source,
                source_start_line=3, context=[], build_command=build,
                run_command=["{binary}", "{input}"], fuzz_seconds=1,
                max_llm_calls=2)
    try:
        report = asyncio.run(go())
        write_json(run / "model_usage.json", {
            "provider": type(client).__name__, "model_request_counts": client.model_request_counts,
            "refinement": report})
        print(json.dumps({"run": str(run), "status": report["status"],
                          "model_request_counts": client.model_request_counts,
                          "refinement_statuses": [r.get("status") for r in report["refinements"]]}))
    except Exception as exc:
        write_json(run / "experiment_error.json", {"type": type(exc).__name__,
                                                  "message": str(exc),
                                                  "model_request_counts": client.model_request_counts})
        raise


if __name__ == "__main__":
    main()
