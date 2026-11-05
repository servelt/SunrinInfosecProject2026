import json
from pathlib import Path

from harnesscreator.models import (
    RuntimeStepObservation, ScenarioStatus, ScenarioStep, ScenarioWitness,
)
from harnesscreator.runtime.stateafl_seeds import export_stateafl_seeds
from harnesscreator.storage import ArtifactStore

root = Path("/tmp/hc-stateafl-test-20261031")
record = json.loads((root / "replay.json").read_text(encoding="utf-8"))
steps = [
    ScenarioStep(index, f"action-{index}", "entry", request, {}, [])
    for index, request in enumerate(record["requests"])
]
observations = [
    RuntimeStepObservation(
        index, step.action_id, request, response,
        False, "no source-backed success oracle", 0.01,
        response_success=False,
    )
    for index, (step, request, response) in enumerate(zip(
        steps, record["requests"], record["responses"],
    ))
]
witness = ScenarioWitness(
    "stateafl-local-witness", "stateafl-local-scenario", "action-1",
    steps, observations, ["/work/daemon", "19099"], "tcp", None,
    ScenarioStatus.UNPROVEN, "original process replied to both requests",
)
manifest = export_stateafl_seeds(ArtifactStore(root), [witness])
row = manifest["rows"][0]
assert row["seed_path"] is not None, row
seed_dir = root / "in"
seed_dir.mkdir(exist_ok=True)
(seed_dir / "seed.replay").write_bytes((root / row["seed_path"]).read_bytes())
print(json.dumps(row, sort_keys=True))
