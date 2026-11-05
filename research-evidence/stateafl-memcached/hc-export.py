import json
from pathlib import Path

from harnesscreator.models import (
    RuntimeStepObservation, ScenarioStatus, ScenarioStep, ScenarioWitness,
)
from harnesscreator.runtime.stateafl_seeds import export_stateafl_seeds
from harnesscreator.storage import ArtifactStore


root = Path("/tmp/hc-memcached-stateafl-20261031")
record = json.loads((root / "hc-replay.json").read_text(encoding="utf-8"))
steps = [
    ScenarioStep(index, f"action-{index}", "entry", request, {}, [])
    for index, request in enumerate(record["requests"])
]
observations = [
    RuntimeStepObservation(
        index, step.action_id, request, response,
        False, "response observed without request-attributed source proof", 0.01,
        response_success=False,
    )
    for index, (step, request, response) in enumerate(zip(
        steps, record["requests"], record["responses"],
    ))
]
witness = ScenarioWitness(
    "memcached-stateafl-local-witness", "memcached-stateafl-local-scenario",
    "action-1", steps, observations,
    ["/work/memcached", "-u", "root", "-p", "19099", "-U", "0",
     "-l", "127.0.0.1", "-t", "1", "-m", "16"],
    "tcp", None, ScenarioStatus.UNPROVEN,
    "original memcached replied to both requests; handler attribution unproven",
)
row = export_stateafl_seeds(ArtifactStore(root), [witness])["rows"][0]
assert row["seed_path"] is not None, row
seed_dir = root / "hc-seed-in"
seed_dir.mkdir(exist_ok=True)
(seed_dir / "seed.replay").write_bytes((root / row["seed_path"]).read_bytes())
print(json.dumps(row, sort_keys=True))
