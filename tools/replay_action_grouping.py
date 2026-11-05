"""Replay only Action source-effect comparison from a completed run.

Entry discovery, Entry verification, Action discovery, request generation,
original execution, and harness generation are deliberately not rerun.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import time
from pathlib import Path

from harnesscreator.agents.action_selection import (
    ActionGroupDecision, ActionSelectionAgent, ActionSelectionDecision,
    build_action_effect_families,
)
from harnesscreator.analysis.graph import GraphStore
from harnesscreator.llm.codex_app_server import CodexAppServerPool
from harnesscreator.models import (
    ActionActor, AnalysisBundle, ExternalActionSchema, FunctionMetadata,
    ProofStatus, stable_id,
)
from harnesscreator.storage import ArtifactStore


def rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def load_actions(path: Path) -> list[ExternalActionSchema]:
    result = []
    for raw in rows(path):
        raw["status"] = ProofStatus(raw["status"])
        raw["actor"] = ActionActor(raw["actor"])
        result.append(ExternalActionSchema(**raw))
    return result


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path, help="directory containing actions/ and analysis/")
    parser.add_argument("--output", type=Path, help="new output directory; defaults beside the run")
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--dry-run", action="store_true", help="check inputs without LLM calls")
    args = parser.parse_args()
    run = args.run.expanduser().resolve()
    action_path = run / "actions/discovered-semantic.jsonl"
    function_path = run / "analysis/functions.jsonl"
    project_path = run / "project.json"
    for path in (action_path, function_path, project_path):
        if not path.is_file():
            parser.error(f"missing input: {path}")
    project = json.loads(project_path.read_text(encoding="utf-8"))
    source_root = Path(project["source_root"])
    if not source_root.is_dir():
        parser.error(f"source checkout is unavailable: {source_root}")
    actions = load_actions(action_path)
    functions = {raw["function_id"]: FunctionMetadata(**raw)
                 for raw in rows(function_path)}
    graph = GraphStore(AnalysisBundle(functions=functions, edges=[]))
    groups = ActionSelectionAgent._candidate_groups(actions)
    paired = [action for group in groups if len(group) > 1 for action in group]
    print(f"source={run}\nactions={len(actions)} comparison_groups={sum(len(g)>1 for g in groups)} "
          f"singleton_reused={sum(len(g)==1 for g in groups)} model={args.model}", flush=True)
    if args.dry_run:
        return
    if args.workers < 1:
        parser.error("--workers must be positive")

    output = (args.output.expanduser().resolve() if args.output else
              run.parent / (run.name + "-action-group-replay"))
    if output == run or output.is_relative_to(run):
        parser.error("output must be outside the original run")
    digest = hashlib.sha256()
    for path in (action_path, function_path):
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1 << 20), b""):
                digest.update(block)
    digest.update(args.model.encode("utf-8"))
    input_digest = digest.hexdigest()
    store = ArtifactStore(output)
    manifest_path = output / "input-manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("input_digest") != input_digest:
            parser.error("existing output belongs to different Action/source/model inputs")
    elif any(output.iterdir()):
        parser.error(f"output has no resume manifest: {output}")
    else:
        store.write_json("input-manifest.json", {
            "source_run": str(run), "model": args.model,
            "input_digest": input_digest,
        })
    old_selection_path = run / "actions/selection.jsonl"
    old_selection = ({row["action_id"]: row for row in rows(old_selection_path)}
                     if old_selection_path.is_file() else {})
    llm = CodexAppServerPool(cwd=source_root, model=args.model,
                             workers=args.workers)
    try:
        await llm.start()
        agent = ActionSelectionAgent(llm, graph)
        paired_groups = [group for group in groups if len(group) > 1]
        semaphore = asyncio.Semaphore(args.workers)
        finished = 0

        async def review(group: list[ExternalActionSchema]):
            nonlocal finished
            group_id = stable_id("action-group", *sorted(item.action_id for item in group))
            checkpoint = output / "actions/group-checkpoints" / f"{group_id}.json"
            if checkpoint.is_file():
                saved = json.loads(checkpoint.read_text(encoding="utf-8"))
                if saved.get("input_digest") == input_digest:
                    decisions = [ActionSelectionDecision(**item)
                                 for item in saved["decisions"]]
                    result = ActionGroupDecision(**saved["group"])
                    finished += 1
                    print(f"[{finished}/{len(paired_groups)}] cached {group_id} {result.relation}",
                          flush=True)
                    return decisions, result
            async with semaphore:
                started = time.monotonic()
                decisions, result = await agent._review_candidate_group(group)
                if result.reason.startswith("Action grouping unavailable:"):
                    raise RuntimeError(f"{group_id}: {result.reason}")
                store.write_json(Path("actions/group-checkpoints") / f"{group_id}.json", {
                    "input_digest": input_digest,
                    "decisions": decisions, "group": result,
                })
                finished += 1
                print(f"[{finished}/{len(paired_groups)}] {group_id} "
                      f"{result.relation} {time.monotonic()-started:.1f}s", flush=True)
                return decisions, result

        compared = await asyncio.gather(*(review(group) for group in paired_groups))
        decisions = {item.action_id: item for group_decisions, _ in compared
                     for item in group_decisions}
        reviewed = {frozenset(group.action_ids): group for _, group in compared}
        output_groups: list[ActionGroupDecision] = []
        for group in groups:
            ids = [item.action_id for item in group]
            if len(group) > 1:
                output_groups.append(reviewed[frozenset(ids)])
                continue
            action_id = ids[0]
            old = old_selection.get(action_id)
            decision = ActionSelectionDecision(
                action_id, old["disposition"] if old else "KEEP",
                old["reason"] if old else "singleton retained without a new LLM call",
                old["source_evidence"] if old else [],
            )
            decisions[action_id] = decision
            output_groups.append(ActionGroupDecision(
                stable_id("action-group", action_id), ids, "SINGLETON",
                decision.disposition, decision.reason, decision.source_evidence,
            ))
        retained = [item for item in actions
                    if decisions[item.action_id].disposition != "DROP"]
        families, routes = build_action_effect_families(output_groups, retained)
        store.write_jsonl("actions/source-groups.jsonl", output_groups)
        store.write_jsonl("actions/selection.jsonl",
                          [decisions[item.action_id] for item in actions])
        store.write_jsonl("actions/effect-families.jsonl", families)
        store.write_jsonl("actions/input-routes.jsonl", routes)
        store.write_json("summary.json", {
            "source_run": str(run), "model": args.model,
            "original_actions": len(actions), "comparison_groups": len(reviewed),
            "effect_families": len(families), "input_routes": len(routes),
            "shared_effects": sum(len(item.action_ids)>1 for item in families),
            "scope": "Action grouping replay only; no request/runtime/harness verification",
        })
        print(f"result={output / 'summary.json'}", flush=True)
    finally:
        await llm.close()


if __name__ == "__main__":
    asyncio.run(main())
