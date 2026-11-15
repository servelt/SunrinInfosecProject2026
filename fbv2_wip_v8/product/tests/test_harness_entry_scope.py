"""Provider-free HarnessCreator -> VA entry/feature contract regression."""

import json
import tempfile
import unittest
from pathlib import Path

from vulnerabilityanalysis.adapter import HarnessAdapter
from vulnerabilityanalysis.scheduler import build_directions, build_workers


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _jsonl(path: Path, values: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in values), encoding="utf-8")


class HarnessEntryScopeTest(unittest.TestCase):
    def test_feature_entry_ids_resolve_without_other_harness_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write(root / "project.json", {})
            functions = [
                ("fn-a1", "entry_a1"), ("fn-a2", "entry_a2"),
                ("fn-b", "entry_b"), ("fn-ca1", "core_a1"),
                ("fn-ca2", "core_a2"), ("fn-cb", "core_b"),
            ]
            _jsonl(root / "analysis/functions.jsonl", [
                {"function_id": fid, "name": name, "file": "target.c"}
                for fid, name in functions
            ])
            _jsonl(root / "analysis/edges.jsonl", [
                {"caller_id": "fn-a1", "callee_id": "fn-ca1"},
                {"caller_id": "fn-a2", "callee_id": "fn-ca2"},
                {"caller_id": "fn-b", "callee_id": "fn-cb"},
            ])
            _jsonl(root / "entries/verified-final.jsonl", [
                {"entry_id": "entry-a1", "entry_function_id": "fn-a1"},
                {"entry_id": "entry-a2", "entry_function_id": "fn-a2"},
                {"entry_id": "entry-b", "entry_function_id": "fn-b"},
            ])
            for sf, eid, core in [
                ("sf-a1", "entry-a1", "fn-ca1"),
                ("sf-a2", "entry-a2", "fn-ca2"),
                ("sf-b", "entry-b", "fn-cb"),
            ]:
                _write(root / f"features/small/{sf}.json", {
                    "small_feature_id": sf, "name": sf,
                    "root_entries": [eid], "required_functions": [core],
                })
            for lf, members in [("lf-a", ["sf-a1", "sf-a2"]), ("lf-b", ["sf-b"])]:
                _write(root / f"features/large/{lf}.json", {
                    "large_feature_id": lf, "name": lf,
                    "small_feature_ids": members, "required_functions": [],
                })
            for label, lf in [("a", "lf-a"), ("b", "lf-b")]:
                folder = root / f"harnesses/{label}/attempt-1"
                folder.mkdir(parents=True)
                (folder / "fuzz.c").write_text("void fuzz(void) {}\n", encoding="utf-8")
                _write(folder / "manifest.json", {
                    "harness_id": label, "large_feature_id": lf,
                    "source_file": "fuzz.c", "sanitizers": ["address"],
                })

            first = HarnessAdapter().load(root / "harnesses/a/attempt-1")
            second = HarnessAdapter().load(root / "harnesses/b/attempt-1")
            self.assertEqual(first.entry_functions, ["entry_a1", "entry_a2"])
            self.assertEqual(second.entry_functions, ["entry_b"])
            directions = build_directions(first, build_workers(first)[0])
            self.assertEqual({item.name for item in directions}, {"sf-a1", "sf-a2"})
            self.assertEqual(
                {item.name: item.entry_functions for item in directions},
                {"sf-a1": ["entry_a1"], "sf-a2": ["entry_a2"]},
            )


if __name__ == "__main__":
    unittest.main()
