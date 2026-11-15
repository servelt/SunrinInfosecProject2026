"""Selection-stage receipt must follow real per-Worker continuation semantics."""

from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from review_tools.freeze_selection_stage import freeze_selection
from vulnerabilityanalysis.adapter import HarnessAdapter
from vulnerabilityanalysis.models import FunctionPoolItem
import vulnerabilityanalysis.scheduler as scheduler_module


PRODUCT = (Path(__file__).resolve().parents[1] / "product")


class FreezeSelectionStageTests(unittest.TestCase):
    def test_same_worker_function_in_two_directions_uses_one_selection(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            phase = root / "phase"
            phase.mkdir()
            artifact = root / "artifact"
            artifact.mkdir()
            (phase / "run.json").write_text(json.dumps({
                "artifact": str(artifact), "harness_id": "h"}))
            (phase / "directions.json").write_text(json.dumps([
                {"direction_id": "d1", "worker_id": "w"},
                {"direction_id": "d2", "worker_id": "w"},
            ]))
            pool = [
                FunctionPoolItem("fn-a", "A", None, "d1", "CORE", None),
                FunctionPoolItem("fn-a", "A", None, "d2", "RELATED", None),
                FunctionPoolItem("fn-b", "B", None, "d2", "RELATED", None),
            ]
            (phase / "function_pool.json").write_text(json.dumps([asdict(x) for x in pool]))
            (phase / "selection.json").write_text(json.dumps({
                "function_id": "fn-a", "direction_id": "d1"}))
            private = root / "private"
            private.mkdir(mode=0o700)
            output = private / "selection.json"
            with patch.object(HarnessAdapter, "load",
                              return_value=SimpleNamespace(harness_id="h")), \
                 patch.object(scheduler_module, "source_evidence_for_pool", return_value={}):
                receipt = freeze_selection(phase, root, PRODUCT, output)
            frozen = json.loads(output.read_text())
            self.assertEqual(frozen["pool_count"], 3)
            self.assertEqual(frozen["unique_worker_function_count"], 2)
            self.assertEqual(receipt["selected_count"], 2)
            self.assertEqual([row["function_id"] for row in frozen["selected_order"]],
                             ["fn-a", "fn-b"])


if __name__ == "__main__":
    unittest.main()
