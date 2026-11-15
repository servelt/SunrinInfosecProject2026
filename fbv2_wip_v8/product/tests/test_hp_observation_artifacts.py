import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from vulnerabilityanalysis.observation_artifacts import (
    file_artifact_observation, triage_artifact_observation)


class TriageArtifactObservationTest(unittest.TestCase):
    def test_file_snapshot_binds_bytes_and_changes_when_file_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "artifact"
            self.assertEqual(file_artifact_observation(path)["status"], "UNAVAILABLE")
            path.write_bytes(b"first")
            first = file_artifact_observation(path)
            self.assertEqual(first["sha256"], hashlib.sha256(b"first").hexdigest())
            self.assertEqual(first["size_bytes"], 5)
            self.assertEqual(first["scope"], "POST_EXECUTION_FILE_SNAPSHOT")
            path.write_bytes(b"second")
            self.assertNotEqual(first["sha256"], file_artifact_observation(path)["sha256"])

    def test_each_classification_is_bound_to_the_bytes_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "triage.json"
            for classification in ("SECURITY_DEFECT_POSSIBLE", "OVERSTRONG_ASSUMPTION",
                                   "INSUFFICIENT_EVIDENCE", "NOT_A_VIOLATION"):
                raw = json.dumps({"classification": classification}).encode()
                path.write_bytes(raw)
                row = triage_artifact_observation(path)
                self.assertEqual(row["classification"], classification)
                self.assertEqual(row["triage_artifact_status"], "AVAILABLE")
                self.assertEqual(row["triage_artifact_sha256"], hashlib.sha256(raw).hexdigest())

    def test_missing_artifact_does_not_invent_a_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            row = triage_artifact_observation(Path(tmp) / "missing.json")
            self.assertEqual(row["triage_artifact_status"], "UNAVAILABLE")
            self.assertIsNone(row["classification"])
            self.assertIsNone(row["triage_artifact_sha256"])

    def test_invalid_artifact_retains_hash_without_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "triage.json"
            for raw in (b"not-json", b"[]", b'{"classification":"VERIFIED"}',
                        b'{"classification":{}}'):
                path.write_bytes(raw)
                row = triage_artifact_observation(path)
                self.assertEqual(row["triage_artifact_status"], "INVALID")
                self.assertIsNone(row["classification"])
                self.assertEqual(row["triage_artifact_sha256"], hashlib.sha256(raw).hexdigest())

    def test_symlink_and_directory_are_not_accepted_as_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "triage.json"
            target.write_text('{"classification":"SECURITY_DEFECT_POSSIBLE"}')
            alias = root / "alias.json"
            alias.symlink_to(target)
            for path in (alias, root):
                self.assertEqual(triage_artifact_observation(path)["triage_artifact_status"],
                                 "UNAVAILABLE")
