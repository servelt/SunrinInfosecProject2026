"""Late HP feedback must remain visible in the final scan summary."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from vulnerabilityanalysis.scan import _sync_scan_crash_index


class ScanSummarySyncTests(unittest.TestCase):
    def test_fuzzer_observation_is_reported_separately_from_runtime_replay(self):
        with TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "runtime/fuzzer_crashes").mkdir(parents=True)
            (run / "runtime/fuzzer_crashes/crash-unreplayed.json").write_text(json.dumps({
                "status": "PENDING_RUNTIME_REPLAY_AND_TRIAGE"}))
            (run / "scan.json").write_text(json.dumps({
                "observed_crash_ids": [], "verified_crash_ids": [],
                "reanalysis_requests": []}))
            _sync_scan_crash_index(run)
            summary = json.loads((run / "scan.json").read_text())
            self.assertEqual(summary["fuzzer_observed_crash_ids"],
                             ["crash-unreplayed"])
            self.assertEqual(summary["observed_crash_ids"], [])
            self.assertEqual(summary["verified_crash_ids"], [])

    def test_late_pov_and_verified_crash_refresh_counts(self):
        with TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "poc").mkdir()
            (run / "runtime/crashes").mkdir(parents=True)
            (run / "scan.json").write_text(json.dumps({
                "poc_count": 0, "observed_crash_ids": [],
                "verified_crash_ids": [], "reanalysis_requests": []}))
            (run / "poc/pocs.json").write_text(json.dumps([{"poc_id": "late"}]))
            (run / "runtime/crashes/crash-late.json").write_text(json.dumps({
                "independent_verification_status": "VERIFIED", "observations": []}))
            (run / "runtime/reanalysis_requests.json").write_text(json.dumps([
                {"crash_id": "crash-late", "status": "PENDING_NEW_EVIDENCE"}]))
            _sync_scan_crash_index(run)
            summary = json.loads((run / "scan.json").read_text())
            self.assertEqual(summary["poc_count"], 1)
            self.assertEqual(summary["observed_crash_ids"], ["crash-late"])
            self.assertEqual(summary["verified_crash_ids"], ["crash-late"])
            self.assertEqual(len(summary["reanalysis_requests"]), 1)


if __name__ == "__main__":
    unittest.main()
