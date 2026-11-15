"""Configured fuzz budget must not be reported as executed exploration."""

import unittest

from vulnerabilityanalysis.scan import summarize_fuzz_execution


class FuzzExecutionSummaryTests(unittest.TestCase):
    def test_disabled_and_skipped_jobs_report_zero_actual_work(self):
        result = summarize_fuzz_execution(120, [], [])
        self.assertEqual(result["configured_limit_seconds"], 120)
        self.assertEqual(result["global"]["ran_jobs"], 0)
        self.assertEqual(result["sp"]["actual_seconds"], 0)
        self.assertEqual(result["assertion"]["actual_seconds"], 0)

    def test_actual_runs_are_separate_by_path_and_status(self):
        windows = [
            {"job": "GLOBAL", "status": "RAN", "started_at": "2026-01-01T00:00:00+00:00",
             "finished_at": "2026-01-01T00:00:03+00:00"},
            {"job": "SP:one", "status": "SKIPPED", "started_at": "2026-01-01T00:00:00+00:00",
             "finished_at": "2026-01-01T00:00:00+00:00"},
            {"job": "SP:two", "status": "RAN", "started_at": "2026-01-01T00:00:04+00:00",
             "finished_at": "2026-01-01T00:00:06+00:00"},
        ]
        result = summarize_fuzz_execution(120, windows, [
            {"status": "RAN", "fuzz_seconds_actual": 1.25}])
        self.assertEqual(result["global"]["actual_seconds"], 3)
        self.assertEqual(result["sp"]["ran_jobs"], 1)
        self.assertEqual(result["sp"]["statuses"], ["RAN", "SKIPPED"])
        self.assertEqual(result["assertion"]["actual_seconds"], 1.25)

    def test_timed_out_fuzzer_still_counts_as_executed(self):
        result = summarize_fuzz_execution(30, [{"job": "GLOBAL", "status": "TIMED_OUT",
            "started_at": "2026-01-01T00:00:00+00:00",
            "finished_at": "2026-01-01T00:00:02+00:00"}], [])
        self.assertEqual(result["global"]["ran_jobs"], 1)
        self.assertEqual(result["global"]["actual_seconds"], 2)


if __name__ == "__main__":
    unittest.main()
