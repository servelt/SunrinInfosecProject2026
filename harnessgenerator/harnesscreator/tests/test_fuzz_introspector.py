from pathlib import Path
import tempfile
import unittest

from harnesscreator.analysis import FuzzIntrospectorRunner, StaticAnalyzer


FIXTURE = Path(__file__).parent / "fixtures" / "c_project"


class FuzzIntrospectorRunnerTest(unittest.TestCase):
    def test_automatically_generates_and_reuses_authoritative_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            cache = Path(temporary) / "fi-cache"
            first = FuzzIntrospectorRunner(FIXTURE, cache).run()
            second = FuzzIntrospectorRunner(FIXTURE, cache).run()
            bundle = StaticAnalyzer(
                FIXTURE,
                first.report,
                require_fuzz_introspector=True,
            ).index()

        self.assertTrue(first.report.name.endswith(".data.yaml"))
        self.assertFalse(first.cache_hit)
        self.assertTrue(second.cache_hit)
        self.assertEqual(first.report, second.report)
        self.assertTrue(bundle.completeness["fuzz_introspector_used"])
        self.assertTrue(bundle.completeness["authoritative"])
        self.assertEqual(bundle.completeness["callers"], "reported")
        self.assertEqual(
            bundle.completeness["fuzz_introspector_mode"], "build-free-c-cpp"
        )
        self.assertEqual(bundle.completeness["fuzz_introspector_version"], first.version)


if __name__ == "__main__":
    unittest.main()
