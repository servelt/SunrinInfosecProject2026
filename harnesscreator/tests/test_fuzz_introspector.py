from pathlib import Path
import tempfile
import unittest

from harnesscreator.analysis import FuzzIntrospectorRunner, StaticAnalyzer
from harnesscreator.analysis.fuzz_introspector import default_fi_cache_root


FIXTURE = Path(__file__).parent / "fixtures" / "c_project"


class FuzzIntrospectorRunnerTest(unittest.TestCase):
    def test_default_cache_follows_source_not_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "source"
            other = Path(temporary) / "other"
            source.mkdir()
            other.mkdir()
            self.assertEqual(
                default_fi_cache_root(source),
                default_fi_cache_root(source / ".." / "source"),
            )
            self.assertNotEqual(
                default_fi_cache_root(source), default_fi_cache_root(other),
            )

    def test_source_inventory_excludes_run_artifacts_and_keeps_cpp(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "source"
            root.mkdir()
            source = root / "listener.c++"
            source.write_text("int listener(void) { return 1; }\n")
            discarded = root / "runs-old" / "nested"
            discarded.mkdir(parents=True)
            (discarded / "fake.c").write_text("int fake(void) { return 0; }\n")

            files = FuzzIntrospectorRunner(root, Path(temporary) / "cache")._source_files()

            self.assertEqual(files, [source.resolve()])

    def test_automatically_generates_and_reuses_partial_report(self) -> None:
        import importlib.metadata
        try:
            importlib.metadata.version('fuzz-introspector')
        except importlib.metadata.PackageNotFoundError:
            self.skipTest('Fuzz Introspector is not installed in this test environment')
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
        self.assertFalse(bundle.completeness["authoritative"])
        self.assertEqual(bundle.completeness["callers"], "partial")
        self.assertEqual(
            bundle.completeness["fuzz_introspector_mode"], "build-free-c-cpp"
        )
        self.assertEqual(bundle.completeness["fuzz_introspector_version"], first.version)


if __name__ == "__main__":
    unittest.main()
