from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from harnesscreator.analysis import GraphStore, StaticAnalyzer
from harnesscreator.cli import _resolve_oss_fuzz_recipe
from harnesscreator.models import HarnessDraft, HarnessManifest, ProjectSpec
from harnesscreator.runtime.oss_fuzz import (
    _LocalSourceOverlay,
    QuartetOssFuzzVerifierAgent,
    _crash_attribution,
    _debugger_infrastructure_error,
    _install_local_source_overlay,
    _libfuzzer_coverage_values,
    _subprocess_text,
    _target_detect_leaks,
    preflight_oss_fuzz_backend,
)


FIXTURE = Path(__file__).parent / "fixtures" / "c_project"
QUARTET = Path(__file__).parents[2] / "QuartetFuzz" / "QuartetFuzz"


class TimeoutOutputTest(unittest.TestCase):
    def test_decodes_each_timeout_stream_before_concatenation(self) -> None:
        self.assertEqual(
            _subprocess_text(b"stdout\xff") + _subprocess_text("stderr"),
            "stdout\ufffdstderr",
        )
        self.assertEqual(_subprocess_text(None), "")


class FakeQuartetRunner:
    def __init__(self, workspace: Path) -> None:
        self._workspace_dir = workspace
        self.builds: list[tuple[str, str]] = []
        self.run_blobs = 0
        self.reach_checks = 0
        self.fuzz_runs = 0
        self.coverage_runs = 0

    def build(self, code: str, filename: str):
        self.builds.append((code, filename))
        return SimpleNamespace(
            build_ok=True,
            build_error="",
            build_log_tail="",
            binary_name="fixture_fuzzer",
        )

    def run_blob(self, generator_code: str, *, binary_name: str):
        namespace: dict[str, object] = {}
        exec(generator_code, namespace)
        assert isinstance(namespace["generate"](), bytes)
        self.run_blobs += 1
        return {
            "crashed": False,
            "sanitizer": None,
            "output": "#1 INITED cov: 2 ft: 3",
            "exit_code": 0,
            "error": None,
        }

    def check_target_reached(
        self,
        generator_code: str,
        target_function: str,
        *,
        binary_name: str,
    ):
        self.reach_checks += 1
        return {
            "hit": True,
            "functions_hit": [target_function],
            "gdb_output": f"HIT_FUNCTION:{target_function}",
            "error": None,
        }

    def run(self, duration: int, *, binary_name: str):
        self.fuzz_runs += 1
        return SimpleNamespace(
            error=None,
            edges_covered=23,
            features=45,
            corpus_size=4,
            total_executions=1000,
        )

    def coverage(self, binary_name: str, *, fuzz_seconds: int):
        self.coverage_runs += 1
        summary = (
            self._workspace_dir / "build" / "out" / "fixture"
            / "report_target" / binary_name / "linux" / "summary.json"
        )
        summary.parent.mkdir(parents=True, exist_ok=True)
        summary.write_text(json.dumps({
            "data": [{
                "files": [{
                    "filename": "/src/fixture/server.c",
                    "summary": {
                        "lines": {"covered": 12, "count": 100},
                        "functions": {"covered": 3, "count": 10},
                    },
                }]
            }]
        }))
        return SimpleNamespace(
            lines_covered=12,
            lines_total=100,
            lines_pct=12.0,
            branches_covered=4,
            branches_total=20,
            branches_pct=20.0,
            functions_covered=3,
            functions_total=10,
            functions_pct=30.0,
            regions_covered=8,
            regions_total=50,
            regions_pct=16.0,
            error="",
        )

    def cleanup(self) -> None:
        return None


class RaisingReplayRunner(FakeQuartetRunner):
    def run_blob(self, generator_code: str, *, binary_name: str):
        raise RuntimeError("docker transport disappeared")


class OssFuzzBackendTest(unittest.IsolatedAsyncioTestCase):
    def test_preflight_imports_quartet_and_validates_recipe_before_llm_work(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            oss_fuzz = root / "oss-fuzz"
            (oss_fuzz / "infra").mkdir(parents=True)
            (oss_fuzz / "infra" / "helper.py").write_text("# helper\n")
            project_dir = oss_fuzz / "projects" / "fixture"
            project_dir.mkdir(parents=True)
            (project_dir / "Dockerfile").write_text("FROM example\n")
            (project_dir / "build.sh").write_text("#!/bin/sh\n")
            (project_dir / "fixture_fuzzer.c").write_text("/* canonical */\n")
            project = ProjectSpec(
                source_root=FIXTURE,
                output_root=root / "runs",
                verification_backend="oss-fuzz",
                harness_source_filename="fixture_fuzzer.c",
                oss_fuzz_project="fixture",
                oss_fuzz_fuzzer="fixture_fuzzer",
                oss_fuzz_source_path="/src/fixture",
                oss_fuzz_dir=oss_fuzz,
                quartet_root=QUARTET,
            ).normalized()

            result = preflight_oss_fuzz_backend(project, check_docker=False)

        self.assertEqual(
            result["quartet_dynamic_runner"],
            "harness.checker.dynamic.DynamicRunner",
        )
        self.assertTrue(result["canonical_harness"].endswith("fixture_fuzzer.c"))

    async def test_canonical_probe_builds_pinned_source_against_local_overlay_runner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            oss_fuzz = root / "oss-fuzz"
            project_dir = oss_fuzz / "projects" / "fixture"
            project_dir.mkdir(parents=True)
            canonical = "int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }\n"
            (project_dir / "fixture_fuzzer.c").write_text(canonical)
            project = ProjectSpec(
                source_root=FIXTURE,
                output_root=root / "runs",
                verification_backend="oss-fuzz",
                harness_source_filename="fixture_fuzzer.c",
                oss_fuzz_project="fixture",
                oss_fuzz_fuzzer="fixture_fuzzer",
                oss_fuzz_source_path="/src/fixture",
                oss_fuzz_dir=oss_fuzz,
                quartet_root=QUARTET,
            ).normalized()
            backend = QuartetOssFuzzVerifierAgent(
                project,
                GraphStore(StaticAnalyzer(FIXTURE).index()),
            )
            fake = FakeQuartetRunner(root / "worker" / "oss-fuzz")
            backend._runners["__canonical_preflight__"] = fake

            binary = await backend.probe_canonical_build()

        self.assertEqual(binary, "fixture_fuzzer")
        self.assertEqual(fake.builds, [(canonical, "fixture_fuzzer.c")])
        self.assertEqual(fake.run_blobs, 1)

    async def test_canonical_probe_fails_before_agents_when_runtime_is_broken(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            oss_fuzz = root / "oss-fuzz"
            project_dir = oss_fuzz / "projects" / "fixture"
            project_dir.mkdir(parents=True)
            (project_dir / "fixture_fuzzer.c").write_text("/* canonical */\n")
            project = ProjectSpec(
                source_root=FIXTURE,
                output_root=root / "runs",
                verification_backend="oss-fuzz",
                harness_source_filename="fixture_fuzzer.c",
                oss_fuzz_project="fixture",
                oss_fuzz_fuzzer="fixture_fuzzer",
                oss_fuzz_source_path="/src/fixture",
                oss_fuzz_dir=oss_fuzz,
                quartet_root=QUARTET,
            ).normalized()
            backend = QuartetOssFuzzVerifierAgent(
                project,
                GraphStore(StaticAnalyzer(FIXTURE).index()),
            )
            backend._runners["__canonical_preflight__"] = RaisingReplayRunner(
                root / "worker" / "oss-fuzz"
            )

            with self.assertRaisesRegex(
                Exception, "canonical OSS-Fuzz runtime probe failed"
            ):
                await backend.probe_canonical_build()

    async def test_runs_quartet_build_replay_reach_fuzz_and_llvm_cov(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(
            function for function in bundle.functions.values()
            if function.name == "serve_client"
        )
        project = ProjectSpec(
            source_root=FIXTURE,
            output_root=Path(tempfile.gettempdir()) / "hc-oss-test",
            verification_backend="oss-fuzz",
            harness_source_filename="fixture_fuzzer.c",
            oss_fuzz_project="fixture",
            oss_fuzz_fuzzer="fixture_fuzzer",
            oss_fuzz_source_path="/src/fixture",
            quartet_root=QUARTET,
            fuzz_seconds=1,
        ).normalized()
        manifest = HarnessManifest(
            harness_id="h-oss",
            large_feature_id="lf-oss",
            source_file="fixture_fuzzer.c",
            build_target="oss-fuzz:fixture/fixture_fuzzer",
            engine="libfuzzer",
            sanitizers=["address"],
            execution_model="in_process_reset",
            headers=[],
            libraries=[],
            min_size=1,
            max_size=4096,
            dispatch_strategy="one_job_per_feature",
            expected_anchors=[serve.function_id],
            expected_consumers=[],
            variant_count=1,
            variant_targets=[],
            verification_backend="oss-fuzz",
            backend_target="fixture/fixture_fuzzer",
        )
        draft = HarnessDraft(
            manifest=manifest,
            code="int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { return 0; }",
        )
        with tempfile.TemporaryDirectory() as temporary:
            backend = QuartetOssFuzzVerifierAgent(project, graph)
            fake = FakeQuartetRunner(Path(temporary) / "oss-fuzz")
            backend._runners[manifest.harness_id] = fake
            result = await backend.verify(draft, Path(temporary))

        self.assertTrue(result.build_ok)
        self.assertTrue(result.qualified)
        self.assertTrue(result.coverage_grew)
        self.assertEqual(result.backend, "quartet-oss-fuzz")
        self.assertEqual(result.coverage_metrics["functions_covered"], 3)
        self.assertEqual(fake.builds[0][1], "fixture_fuzzer.c")
        self.assertGreaterEqual(fake.run_blobs, 8)
        self.assertEqual(fake.fuzz_runs, 1)
        self.assertEqual(fake.coverage_runs, 1)

    async def test_replay_exception_is_reported_as_infrastructure_not_raised(self) -> None:
        bundle = StaticAnalyzer(FIXTURE).index()
        graph = GraphStore(bundle)
        serve = next(
            function for function in bundle.functions.values()
            if function.name == "serve_client"
        )
        project = ProjectSpec(
            source_root=FIXTURE,
            output_root=Path(tempfile.gettempdir()) / "hc-oss-infra-test",
            verification_backend="oss-fuzz",
            harness_source_filename="fixture_fuzzer.c",
            oss_fuzz_project="fixture",
            oss_fuzz_fuzzer="fixture_fuzzer",
            oss_fuzz_source_path="/src/fixture",
            quartet_root=QUARTET,
            fuzz_seconds=1,
        ).normalized()
        manifest = HarnessManifest(
            harness_id="h-infra",
            large_feature_id="lf-infra",
            source_file="fixture_fuzzer.c",
            build_target="oss-fuzz:fixture/fixture_fuzzer",
            engine="libfuzzer",
            sanitizers=["address"],
            execution_model="in_process_reset",
            headers=[],
            libraries=[],
            min_size=1,
            max_size=64,
            dispatch_strategy="one_job_per_feature",
            expected_anchors=[serve.function_id],
            expected_consumers=[],
            verification_backend="oss-fuzz",
            backend_target="fixture/fixture_fuzzer",
        )
        draft = HarnessDraft(manifest=manifest, code="int LLVMFuzzerTestOneInput(){return 0;}")
        with tempfile.TemporaryDirectory() as temporary:
            backend = QuartetOssFuzzVerifierAgent(project, graph)
            backend._runners[manifest.harness_id] = RaisingReplayRunner(
                Path(temporary) / "oss-fuzz"
            )

            result = await backend.verify(draft, Path(temporary))

        self.assertFalse(result.qualified)
        self.assertEqual(result.reason, "OSS-Fuzz adversarial replay infrastructure failed")
        self.assertIn("docker transport disappeared", result.infrastructure_error or "")
        self.assertEqual(result.harness_faults, [])

    def test_memcached_recipe_is_resolved_without_manual_build_flags(self) -> None:
        fuzzer, source, checkout = _resolve_oss_fuzz_recipe(QUARTET, "memcached", None)
        self.assertEqual(fuzzer, "fuzzer_proxy")
        self.assertEqual(source, "fuzzer_proxy.c")
        self.assertEqual(checkout, "/src/memcached")

    def test_unattributed_signal_is_not_promoted_to_target_bug(self) -> None:
        self.assertEqual(
            _crash_attribution("#0 0x123 in abort ()", "fuzzer_proxy.c"),
            "unknown",
        )
        self.assertEqual(
            _crash_attribution(
                "#0 crash_here at /src/memcached/items.c:12\n"
                "#1 LLVMFuzzerTestOneInput at /src/fuzzer_proxy.c:30\n",
                "fuzzer_proxy.c",
                target_source_path="/src/memcached",
            ),
            "target",
        )
        self.assertEqual(
            _crash_attribution(
                "#0 malloc at /src/llvm-project/compiler-rt/asan_malloc_linux.cpp:67\n"
                "#1 event_new at /src/libevent/event.c:120\n",
                "fuzzer_proxy.c",
                target_source_path="/src/memcached",
                target_source_basenames={"items.c", "memcached.c"},
            ),
            "unknown",
        )

    def test_local_checkout_is_overlaid_before_generated_harness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "items.c").write_text("int local_revision = 7;\n")
            output = source / "runs"
            output.mkdir()
            (output / "large-artifact").write_text("do not copy")
            project_dir = root / "oss-fuzz" / "projects" / "memcached"
            project_dir.mkdir(parents=True)
            (project_dir / "Dockerfile").write_text(
                "FROM gcr.io/oss-fuzz-base/base-builder\n"
                "COPY fuzzer_proxy.c /src/memcached/fuzzer_proxy.c\n"
                "WORKDIR /src/memcached\n"
            )
            _install_local_source_overlay(
                root / "oss-fuzz",
                _LocalSourceOverlay(
                    source_root=source,
                    output_root=output,
                    project="memcached",
                    container_path="/src/memcached",
                    harness_source_filename="fuzzer_proxy.c",
                ),
            )

            copied = project_dir / ".harnesscreator-local-source"
            self.assertEqual((copied / "items.c").read_text(), "int local_revision = 7;\n")
            self.assertFalse((copied / "runs").exists())
            dockerfile = (project_dir / "Dockerfile").read_text()
            self.assertIn(
                "apt-get install -y --no-install-recommends gdb",
                dockerfile,
            )
            self.assertLess(
                dockerfile.index("COPY .harnesscreator-local-source /src/memcached"),
                dockerfile.index("COPY fuzzer_proxy.c /src/memcached/fuzzer_proxy.c"),
            )

    def test_canonical_target_options_control_leak_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "oss-fuzz"
            options = (
                workspace / "build" / "out" / "memcached"
                / "fuzzer_proxy.options"
            )
            options.parent.mkdir(parents=True)
            options.write_text("[libfuzzer]\ndetect_leaks = 0\n")
            runner = SimpleNamespace(_workspace_dir=workspace)
            self.assertFalse(
                _target_detect_leaks(runner, "memcached", "fuzzer_proxy")
            )

    def test_campaign_coverage_growth_can_supply_missing_fixed_seed_baseline(self) -> None:
        values = _libfuzzer_coverage_values(
            "#78 NEW cov: 9 ft: 10\n"
            "#100 pulse cov: 9 ft: 10\n"
            "#200 DONE cov: 10 ft: 11\n"
        )
        self.assertEqual(values, [9, 9, 10])

    def test_missing_container_gdb_is_an_infrastructure_error(self) -> None:
        error = _debugger_infrastructure_error({
            "hit": False,
            "error": None,
            "gdb_output": "bash: line 1: gdb: command not found",
        })
        self.assertIn("infrastructure", error or "")


if __name__ == "__main__":
    unittest.main()
