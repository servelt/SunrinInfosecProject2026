"""Native OSS-Fuzz integration tests. No QuartetFuzz code is imported."""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from harnesscreator.analysis import GraphStore, StaticAnalyzer
from harnesscreator.models import (
    CommandReport, HarnessDraft, HarnessManifest, ProjectSpec, SeedSpec,
)
from harnesscreator.runtime.oss_fuzz import (
    NativeOssFuzzVerifierAgent, OssFuzzBackendError, preflight_oss_fuzz_backend,
)

FIXTURE = Path(__file__).parent / 'fixtures' / 'c_project'


class FakeRunner:
    def __init__(self, fail_on: str = ''):
        self.argvs: list[list[str]] = []
        self.fail_on = fail_on

    async def run(self, argv: list[str], **kwargs):
        self.argvs.append(argv)
        assert kwargs['timeout_seconds'] > 0
        result = 1 if self.fail_on and self.fail_on in argv else 0
        return CommandReport(
            argv=argv, returncode=result, stdout='ok', stderr='error' if result else '',
            duration_seconds=0.1,
        )


def make_project(root: Path) -> ProjectSpec:
    oss = root / 'oss-fuzz'
    (oss / 'infra').mkdir(parents=True)
    (oss / 'infra' / 'helper.py').write_text('# trusted helper placeholder\n')
    project = oss / 'projects' / 'fixture'
    project.mkdir(parents=True)
    (project / 'Dockerfile').write_text('FROM example\nWORKDIR /src/fixture\n')
    (project / 'build.sh').write_text('#!/bin/sh\n')
    (project / 'fixture_fuzzer.c').write_text(
        '#include <stddef.h>\nint LLVMFuzzerTestOneInput(const unsigned char *p, size_t n) {return 0;}\n'
    )
    return ProjectSpec(
        source_root=FIXTURE, output_root=root / 'runs',
        verification_backend='oss-fuzz', oss_fuzz_dir=oss,
        oss_fuzz_project='fixture', oss_fuzz_fuzzer='fixture_fuzzer',
        oss_fuzz_source_path='/src/fixture', harness_source_filename='fixture_fuzzer.c',
    ).normalized()


def make_draft() -> HarnessDraft:
    return HarnessDraft(
        manifest=HarnessManifest(
            harness_id='harness-01', source_file='fixture_fuzzer.c',
            build_target='oss-fuzz:fixture/fixture_fuzzer', engine='libfuzzer',
            sanitizers=['address'], execution_model='in_process_reset',
            headers=[], libraries=[], min_size=1, max_size=64,
            dispatch_strategy='one_scenario_per_harness', expected_anchors=[],
            expected_consumers=[], verification_backend='oss-fuzz',
        ),
        code='#include <stddef.h>\nint LLVMFuzzerTestOneInput(const unsigned char *p, size_t n) {return (int)(n<1);}\n',
    )


class NativeOssFuzzTests(unittest.IsolatedAsyncioTestCase):
    async def test_preflight_requires_only_official_oss_fuzz_recipe(self):
        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            result = preflight_oss_fuzz_backend(project, check_docker=False)
            self.assertEqual(result['backend'], 'harnesscreator-native-oss-fuzz')
            self.assertEqual(result['docker_server_version'], 'not checked')
            self.assertNotIn('quartet', str(result).lower())

    async def test_preflight_rejects_missing_real_fuzzer_source(self):
        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            (project.oss_fuzz_dir / 'projects' / 'fixture' / 'fixture_fuzzer.c').unlink()
            with self.assertRaisesRegex(OssFuzzBackendError, 'missing'):
                preflight_oss_fuzz_backend(project, check_docker=False)

    async def test_generated_source_isolated_from_original_project(self):
        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            backend = NativeOssFuzzVerifierAgent(project, GraphStore(StaticAnalyzer(FIXTURE).index()))
            canonical = project.oss_fuzz_dir / 'projects' / 'fixture' / 'fixture_fuzzer.c'
            before = canonical.read_bytes()
            temp = Path(td) / 'worker'
            copy = backend._temporary_project(temp, 'REPLACED\n')
            self.assertEqual((copy / 'fixture_fuzzer.c').read_text(), 'REPLACED\n')
            self.assertEqual(canonical.read_bytes(), before)
            self.assertNotEqual(copy, canonical)

    async def test_external_recipe_compatibility_uses_original_dockerfile(self):
        # OSS-Fuzz helper.py with --external resolves Dockerfile and build.sh
        # inside .clusterfuzzlite, not at the root of an in-tree OSS-Fuzz recipe.
        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            canonical = project.oss_fuzz_dir / 'projects' / 'fixture'
            (canonical / 'project.yaml').write_text('language: c\n')
            backend = NativeOssFuzzVerifierAgent(
                project, GraphStore(StaticAnalyzer(FIXTURE).index())
            )
            before = {name: (canonical / name).read_bytes()
                      for name in ('Dockerfile', 'build.sh', 'project.yaml',
                                   'fixture_fuzzer.c')}
            temporary = backend._temporary_project(Path(td) / 'work', 'GENERATED\n')
            integration = temporary / '.clusterfuzzlite'
            for name in ('Dockerfile', 'build.sh', 'project.yaml'):
                self.assertEqual((integration / name).read_bytes(), before[name])
            # Docker keeps using the recipe root as its COPY build context.
            self.assertEqual((temporary / 'Dockerfile').read_bytes(), before['Dockerfile'])
            self.assertEqual((temporary / 'build.sh').read_bytes(), before['build.sh'])
            self.assertEqual((temporary / 'fixture_fuzzer.c').read_text(), 'GENERATED\n')
            for name, original in before.items():
                self.assertEqual((canonical / name).read_bytes(), original)
            self.assertFalse((canonical / '.clusterfuzzlite').exists())

    async def test_external_recipe_compatibility_without_project_yaml(self):
        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            backend = NativeOssFuzzVerifierAgent(
                project, GraphStore(StaticAnalyzer(FIXTURE).index())
            )
            destination = backend._temporary_project(Path(td) / 'work', 'code')
            self.assertTrue((destination / '.clusterfuzzlite' / 'Dockerfile').is_file())
            self.assertTrue((destination / '.clusterfuzzlite' / 'build.sh').is_file())
            self.assertFalse((destination / '.clusterfuzzlite' / 'project.yaml').exists())

    async def test_canonical_probe_uses_official_helper_and_never_quartet(self):
        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            runner = FakeRunner()
            backend = NativeOssFuzzVerifierAgent(
                project, GraphStore(StaticAnalyzer(FIXTURE).index()), runner=runner
            )
            # Avoid requiring Docker while checking CLI structure.
            import unittest.mock as mock
            with mock.patch('harnesscreator.runtime.oss_fuzz.preflight_oss_fuzz_backend',
                            return_value={'backend': 'native'}):
                name = await backend.probe_canonical_build()
            self.assertEqual(name, 'fixture_fuzzer')
            self.assertEqual(len(runner.argvs), 1)
            command = runner.argvs[0]
            self.assertIn('build_fuzzers', command)
            self.assertIn('--external', command)
            self.assertIn('--mount_path', command)
            self.assertIn('/src/fixture', command)
            self.assertNotIn('quartet', ' '.join(command).lower())

    async def test_build_only_does_not_claim_runtime_qualification(self):
        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            runner = FakeRunner()
            backend = NativeOssFuzzVerifierAgent(
                project, GraphStore(StaticAnalyzer(FIXTURE).index()), runner=runner
            )
            import unittest.mock as mock
            with mock.patch('harnesscreator.runtime.oss_fuzz.preflight_oss_fuzz_backend',
                            return_value={'backend': 'native'}):
                result = await backend.verify(make_draft(), Path(td) / 'attempt', runtime_checks=False)
            self.assertTrue(result.build_ok)
            self.assertFalse(result.qualified)
            self.assertIsNone(result.fuzz)
            self.assertIn('build-only', result.reason)
            self.assertEqual(len(runner.argvs), 1)

    async def test_exploratory_replay_uses_only_witness_seed_and_never_fuzzes(self):
        import unittest.mock as mock
        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            runner = FakeRunner()
            backend = NativeOssFuzzVerifierAgent(
                project, GraphStore(StaticAnalyzer(FIXTURE).index()), runner=runner,
            )
            witness = SeedSpec('observed', b'GET key\r\n'.hex(), 'original request')
            with mock.patch('harnesscreator.runtime.oss_fuzz.preflight_oss_fuzz_backend',
                            return_value={'backend': 'native'}):
                result = await backend.verify(
                    make_draft(), Path(td) / 'attempt', [witness], replay_only=True,
                )
            self.assertTrue(result.build_ok)
            self.assertFalse(result.qualified)
            self.assertIsNone(result.fuzz)
            self.assertEqual(len(result.replays), 2)  # check_build + one reproduce
            self.assertEqual([argv[2] for argv in runner.argvs],
                             ['build_fuzzers', 'check_build', 'reproduce'])
            self.assertEqual((Path(td) / 'attempt' / 'seeds' / 'llm-observed').read_bytes(),
                             b'GET key\r\n')

    async def test_exploratory_replay_without_seed_stops_after_build_check(self):
        import unittest.mock as mock
        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            runner = FakeRunner()
            backend = NativeOssFuzzVerifierAgent(project, graph=None, runner=runner)
            with mock.patch('harnesscreator.runtime.oss_fuzz.preflight_oss_fuzz_backend',
                            return_value={'backend': 'native'}):
                result = await backend.verify(
                    make_draft(), Path(td) / 'attempt', [], replay_only=True,
                )
            self.assertFalse(result.qualified)
            self.assertIn('no in-range witnessed request', result.reason)
            self.assertEqual([argv[2] for argv in runner.argvs],
                             ['build_fuzzers', 'check_build'])

    async def test_existing_harness_verifier_agent_owns_native_backend(self):
        from harnesscreator.runtime.runner import HarnessVerifierAgent
        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            runner = FakeRunner()
            verifier = HarnessVerifierAgent(
                runner, project, GraphStore(StaticAnalyzer(FIXTURE).index())
            )
            import unittest.mock as mock
            with mock.patch('harnesscreator.runtime.oss_fuzz.preflight_oss_fuzz_backend',
                            return_value={'backend': 'native'}):
                result = await verifier.verify(
                    make_draft(), Path(td) / 'attempt', runtime_checks=False,
                )
            self.assertTrue(result.build_ok)
            self.assertFalse(result.qualified)
            self.assertEqual(runner.argvs[0][2], 'build_fuzzers')

    async def test_parallel_builds_are_serialized_without_blocking_event_loop(self):
        class SlowRunner(FakeRunner):
            active = 0
            maximum_active = 0

            async def run(self, argv, **kwargs):
                self.active += 1
                self.maximum_active = max(self.maximum_active, self.active)
                await asyncio.sleep(0.03)
                self.active -= 1
                return await super().run(argv, **kwargs)

        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            runner = SlowRunner()
            backend = NativeOssFuzzVerifierAgent(
                project, GraphStore(StaticAnalyzer(FIXTURE).index()), runner=runner,
            )
            import unittest.mock as mock
            with mock.patch('harnesscreator.runtime.oss_fuzz.preflight_oss_fuzz_backend',
                            return_value={'backend': 'native'}):
                a, b = await asyncio.wait_for(asyncio.gather(
                    backend.verify(make_draft(), Path(td) / 'a', runtime_checks=False),
                    backend.verify(make_draft(), Path(td) / 'b', runtime_checks=False),
                ), timeout=3)
            self.assertTrue(a.build_ok and b.build_ok)
            self.assertEqual(runner.maximum_active, 1)
            self.assertTrue(all('--clean' in argv for argv in runner.argvs))

    async def test_build_failure_cannot_be_misreported_as_success(self):
        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            runner = FakeRunner(fail_on='build_fuzzers')
            backend = NativeOssFuzzVerifierAgent(
                project, GraphStore(StaticAnalyzer(FIXTURE).index()), runner=runner
            )
            import unittest.mock as mock
            with mock.patch('harnesscreator.runtime.oss_fuzz.preflight_oss_fuzz_backend',
                            return_value={'backend': 'native'}):
                result = await backend.verify(make_draft(), Path(td) / 'attempt')
            self.assertFalse(result.qualified)
            self.assertFalse(result.build_ok)
            self.assertIn('build failed', result.reason)

    async def test_canonical_compiler_stdout_is_reported_and_saved(self):
        class CompilerFailureRunner(FakeRunner):
            async def run(self, argv, **kwargs):
                self.argvs.append(argv)
                return CommandReport(
                    argv=argv, returncode=1,
                    stdout='clang: error: missing required header\n',
                    stderr='ERROR:__main__:Building fuzzers failed.\n',
                    duration_seconds=1.5,
                )

        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            backend = NativeOssFuzzVerifierAgent(project, graph=None, runner=CompilerFailureRunner())
            import unittest.mock as mock
            with mock.patch('harnesscreator.runtime.oss_fuzz.preflight_oss_fuzz_backend',
                            return_value={'backend': 'native'}):
                with self.assertRaises(OssFuzzBackendError) as caught:
                    await backend.probe_canonical_build()
            self.assertIn('clang: error: missing required header', str(caught.exception))
            self.assertIn('returncode=1', str(caught.exception))
            path = project.output_root / '.oss-fuzz-build-logs' / 'canonical-build.log'
            self.assertTrue(path.is_file())
            self.assertIn('clang: error', path.read_text())
            self.assertIn('Building fuzzers failed', path.read_text())

    async def test_generated_build_failure_preserves_output_without_qualification(self):
        class CompilerFailureRunner(FakeRunner):
            async def run(self, argv, **kwargs):
                self.argvs.append(argv)
                return CommandReport(
                    argv=argv, returncode=1,
                    stdout='fatal error: generated source is invalid\n',
                    stderr='Build failed\n', duration_seconds=0.5,
                )

        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            backend = NativeOssFuzzVerifierAgent(project, graph=None, runner=CompilerFailureRunner())
            artifact_dir = Path(td) / 'attempt'
            import unittest.mock as mock
            with mock.patch('harnesscreator.runtime.oss_fuzz.preflight_oss_fuzz_backend',
                            return_value={'backend': 'native'}):
                result = await backend.verify(make_draft(), artifact_dir)
            self.assertFalse(result.qualified)
            self.assertFalse(result.build_ok)
            self.assertIn('fatal error: generated source is invalid', result.build.stdout)
            self.assertIn('oss-fuzz-build.log', result.reason)
            self.assertTrue((artifact_dir / 'oss-fuzz-build.log').is_file())

    async def test_smoke_test_does_not_claim_exact_handler_or_full_equivalence(self):
        with tempfile.TemporaryDirectory() as td:
            project = make_project(Path(td))
            runner = FakeRunner()
            backend = NativeOssFuzzVerifierAgent(
                project, GraphStore(StaticAnalyzer(FIXTURE).index()), runner=runner
            )
            import unittest.mock as mock
            with mock.patch('harnesscreator.runtime.oss_fuzz.preflight_oss_fuzz_backend',
                            return_value={'backend': 'native'}):
                result = await backend.verify(
                    make_draft(), Path(td) / 'attempt',
                    [SeedSpec('normal', '42', 'normal input')], runtime_checks=True,
                )
            self.assertTrue(result.build_ok)
            self.assertFalse(result.qualified)
            self.assertTrue(result.replays)
            self.assertIsNotNone(result.fuzz)
            self.assertIn('remain unverified', result.reason)
            commands = [item[2] for item in runner.argvs]
            self.assertIn('check_build', commands)
            self.assertIn('reproduce', commands)
            self.assertIn('run_fuzzer', commands)


if __name__ == '__main__':
    unittest.main()
