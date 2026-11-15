"""Model-free checks for a target-neutral complete freeze identity."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from create_freeze_manifest import build_manifest, digest
from blind2_freeze_contract import verify_frozen_surface

ROLE_PROMPTS = ('assertion_generator', 'function_analysis', 'poc_generator',
                'sp_generation', 'sp_verifier')


class Blind2FreezeContractTests(TestCase):
    def make_fixture(self, base: Path):
        reference = base / 'reference'; product = base / 'product'
        files = {
            'evaluation_tools': ['tools/blind2_runner_draft.py', 'tools/build.py',
                                 'tools/build_manifest.json', 'tools/codex.toml',
                                 'tools/blind_runner_guards.py',
                                 'tools/blind2_budget_guard.py',
                                 'tools/blind2_freeze_contract.py',
                                 'tools/catalog_build_integrity.py',
                                 'tools/create_freeze_manifest.py',
                                 'tools/blind2_model_sandbox.py'],
            'target_source': ['model_target/source/file.c'],
            'target_catalog_and_artifact': ['model_target/project.json',
                'model_target/attempt/manifest.json',
                'model_target/analysis/functions.jsonl',
                'model_target/analysis/edges.jsonl'],
            'official_harness': ['model_target/attempt/new_fuzzer.cc',
                'public/OFFICIAL_HARNESS_CONTRACT.json',
                'public/OFFICIAL_HARNESS_API_REVIEW.json'],
            'normal_corpus': ['public/normal_seed_corpus/seed1',
                              'public/normal_seed_corpus/seed2'],
            'replay_and_coverage_build': ['build/asan', 'build/coverage'],
            'preregistration': ['public/BLIND2_PREREGISTRATION.md'],
        }
        product_files = {
            'product_code': [
                'vulnerabilityanalysis/src/vulnerabilityanalysis/a.py',
                'vulnerabilityanalysis/src/vulnerabilityanalysis/scan.py',
                'vulnerabilityanalysis/src/vulnerabilityanalysis/runtime.py',
                'vulnerabilityanalysis/src/vulnerabilityanalysis/analysis.py'],
            'product_prompts': [f'vulnerabilityanalysis/prompts/{name}.md'
                                for name in ROLE_PROMPTS],
            'product_config': ['vulnerabilityanalysis/config/default.yaml'],
        }
        for root, groups in ((reference, files), (product, product_files)):
            for paths in groups.values():
                for name in paths:
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(name)
        review = reference / 'public/OFFICIAL_HARNESS_API_REVIEW.json'
        official = reference / 'public/OFFICIAL_HARNESS_CONTRACT.json'
        official.write_text(json.dumps({
            'kind': 'OFFICIAL_OSS_FUZZ_HARNESS_V1',
            'review_artifact': str(review), 'review_sha256': digest(review)}))
        spec = {'roots': {'reference': str(reference), 'product': str(product)},
                'groups': {name: {'root': 'reference', 'paths': paths}
                           for name, paths in files.items()}}
        spec['groups'].update({name: {'root': 'product', 'paths': paths}
                               for name, paths in product_files.items()})
        spec_path = reference / 'tools/freeze_spec.json'
        spec_path.write_text(json.dumps(spec))
        manifest_path = reference / 'public/FREEZE_MANIFEST.json'
        manifest_path.write_text(json.dumps(build_manifest(spec_path)))
        contract = {
            'freeze_spec': 'tools/freeze_spec.json',
            'freeze_manifest': 'public/FREEZE_MANIFEST.json',
            'freeze_spec_sha256': digest(spec_path),
            'freeze_manifest_sha256': digest(manifest_path),
            'artifact': 'model_target/attempt',
            'target_repository': 'model_target/source',
            'official_harness_path': 'model_target/attempt/new_fuzzer.cc',
            'official_harness_contract': 'public/OFFICIAL_HARNESS_CONTRACT.json',
            'official_harness_contract_sha256': digest(official),
            'official_harness_review': 'public/OFFICIAL_HARNESS_API_REVIEW.json',
            'asan_binary': 'build/asan', 'coverage_fuzzer': 'build/coverage',
            'codex_config': 'tools/codex.toml',
            'assertion_build_manifest': 'tools/build_manifest.json',
            'assertion_build_command': [str(reference / 'tools/build.py'),
                                        '{source}', '-o', '{binary}'],
            'runner_path': 'tools/blind2_runner_draft.py',
            'run_command': ['build/asan', '{input}'],
            'assertion_run_command': ['{binary}', '{input}'],
            'normal_seeds': files['normal_corpus'],
            'assertion_seed': files['normal_corpus'][0],
        }
        return reference, product, contract

    def refresh(self, reference: Path, contract: dict) -> None:
        spec_path = reference / contract['freeze_spec']
        manifest_path = reference / contract['freeze_manifest']
        manifest_path.write_text(json.dumps(build_manifest(spec_path)))
        contract['freeze_spec_sha256'] = digest(spec_path)
        contract['freeze_manifest_sha256'] = digest(manifest_path)
        contract['official_harness_contract_sha256'] = digest(
            reference / contract['official_harness_contract'])

    def test_new_target_harness_and_two_seeds_are_accepted_when_frozen(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            report = verify_frozen_surface(contract, reference, product)
            self.assertEqual(report['entry_count'], 33)

    def test_model_sandbox_launcher_cannot_be_omitted_from_freeze(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            spec_path = reference / contract['freeze_spec']
            spec = json.loads(spec_path.read_text())
            spec['groups']['evaluation_tools']['paths'].remove(
                'tools/blind2_model_sandbox.py')
            spec_path.write_text(json.dumps(spec))
            self.refresh(reference, contract)
            with self.assertRaisesRegex(ValueError, 'evaluation tool module missing'):
                verify_frozen_surface(contract, reference, product)

    def test_separate_source_checkout_and_artifact_root_are_frozen(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            old = reference / 'model_target'
            staged = reference / 'v2_artifact_stage'; staged.mkdir()
            for name in ('project.json', 'analysis', 'attempt'):
                (old / name).rename(staged / name)
            spec_path = reference / contract['freeze_spec']
            spec = json.loads(spec_path.read_text())
            group = spec['groups']['target_catalog_and_artifact']['paths']
            spec['groups']['target_catalog_and_artifact']['paths'] = [
                value.replace('model_target/', 'v2_artifact_stage/', 1)
                for value in group]
            official = spec['groups']['official_harness']['paths']
            official[0] = official[0].replace('model_target/', 'v2_artifact_stage/', 1)
            spec_path.write_text(json.dumps(spec))
            manifest_path = reference / contract['freeze_manifest']
            manifest_path.write_text(json.dumps(build_manifest(spec_path)))
            contract.update({
                'artifact': 'v2_artifact_stage/attempt',
                'official_harness_path': official[0],
                'freeze_spec_sha256': digest(spec_path),
                'freeze_manifest_sha256': digest(manifest_path)})
            report = verify_frozen_surface(contract, reference, product)
            self.assertEqual(report['entry_count'], 33)

    def test_v2_api_review_path_sha_and_reviewer_are_bound(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            review = reference / contract['official_harness_review']
            review.write_text(json.dumps({'reviewer_id': 'independent-reviewer'}))
            official = reference / contract['official_harness_contract']
            official.write_text(json.dumps({
                'kind': 'OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2',
                'api_review': {'file': str(review), 'sha256': digest(review),
                               'reviewer_id': 'independent-reviewer'}}))
            self.refresh(reference, contract)
            verify_frozen_surface(contract, reference, product)
            for key, value in [('file', str(reference / 'other.json')),
                               ('sha256', '0' * 64),
                               ('reviewer_id', 'wrong-reviewer')]:
                data = json.loads(official.read_text())
                data['api_review'][key] = value
                official.write_text(json.dumps(data))
                self.refresh(reference, contract)
                with self.assertRaisesRegex(ValueError, 'API review'):
                    verify_frozen_surface(contract, reference, product)
                data['api_review'][key] = (
                    str(review) if key == 'file' else
                    digest(review) if key == 'sha256' else 'independent-reviewer')
                official.write_text(json.dumps(data))

    def test_v1_mismatched_review_is_rejected(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            official = reference / contract['official_harness_contract']
            official.write_text(json.dumps({
                'kind': 'OFFICIAL_OSS_FUZZ_HARNESS_V1',
                'review_artifact': str(reference / 'other.json')}))
            self.refresh(reference, contract)
            with self.assertRaisesRegex(ValueError, 'API review'):
                verify_frozen_surface(contract, reference, product)

    def test_v1_review_digest_mismatch_is_rejected(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            official = reference / contract['official_harness_contract']
            data = json.loads(official.read_text())
            data['review_sha256'] = '0' * 64
            official.write_text(json.dumps(data))
            self.refresh(reference, contract)
            with self.assertRaisesRegex(ValueError, 'API review'):
                verify_frozen_surface(contract, reference, product)

    def test_missing_role_prompt_is_rejected_after_manifest_rebuilt(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            path = reference / contract['freeze_spec']
            spec = json.loads(path.read_text())
            spec['groups']['product_prompts']['paths'].pop()
            path.write_text(json.dumps(spec))
            self.refresh(reference, contract)
            with self.assertRaisesRegex(ValueError, 'prompt'):
                verify_frozen_surface(contract, reference, product)

    def test_default_config_cannot_be_replaced_by_unused_yaml(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            unused = product / 'vulnerabilityanalysis/config/unused.yaml'
            unused.write_text('unused: true\n')
            path = reference / contract['freeze_spec']
            spec = json.loads(path.read_text())
            spec['groups']['product_config']['paths'] = [
                'vulnerabilityanalysis/config/unused.yaml']
            path.write_text(json.dumps(spec))
            self.refresh(reference, contract)
            with self.assertRaisesRegex(ValueError, 'config'):
                verify_frozen_surface(contract, reference, product)

    def test_missing_evaluation_helper_is_rejected(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            path = reference / contract['freeze_spec']
            spec = json.loads(path.read_text())
            spec['groups']['evaluation_tools']['paths'].remove(
                'tools/blind2_budget_guard.py')
            path.write_text(json.dumps(spec))
            self.refresh(reference, contract)
            with self.assertRaisesRegex(ValueError, 'evaluation tool'):
                verify_frozen_surface(contract, reference, product)

    def test_new_unregistered_evaluation_module_is_rejected(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            (reference / 'tools/new_helper.py').write_text('VALUE = 1\n')
            with self.assertRaisesRegex(ValueError, 'evaluation tool'):
                verify_frozen_surface(contract, reference, product)

    def test_target_source_file_missing_from_manifest_is_rejected(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            (reference / contract['target_repository'] / 'second.c').write_text('int x;\n')
            with self.assertRaisesRegex(ValueError, 'Target Source'):
                verify_frozen_surface(contract, reference, product)

    def test_target_source_pycache_directory_is_rejected(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            hidden = reference / contract['target_repository'] / '__pycache__'
            hidden.mkdir()
            (hidden / 'shadow.c').write_text('int hidden(void) { return 1; }\n')
            with self.assertRaisesRegex(ValueError, 'Target Source'):
                verify_frozen_surface(contract, reference, product)

    def test_full_target_source_directory_is_accepted(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            (reference / contract['target_repository'] / 'second.c').write_text('int x;\n')
            path = reference / contract['freeze_spec']
            spec = json.loads(path.read_text())
            spec['groups']['target_source']['paths'] = [contract['target_repository']]
            path.write_text(json.dumps(spec))
            self.refresh(reference, contract)
            verify_frozen_surface(contract, reference, product)

    def test_canonical_preregistration_file_is_required(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            unused = reference / 'public/unused.md'
            unused.write_text('unused\n')
            path = reference / contract['freeze_spec']
            spec = json.loads(path.read_text())
            spec['groups']['preregistration']['paths'] = ['public/unused.md']
            path.write_text(json.dumps(spec))
            self.refresh(reference, contract)
            with self.assertRaisesRegex(ValueError, 'preregistration'):
                verify_frozen_surface(contract, reference, product)

    def test_sourceless_bytecode_and_native_extension_are_rejected(self):
        for suffix in ('.pyc', '.so'):
            with self.subTest(suffix=suffix), TemporaryDirectory() as tmp:
                reference, product, contract = self.make_fixture(Path(tmp))
                package = product / 'vulnerabilityanalysis/src/vulnerabilityanalysis'
                (package / ('legacy' + suffix)).write_bytes(b'not trusted')
                with self.assertRaisesRegex(ValueError, 'untrusted'):
                    verify_frozen_surface(contract, reference, product)

    def test_unfrozen_top_level_product_import_shadow_is_rejected(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            src = product / 'vulnerabilityanalysis/src'
            (src / 'yaml.py').write_text('VALUE = "shadow"\n')
            with self.assertRaisesRegex(ValueError, 'untrusted'):
                verify_frozen_surface(contract, reference, product)

    def test_linked_source_directory_is_not_silently_skipped(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            reference, _, contract = self.make_fixture(base)
            outside = base / 'outside'; outside.mkdir()
            (outside / 'hidden.c').write_text('int hidden;\n')
            source = reference / contract['target_repository']
            (source / 'linked').symlink_to(outside, target_is_directory=True)
            spec_path = reference / contract['freeze_spec']
            spec = json.loads(spec_path.read_text())
            spec['groups']['target_source']['paths'] = [contract['target_repository']]
            spec_path.write_text(json.dumps(spec))
            with self.assertRaisesRegex(ValueError, 'unsafe freeze input'):
                build_manifest(spec_path)

    def test_cxx_harness_is_accepted_consistently(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            old = reference / contract['official_harness_path']
            new = old.with_suffix('.cxx'); old.rename(new)
            spec_path = reference / contract['freeze_spec']
            spec = json.loads(spec_path.read_text())
            spec['groups']['official_harness']['paths'][0] = new.relative_to(reference).as_posix()
            spec_path.write_text(json.dumps(spec))
            contract['official_harness_path'] = new.relative_to(reference).as_posix()
            self.refresh(reference, contract)
            verify_frozen_surface(contract, reference, product)

    def test_executable_sp_fuzzer_module_missing_from_manifest_is_rejected(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            spec_path = reference / contract['freeze_spec']
            spec = json.loads(spec_path.read_text())
            paths = spec['groups']['product_code']['paths']
            spec['groups']['product_code']['paths'] = [
                path for path in paths if not path.endswith('/scan.py')]
            spec_path.write_text(json.dumps(spec))
            manifest_path = reference / contract['freeze_manifest']
            manifest_path.write_text(json.dumps(build_manifest(spec_path)))
            contract['freeze_spec_sha256'] = digest(spec_path)
            contract['freeze_manifest_sha256'] = digest(manifest_path)
            with self.assertRaisesRegex(ValueError, 'product code'):
                verify_frozen_surface(contract, reference, product)

    def test_symlinked_package_directory_with_unfrozen_module_is_rejected(self):
        with TemporaryDirectory() as tmp:
            base = Path(tmp)
            reference, product, contract = self.make_fixture(base)
            outside = base / 'outside_modules'
            outside.mkdir()
            (outside / 'unfrozen.py').write_text('VALUE = 1\n')
            package = product / 'vulnerabilityanalysis/src/vulnerabilityanalysis'
            (package / 'extra').symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'product code'):
                verify_frozen_surface(contract, reference, product)

    def test_harness_bytes_changed_after_freeze_are_rejected(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            (reference / contract['official_harness_path']).write_text('changed')
            with self.assertRaises(ValueError):
                verify_frozen_surface(contract, reference, product)

    def test_catalog_receipt_requires_indirect_artifact_in_frozen_manifest(self):
        with TemporaryDirectory() as tmp:
            reference, product, contract = self.make_fixture(Path(tmp))
            contract['catalog_build_receipt'] = 'public/catalog_receipt.json'
            with self.assertRaisesRegex(ValueError, 'indirect'):
                verify_frozen_surface(contract, reference, product)
            contract['catalog_indirect_edges'] = (
                'model_target/analysis/indirect_edges.jsonl')
            sidecar = reference / contract['catalog_indirect_edges']
            sidecar.write_text('{"kind":"function_reference"}\n')
            with self.assertRaisesRegex(ValueError, 'missing from Manifest'):
                verify_frozen_surface(contract, reference, product)
