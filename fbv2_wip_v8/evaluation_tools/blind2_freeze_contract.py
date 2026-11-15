"""Target-neutral, read-only binding of a blind2 contract to its frozen files."""
from __future__ import annotations

import json
from pathlib import Path

from create_freeze_manifest import build_manifest, digest


REQUIRED_GROUPS = frozenset({
    'product_code', 'product_prompts', 'product_config', 'evaluation_tools',
    'target_source', 'target_catalog_and_artifact', 'official_harness',
    'normal_corpus', 'replay_and_coverage_build', 'preregistration',
})
ROLE_PROMPTS = frozenset({
    'assertion_generator.md', 'function_analysis.md', 'poc_generator.md',
    'sp_generation.md', 'sp_verifier.md',
})
EVALUATION_MODULES = frozenset({
    'blind2_runner_draft.py', 'blind_runner_guards.py',
    'blind2_budget_guard.py', 'blind2_freeze_contract.py',
    'catalog_build_integrity.py', 'create_freeze_manifest.py',
    'blind2_model_sandbox.py',
})
UNFROZEN_EXECUTABLE_SUFFIXES = frozenset({'.so', '.pyd', '.dll', '.pyo'})
PREREGISTRATION = 'public/BLIND2_PREREGISTRATION.md'


def verify_frozen_surface(contract: dict, reference_root: Path,
                          product_root: Path) -> dict:
    """Bind the runner's model-visible files and local tools to the Manifest."""
    reference_root = reference_root.resolve(strict=True)
    product_root = product_root.resolve(strict=True)
    if (contract.get('freeze_spec') != 'tools/freeze_spec.json' or
            contract.get('freeze_manifest') != 'public/FREEZE_MANIFEST.json'):
        raise ValueError('unexpected freeze spec or Manifest path')
    spec_path = reference_root / contract['freeze_spec']
    manifest_path = reference_root / contract['freeze_manifest']
    if (digest(spec_path) != contract.get('freeze_spec_sha256') or
            digest(manifest_path) != contract.get('freeze_manifest_sha256')):
        raise ValueError('freeze spec or Manifest digest changed')
    spec = json.loads(spec_path.read_text())
    if (set(spec.get('groups', {})) != REQUIRED_GROUPS or
            spec.get('roots') != {'reference': str(reference_root),
                                  'product': str(product_root)}):
        raise ValueError('freeze groups or roots changed')
    recorded = json.loads(manifest_path.read_text())
    actual = build_manifest(spec_path)
    if recorded != actual:
        raise ValueError('frozen file membership or bytes changed')
    groups = {group: {row['path'] for row in actual['entries']
                      if row['group'] == group} for group in REQUIRED_GROUPS}
    reference_entries = {row['path'] for row in actual['entries']
                         if row['root'] == 'reference'}
    product_entries = {row['path'] for row in actual['entries']
                       if row['root'] == 'product'}

    def require(value: str, group: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f'missing {group} path')
        path = Path(value)
        resolved = path.resolve(strict=True) if path.is_absolute() else (reference_root / path).resolve(strict=True)
        if not resolved.is_file() or not resolved.is_relative_to(reference_root):
            raise ValueError(f'executed {group} file outside frozen root')
        relative = resolved.relative_to(reference_root).as_posix()
        if relative not in groups[group] or relative not in reference_entries:
            raise ValueError(f'executed {group} file missing from Manifest')
        return relative

    artifact_value = contract.get('artifact')
    source_value = contract.get('target_repository')
    if (not isinstance(artifact_value, str) or not isinstance(source_value, str)
            or not artifact_value or not source_value
            or Path(artifact_value).is_absolute() or Path(source_value).is_absolute()
            or '..' in Path(artifact_value).parts or '..' in Path(source_value).parts
            or Path(artifact_value).name != 'attempt'):
        raise ValueError('invalid model-visible Artifact or Source root')
    artifact_path = (reference_root / artifact_value).resolve(strict=True)
    source_path = (reference_root / source_value).resolve(strict=True)
    catalog_root = artifact_path.parent
    if (not artifact_path.is_dir() or not source_path.is_dir()
            or not artifact_path.is_relative_to(reference_root)
            or not source_path.is_relative_to(reference_root)
            or source_path == catalog_root):
        raise ValueError('model-visible Artifact or Source root changed')
    artifact = artifact_path.relative_to(reference_root).as_posix()
    source = source_path.relative_to(reference_root).as_posix()
    catalog_prefix = catalog_root.relative_to(reference_root).as_posix()

    for group, prefix in {
        'evaluation_tools': 'tools/',
        'target_source': source + '/',
        'target_catalog_and_artifact': catalog_prefix + '/',
        'normal_corpus': 'public/normal_seed_corpus/',
        'replay_and_coverage_build': 'build/',
        'preregistration': 'public/',
    }.items():
        if not groups[group] or any(not row.startswith(prefix) for row in groups[group]):
            raise ValueError(f'freeze group points outside its surface: {group}')
    for group, prefix in {
        'product_code': 'vulnerabilityanalysis/src/vulnerabilityanalysis/',
        'product_prompts': 'vulnerabilityanalysis/prompts/',
        'product_config': 'vulnerabilityanalysis/',
    }.items():
        if not groups[group] or any(not row.startswith(prefix) for row in groups[group]):
            raise ValueError(f'product freeze group points outside its surface: {group}')
        if not groups[group].issubset(product_entries):
            raise ValueError(f'product freeze group uses wrong root: {group}')
    # The runner imports the live product package. Freezing only an arbitrary
    # subset would leave executable scan/Fuzzer code outside the contract.
    package_root = product_root / 'vulnerabilityanalysis/src/vulnerabilityanalysis'
    source_import_root = package_root.parent
    if (not source_import_root.is_dir() or source_import_root.is_symlink() or
            any(path.name != 'vulnerabilityanalysis' for path in source_import_root.iterdir())):
        raise ValueError('product import root has untrusted sibling modules')
    if (not package_root.is_dir() or
            any(path.is_symlink() for path in (package_root, *package_root.parents)
                if path != product_root and path.is_relative_to(product_root))):
        raise ValueError('product code package missing')
    package_entries = list(package_root.rglob('*'))
    if any(path.is_symlink() for path in package_entries):
        raise ValueError('product code package has untrusted Python files')
    executable_files = [path for path in package_entries if path.suffix == '.py']
    if not executable_files or any(not path.is_file() for path in executable_files):
        raise ValueError('product code package has no regular Python modules')
    required_code = {path.relative_to(product_root).as_posix()
                     for path in executable_files}
    if not required_code.issubset(groups['product_code']):
        raise ValueError('product code module missing from frozen Manifest')
    if any(path.suffix in UNFROZEN_EXECUTABLE_SUFFIXES or
           (path.suffix == '.pyc' and '__pycache__' not in path.parts)
           for path in package_entries):
        raise ValueError('product code package has untrusted executable files')

    prompt_root = product_root / 'vulnerabilityanalysis/prompts'
    if not prompt_root.is_dir() or prompt_root.is_symlink():
        raise ValueError('product prompt directory missing or linked')
    prompt_entries = list(prompt_root.rglob('*'))
    if any(path.is_symlink() for path in prompt_entries):
        raise ValueError('product prompt directory has linked files')
    prompt_files = {path.relative_to(product_root).as_posix()
                    for path in prompt_entries if path.is_file() and path.suffix == '.md'}
    role_files = {f'vulnerabilityanalysis/prompts/{name}' for name in ROLE_PROMPTS}
    if not role_files.issubset(prompt_files) or not prompt_files.issubset(groups['product_prompts']):
        raise ValueError('product prompt missing from frozen Manifest')
    if 'vulnerabilityanalysis/config/default.yaml' not in groups['product_config']:
        raise ValueError('product config/default.yaml missing from frozen Manifest')

    tools_root = reference_root / 'tools'
    if not tools_root.is_dir() or tools_root.is_symlink():
        raise ValueError('evaluation tool directory missing or linked')
    tool_entries = list(tools_root.rglob('*'))
    if any(path.is_symlink() for path in tool_entries):
        raise ValueError('evaluation tool directory has linked files')
    if any(path.suffix in UNFROZEN_EXECUTABLE_SUFFIXES or
           (path.suffix == '.pyc' and '__pycache__' not in path.parts)
           for path in tool_entries):
        raise ValueError('evaluation tool directory has untrusted executable files')
    tool_files = {path.relative_to(reference_root).as_posix()
                  for path in tool_entries if path.is_file() and path.suffix == '.py'}
    required_tools = {f'tools/{name}' for name in EVALUATION_MODULES}
    if not required_tools.issubset(tool_files) or not tool_files.issubset(groups['evaluation_tools']):
        raise ValueError('evaluation tool module missing from frozen Manifest')
    require(PREREGISTRATION, 'preregistration')

    source_entries = list(source_path.rglob('*'))
    if any(path.is_symlink() for path in source_entries
           if '.git' not in path.relative_to(source_path).parts):
        raise ValueError('Target Source has linked files')
    if any('__pycache__' in path.relative_to(source_path).parts
           for path in source_entries):
        raise ValueError('Target Source has untrusted cache directory')
    source_files = {path.relative_to(reference_root).as_posix()
                    for path in source_entries
                    if path.is_file() and '.git' not in path.relative_to(source_path).parts
                    and '__pycache__' not in path.relative_to(source_path).parts}
    if not source_files or not source_files.issubset(groups['target_source']):
        raise ValueError('Target Source file missing from frozen Manifest')

    for value in (catalog_prefix + '/project.json', artifact + '/manifest.json',
                  catalog_prefix + '/analysis/functions.jsonl',
                  catalog_prefix + '/analysis/edges.jsonl'):
        require(value, 'target_catalog_and_artifact')
    if contract.get('catalog_build_receipt'):
        indirect = catalog_prefix + '/analysis/indirect_edges.jsonl'
        if contract.get('catalog_indirect_edges') != indirect:
            raise ValueError('indirect Catalog sidecar missing from contract')
        require(indirect, 'target_catalog_and_artifact')
    if not any(row.startswith(source + '/') for row in groups['target_source']):
        raise ValueError('model-visible Source tree absent from Manifest')

    harness = require(contract.get('official_harness_path'), 'official_harness')
    if (not harness.startswith(artifact + '/') or
            Path(harness).suffix not in {'.c', '.cc', '.cpp', '.cxx'}):
        raise ValueError('official Harness outside model-visible Artifact')
    official_contract = require(contract.get('official_harness_contract'), 'official_harness')
    review = require(contract.get('official_harness_review'), 'official_harness')
    if (official_contract != 'public/OFFICIAL_HARNESS_CONTRACT.json' or
            digest(reference_root / official_contract) != contract.get('official_harness_contract_sha256')):
        raise ValueError('official Harness review contract changed')
    official_data = json.loads((reference_root / official_contract).read_text())
    kind = official_data.get('kind')
    if kind == 'OFFICIAL_OSS_FUZZ_UPSTREAM_HARNESS_V2':
        binding = official_data.get('api_review')
        if (not isinstance(binding, dict) or
                set(binding) != {'file', 'sha256', 'reviewer_id'} or
                not isinstance(binding['file'], str) or
                not Path(binding['file']).is_absolute() or
                Path(binding['file']).resolve() != (reference_root / review).resolve() or
                binding['sha256'] != digest(reference_root / review) or
                not isinstance(binding['reviewer_id'], str) or
                not binding['reviewer_id'].strip()):
            raise ValueError('official Harness API review identity changed')
        review_data = json.loads((reference_root / review).read_text())
        if (not isinstance(review_data, dict) or
                review_data.get('reviewer_id') != binding['reviewer_id']):
            raise ValueError('official Harness API review signer changed')
    elif kind in (None, 'OFFICIAL_OSS_FUZZ_HARNESS_V1'):
        review_path = official_data.get('review_artifact')
        if (not isinstance(review_path, str) or
                Path(review_path).resolve() != (reference_root / review).resolve()):
            raise ValueError('official Harness API review identity changed')
        recorded_sha = official_data.get('review_sha256')
        if recorded_sha is not None and recorded_sha != digest(reference_root / review):
            raise ValueError('official Harness API review digest changed')
    else:
        raise ValueError('official Harness API review contract kind unsupported')

    for key in ('asan_binary', 'coverage_fuzzer'):
        require(contract.get(key), 'replay_and_coverage_build')
    require(contract.get('codex_config'), 'evaluation_tools')
    require(contract.get('assertion_build_manifest'), 'evaluation_tools')
    builder_command = contract.get('assertion_build_command')
    if (not isinstance(builder_command, list) or len(builder_command) != 4 or
            builder_command[1:] != ['{source}', '-o', '{binary}']):
        raise ValueError('Assertion build command changed')
    require(builder_command[0], 'evaluation_tools')
    require(contract.get('runner_path'), 'evaluation_tools')
    if (contract.get('assertion_run_command') != ['{binary}', '{input}'] or
            contract.get('run_command') != [contract['asan_binary'], '{input}']):
        raise ValueError('original or Assertion replay command changed')

    seeds = contract.get('normal_seeds')
    if (not isinstance(seeds, list) or not 1 <= len(seeds) <= 128 or
            len(set(seeds)) != len(seeds)):
        raise ValueError('invalid normal Seed list')
    if {require(seed, 'normal_corpus') for seed in seeds} != groups['normal_corpus']:
        raise ValueError('executed Seed set differs from frozen Corpus')
    if contract.get('assertion_seed') not in seeds:
        raise ValueError('Assertion Seed not in frozen normal Corpus')
    return actual
