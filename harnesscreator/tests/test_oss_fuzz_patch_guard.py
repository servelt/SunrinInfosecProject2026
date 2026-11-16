"""Regression tests: native OSS-Fuzz must retain original patch idempotence."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from harnesscreator.runtime.oss_fuzz import _make_recipe_patch_idempotent


PATCH = """diff --git a/sample.txt b/sample.txt
--- a/sample.txt
+++ b/sample.txt
@@ -1 +1 @@
-old
+new
"""


def _fixture(tmp_path: Path, *, line: str = 'git apply $SRC/patch.diff') -> tuple[Path, Path]:
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'sample.txt').write_text('old\n', encoding='utf-8')
    recipe = tmp_path / 'recipe'
    recipe.mkdir()
    (recipe / 'patch.diff').write_text(PATCH, encoding='utf-8')
    (recipe / 'build.sh').write_text(f'#!/bin/sh\nset -e\n{line}\n', encoding='utf-8')
    return recipe, source


def _execute(recipe: Path, source: Path) -> subprocess.CompletedProcess[str]:
    # The pinned recipe's $SRC points at the patch and is normally /src.
    # Here route the path through a local, absolute temporary directory.
    script = (recipe / 'build.sh').read_text(encoding='utf-8').replace(
        '/src/patch.diff', '$SRC/patch.diff'
    )
    return subprocess.run(
        ['sh', '-c', script],
        cwd=source,
        env={**os.environ, 'SRC': str(recipe)},
        capture_output=True,
        text=True,
        check=False,
    )


def test_applies_not_yet_applied_patch(tmp_path):
    recipe, source = _fixture(tmp_path)
    assert _make_recipe_patch_idempotent(recipe)
    result = _execute(recipe, source)
    assert result.returncode == 0, result.stderr
    assert (source / 'sample.txt').read_text() == 'new\n'


def test_skips_already_applied_patch(tmp_path):
    recipe, source = _fixture(tmp_path, line='git apply "$SRC/patch.diff"')
    subprocess.run(['git', 'apply', str(recipe / 'patch.diff')], cwd=source, check=True)
    assert _make_recipe_patch_idempotent(recipe)
    result = _execute(recipe, source)
    assert result.returncode == 0, result.stderr
    assert 'already applied' in result.stdout
    assert (source / 'sample.txt').read_text() == 'new\n'


def test_genuinely_incompatible_patch_still_fails(tmp_path):
    recipe, source = _fixture(tmp_path, line="git apply '${SRC}/patch.diff'")
    (source / 'sample.txt').write_text('different\n', encoding='utf-8')
    assert _make_recipe_patch_idempotent(recipe)
    result = _execute(recipe, source)
    assert result.returncode != 0
    assert 'incompatible' in result.stderr
    assert (source / 'sample.txt').read_text() == 'different\n'


def test_never_mutates_original_recipe(tmp_path):
    recipe, source = _fixture(tmp_path)
    copied = tmp_path / 'copy'
    import shutil
    shutil.copytree(recipe, copied)
    assert _make_recipe_patch_idempotent(copied)
    assert '# HARNESSCREATOR_IDEMPOTENT_PATCH_BEGIN' in (copied / 'build.sh').read_text()
    assert '# HARNESSCREATOR_IDEMPOTENT_PATCH_BEGIN' not in (recipe / 'build.sh').read_text()
    assert _make_recipe_patch_idempotent(copied)
    assert (copied / 'build.sh').read_text().count('HARNESSCREATOR_IDEMPOTENT_PATCH_BEGIN') == 1


def test_literal_container_patch_path_gets_guarded(tmp_path):
    recipe, _ = _fixture(tmp_path, line='git apply /src/patch.diff')
    assert _make_recipe_patch_idempotent(recipe)
    guarded = (recipe / 'build.sh').read_text(encoding='utf-8')
    assert 'git apply --check /src/patch.diff' in guarded
    assert 'git apply --reverse --check /src/patch.diff' in guarded
