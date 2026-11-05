# HarnessCreator C-first trial (2026-10-22)

## What actually changed

Based on `HarnessCreator_structural_hardening.zip` (not a new architecture and **not** a general C-daemon success guarantee):

1. `analysis/clang_c.py` adds a **bounded Clang C AST supplement**. It indexes macro-expanded C functions and calls that the regex bootstrap missed. No candidate-only evidence from an unconfigured AST is upgraded into a proven executable call. Function-pointer-table references remain non-causal reference edges. If a TU cannot be parsed using available compilation flags, existing source records are kept; `AnalysisBundle.completeness` reports attempted/failed TUs and budget exhaustion. Clang is optional for source indexing but required for native fuzzing.
2. `runtime/request_ir.py` resolves machine-readable derived fields transitively, detects cycles, and rejects mutated requests with unsupported nonopaque dependent relations rather than leaving stale length/checksum values in the packet. The unmodified original source example remains usable as-is.
3. `runtime/native_build.py` only requires `clang++` when a C++ source or C++ harness is present. For all-C projects explicitly request `--harness-source-filename fuzz_target.c`.
4. Added source-only C fixtures and tests for direct calls, preprocessor-wrapped `recv`, macro-generated functions, and function-pointer dispatch tables, plus negative tests for unsupported request fields.

## Important limits

- The C AST pass is best effort. `HC_C_AST_BUDGET_SECONDS` defaults to 45 seconds to limit large-project indexing overhead; can be increased, for example, to `180`. It does NOT establish dataflow, object identity, event/queue handoffs, or all indirect targets. AST without a concrete compile database is navigation evidence, not runtime proof.
- Some C sources require generated headers/compile definitions. Provide `compile_commands.json` from the actual configured build if possible; conflicting compile variants are not silently selected.
- Counter/temporal state contracts, full original-vs-harness Setup/Fuzz/Post differential validation, and arbitrary daemon lifecycle/reset synthesis remain unimplemented. The primary Harness Generator remains LLM based.
- **No actual memcached Ollama full-run/valid harness result was measured in this environment.** A source-only draft does not imply verified handler reachability or semantic equivalence.

## WSL prerequisites

```bash
command -v clang && command -v make && command -v python3
ollama list
```

To install (distribution dependent): `sudo apt-get install clang make cmake`.

## Run only the reproducible C tests first

```bash
python3 -m pip install -e .
python3 -m pytest -q tests/test_c_ast_semantics.py tests/test_request_ir.py tests/test_native_independent_build.py
```

## Analyze memcached source without an OSS-Fuzz checkout

```bash
export SRC=/mnt/c/memcached
export HC_C_AST_BUDGET_SECONDS=180
harnesscreator run "$SRC" \
  --output "$HOME/hc-c-trial" \
  --provider ollama \
  --ollama-url http://127.0.0.1:11434 \
  --allow-source-analysis \
  --no-svf \
  --allow-partial-indirect-calls \
  --harness-source-filename fuzz_target.c \
  --verification-backend auto \
  --source-only-drafts \
  --max-source-drafts 16 \
  --workers 2 \
  --agent-debug \
  2>&1 | tee "$HOME/hc-c-trial.log"
```

This command will attempt **source-only drafts**, not an original-program runtime proof. It relies on default per-agent Ollama roles, without changing those settings. Run with a trusted original-program `--scenario-command` and matching runtime settings only if testing actual original execution.

## Tests run here

- Source AST, request IR, native build and indexer focused regression: **42 passed**.
- Scenario orchestration, execution adapter, differential, CLI and Ollama routing: **30 passed, 3 subtests passed**.
- Broader regression subset: **176 passed, 1 failed, 3 subtests passed**. The failing `test_unattributed_trace_becomes_observed_not_proven` timed out starting its temporary Python TCP server (not a semantic assertion error). It was not counted as passed.

These tests do not determine the proportion of real C daemons for which a runnable harness can be generated.
