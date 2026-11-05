# HarnessCreator: structural hardening and actual verification

## Scope and status

This package is a **structural hardening revision** of `HarnessCreator_callback_recovery.zip`. It does **not** establish that harness generation works for most C/C++ daemons, nor was a real memcached Ollama run performed in this container. Such a claim requires multi-project, held-out, actual-LLM end-to-end measurements.

The existing Entry Generator / Entry Verifier / Input Action / State Dependency / Scenario Planner / Original Runtime Verifier / Harness Generator / Harness Verifier / Crash Reproducer stages and the prescribed Ollama reasoning configuration are retained.

## Core changes

1. **Discovery recall is separate from qualification precision.** The source-supported `POSSIBLE` Actions and provisional state transitions can produce bounded **unverified** `Setup → Fuzz → Post` candidates, even when runtime evidence is unavailable or the original fails to start. This must never become `PROVEN_RUNTIME` or `QUALIFIED` on the strength of a graph heuristic or ordinary protocol response alone.
2. **Candidate scheduling uses explicit status and budgets.** `schedule_generation()` fairly prioritizes one candidate per Action, keeps observed/replayed candidates when `--source-only-drafts` is selected, and records excluded scenario IDs with reasons. Proven witnesses retain priority.
3. **Target-specific independent builds.** For CMake, existing `compile_commands.json` and `CMakeFiles/*/link.txt` determine the selected executable's source/object/archive closure. For configured Automake-style Makefiles, targets, local archives, source lists and limited compiler/linker flags are expanded statically. A small, unambiguous standalone source layout remains the fallback. Native compiler uses sanitizers and libFuzzer. **No existing OSS-Fuzz project/fuzzer/patch is required for `--verification-backend auto`.** Ambiguous build graphs are reported; they are not treated as successful builds.
4. **Per-target compiler flags.** CMake projects that compile the same source with different `-D` options in different executables must compile the exact objects belonging to the selected target, never use the last compile-db record by filename. A real CMake/Clang/libFuzzer regression tests this.
5. **Optional capability checks never abort discovery.** Missing Clang/GDB or unresolved target closure is recorded in `workflow/capability-preflight.json` and `harness-plans/build-readiness.json`; errors from parsing a project's build graph cannot crash unrelated candidate generation.
6. **Request-response vs request-attributed proof.** Response-only success is `REPLAYED_RUNTIME` for exploratory replay, **not** causal handler proof. A GDB ordered breakpoint observation is not a request-correlated causal trace. Strict verification still refuses proof. Runtime first-request budgets permit slow process initialization; later requests retain the per-step budget.
7. **Lossless, crash-resilient candidate ledger.** `workflow/candidate-lifecycle.jsonl` is checkpointed after Action discovery, Scenario creation, runtime Witness evaluation, plan selection, code generation, and each plan's verification; every Action receives a disposition. Fixed a concrete bug: the Scenario pipeline previously did not populate `generated_by_action`, so successful generated/build-tested harnesses showed as not generated in the ledger.
8. **Qualification is independent.** Backend build/fuzz success and original-vs-harness semantic verification remain separate sets and output fields. No source-only or unattributed exploratory harness may be reported as semantically verified.
9. **Read interrupted runs without an LLM.** `harnesscreator report RUN_DIR` and `--json` display collected Action, Scenario, Plan, build, backend and semantic statuses and unresolved obligations even if `summary.json` has not been written.

## Empirical tests in this environment

- `python -m pytest -q --ignore=tests/test_scenario_workflow.py --ignore=tests/test_exploratory_drafts.py` → **296 passed, 4 skipped, 32 subtests passed**.
- `python -m pytest -q tests/test_exploratory_drafts.py -k 'not test_unattributed_trace_becomes_observed_not_proven'` → **8 passed, 1 deselected**.
- `python -m pytest -q tests/test_scenario_workflow.py -k 'not tcp_original_executor_observes_a_split_success_response'` → **71 passed, 2 skipped, 1 deselected**.
- Combined disjoint test sets: **375 passed, 6 skipped, 2 excluded** out of **383 collected**. The excluded tests both spawn Python TCP server subprocesses which did not become ready within configured 2-second timeout in this container. They are **not** counted as passes; prior direct execution produced `INFRASTRUCTURE_FAILED`, not the expected witness status. This is an unresolved test/runtime-readiness concern, not a known successful full-suite run.
- Real Clang/libFuzzer tests: small standalone C, multi-executable CMake C, generated-Makefile/Autotools C, C++ daemon + C harness, and CMake compile-definition collision. Separate test harnesses and original-service network tests include a TCP worker queue and UDP service, as well as file/argv/environment program input. Existing end-to-end orchestration test uses **scripted** LLM responses, not Ollama inference.

### What has NOT been shown

- No actual source checkout of the user's WSL memcached or Ollama Cloud connector was available here, so **no fresh memcached Action → Scenario → generated C harness → validated fuzzing run** was performed.
- No cross-project held-out real LLM benchmark was run. "Works for most C/C++ daemons" is **not demonstrated**.
- No general automatic synthesis of per-request instrumentation, arbitrary TLS/IPC/fork/privilege/session lifecycles, or full reset semantics exists.
- Static CMake/Make target closure resolution does not guarantee compatibility with large vendored, generated-code, libtool, unusual assembly, or external linked dependencies. Such cases are reported as `UNRESOLVED` and require appropriate original build instructions or additional implementation.
- Candidate exploration is recall-oriented but subject to `max_source_drafts`/scenario budgets. It does not guarantee complete reachability nor coverage across arbitrarily complex code.

## Run commands: independent of OSS-Fuzz registration

After extracting this ZIP and installing with `python -m pip install -e .`:

```bash
harnesscreator run /mnt/c/memcached \
  --output "$HOME/hc-runs-structural" \
  --provider ollama \
  --ollama-url http://127.0.0.1:11434 \
  --allow-source-analysis \
  --no-svf \
  --allow-partial-indirect-calls \
  --verification-backend auto \
  --source-only-drafts \
  --scenario-post-fuzz \
  --max-source-drafts 16 \
  --workers 2 \
  --agent-debug \
  2>&1 | tee "$HOME/hc-structural.log"
```

This command **does not** configure the original memcached process, hence produces **unverified source drafts**, not original-runtime-proven targets. Actual original replay requires an appropriate isolated `--scenario-command` and channel matching the specific Action; setting a single channel must not filter source discovery.

Inspect a completed or interrupted run:

```bash
harnesscreator report "$HOME/hc-runs-structural/<run-id>"
harnesscreator report "$HOME/hc-runs-structural/<run-id>" --json
```

Select the actual run directory created inside the output root; do not include the literal brackets.

## Fixed model mapping (unchanged)

| Role | Model | Reasoning |
|---|---|---|
| Entry Generator | `glm-5.3-flash:cloud` | high |
| Entry Verifier | `glm-5.3:cloud` | **low** |
| Input Action / State Dependency / Scenario Refiner | `glm-5.3:cloud` | high |
| Harness Generator | `kimi-k2.7-code:cloud` | default (no `think` override) |
| Harness Verifier | `glm-5.3:cloud` | max |

The old Small/Large Feature roles retain high for backwards compatibility but the active scenario workflow uses Input Action and State Dependency.

## Next non-negotiable acceptance test

Measure on **held-out** daemon projects with different architectures and no user-provided request corpus. Record: Actions discovered, source-grounded Action examples, completed original normal-flow traces, validated Setup/Fuzz/Post sequences, C harnesses generated, linking success, actual target coverage, sanitizer replays, and semantically validated harnesses. Fix generic stage interfaces and input/lifecycle contracts, not named memcached functions. Report **precision and recall separately**, including blocked candidates. Success cannot be declared by unit tests or by generated files alone.
