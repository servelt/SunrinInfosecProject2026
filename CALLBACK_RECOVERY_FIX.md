# HarnessCreator callback-dispatch recovery (2026-10-22)

## Scope

This patch is based on `HarnessCreator_ossfuzz_independent_native.zip` and **does not change the Ollama model/effort routing** or reintroduce OSS-Fuzz project-recipe dependencies.

## The two hard blocks addressed

1. The read/parse path of an event-driven program often looks like `read_callback <- read_loop <- event_loop -> protocol_callback -> request_dispatcher`. The direct call graph misses source-level callback assignment/invocation pairs. `GraphStore.callback_slot_candidates()` now records *lexical navigational candidates* using pointer-member registrations and invocation sites. Known, conflicting object pointer types are rejected. The optional bounded `callback_navigation_path()` is **not** injected into authoritative CallEdges or static-proven reachability. It exists to open the source leading to dispatcher candidate, not to assert that the runtime object identity, execution or input provenance is established.
2. `InputActionAgent` can now continue source inspection along a hinted candidate callback path, retaining the corresponding branch work as `POSSIBLE` if the authoritative path is absent. The source-only orchestrator can plan `POSSIBLE` actions if the dispatcher, handler and concrete request have cited source evidence. Runtime qualification is NOT relaxed.

Further repairs:
- A source-only candidate is constructed even if its action lacks a literal success-output marker (the missing oracle remains a runtime verification limitation).
- `ScenarioRuntimeVerifier` in `auto` mode preserves the Action's inferred `tcp`, `udp`, `stdin`, `file`, `argv`, or `env` channel in an `UNPROVEN` source-only witness even when no original command was configured, preventing a spurious `unsupported_transport` HarnessPlan.
- `--scenario-exploratory-drafts` no longer rejects response replay before execution merely because GDB was installed but exact branch probe metadata was absent. Such response-only replays remain `REPLAYED_RUNTIME` or `UNPROVEN`, never `PROVEN_RUNTIME` on the strength of a reply alone.
- `StateDependencyAgent` also accepts cited `POSSIBLE` actions when source-only draft mode is enabled, without promoting their contracts to static proof.

## Validation

- `tests/test_callback_candidate_recovery.py`: 8 tests, all passed (synthetic source-level callback return/path and rejection of unrelated callback types, candidate branch traversal, runtime gate semantics, inferred transport).
- Existing focused test groups: 133 passed in one run; `test_scenario_orchestrator.py`, `test_universal_executor.py` and new tests: 16 passed plus 3 subtests in another run.
- Full test suite was not completed: it exceeded the available run time. Three other original scenario tests also fail under this environment; two of those were reproduced on the unmodified baseline, so do not claim full regression success.
- Crucially, the actual user's `/mnt/c/memcached` source tree, Ollama credentials/service, GDB and the WSL Clang build were **not available** in this environment. This patch has NOT been verified to generate a memcached harness automatically, and does not solve the project's full build graph, runtime instrumentation or state reset fidelity.

## Suggested WSL checks

```bash
# Within a virtual environment using this installed code:
python -m pytest -q tests/test_callback_candidate_recovery.py
which clang clang++ || true
harnesscreator run /mnt/c/memcached \
  --output "$HOME/hc-callback-candidate-run" \
  --provider ollama \
  --ollama-url http://127.0.0.1:11434 \
  --allow-source-analysis --no-svf --allow-partial-indirect-calls \
  --scenario-channel auto \
  --scenario-exploratory-drafts --source-only-drafts --max-source-drafts 8 \
  --verification-backend auto --workers 2 --agent-debug \
  2>&1 | tee "$HOME/hc-callback-candidate.log"
```

Do not interpret a SOURCE_ONLY_UNVERIFIED or REPLAYED_RUNTIME result as verified. Verify actual Action count, branch path, generated `harnesses/*/attempt-*/fuzz_target.*`, compilation, sanitizer execution and original/harness semantic equivalence independently.
