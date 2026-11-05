# HarnessCreator — input-discovery / original-execution / build separation

## The architectural change

The **product Entry and Input Action inventory is source-wide**. `--scenario-channel`
no longer excludes other product input surfaces from analysis. An unverified
Entry remains explicitly unverified. The configured executor is only an adapter
used **after** actions and state contracts have been discovered.

1. Static source/graph analysis -> Entry Generator -> Entry Verifier.
2. Input Action Agent analyzes all verified Entries and source-located unresolved
   acquisition candidates (these stay `POSSIBLE`, never auto-`VERIFIED`).
3. State Dependency Agent -> Scenario Planner produces source-backed candidates.
4. Per-scenario original executor chooses `stdin`, `tcp`, `udp`, `file`, `argv`,
   or `env` using source-derived Action metadata, with `--scenario-channel auto`
   (the default). Ambiguous FDs, TLS, IPC, devices, and mixed-channel sequences
   remain `UNPROVEN` unless an appropriate executor is implemented.
5. A causally attributed trace can establish `PROVEN_RUNTIME`; an observed
   response alone at most establishes `REPLAYED_RUNTIME` when exploratory
   drafts are enabled.
6. Harness generation -> static checks -> optional independent build backend;
   no canonical upstream OSS-Fuzz fuzzer build is a source-analysis prerequisite.

The design retains **the existing agents**, **the existing Ollama routing and
thinking levels**, and **the user-provided command as trusted executable
configuration**. No external QuartetFuzz runtime is used.

## Examples

Source inventory and unqualified C draft candidates **without an original
runtime runner or OSS-Fuzz**:

```bash
harnesscreator run /path/to/c-project \
  --output "$HOME/hc-runs" \
  --provider ollama --ollama-url http://127.0.0.1:11434 \
  --allow-source-analysis --no-svf --allow-partial-indirect-calls \
  --max-source-drafts 8
```

This is not a verified fuzzing harness: C code generated without original-run
proof is stored as `UNVERIFIED_SOURCE_DRAFT`. If no statically supported scenario
or execution context is found, there might be **no C draft**.

One TCP memcached run (only the original execution is TCP; source discovery
remains global), **without any OSS-Fuzz registration or existing fuzzer**:

```bash
SRC=/mnt/c/memcached
harnesscreator run "$SRC" \
  --output "$HOME/hc-runs" \
  --provider ollama --ollama-url http://127.0.0.1:11434 \
  --allow-source-analysis --no-svf --allow-partial-indirect-calls \
  --scenario-command "$SRC/memcached -p 11211 -U 0 -l 127.0.0.1 -u root" \
  --scenario-channel tcp --scenario-host 127.0.0.1 --scenario-port 11211 \
  --scenario-attribution gdb --scenario-response-protocol memcached_ascii \
  --scenario-exploratory-drafts --source-only-drafts --scenario-post-fuzz \
  --verification-backend auto \
  --workers 2 --fuzz-seconds 60 --agent-debug
```

Native compilation can fail for complex program-specific build/link graphs.
Such a failure affects only that harness attempt; it does not make the source
inventory OSS-Fuzz-dependent or permit an unproven QUALIFIED verdict. See
[INDEPENDENT_BUILD_WORKFLOW.md](INDEPENDENT_BUILD_WORKFLOW.md) for details.

For a program that reads **one file per process**:

```bash
--scenario-command '/path/to/binary {input_file}' \
--scenario-channel auto --scenario-exploratory-drafts
```

`{input_file}` is replaced with an isolated temporary file containing exactly
the source-derived request bytes. This adapter needs a known argv shape; it does
not invent a filename option.

For an **argv** parser:

```bash
--scenario-command '/path/to/binary --parse {input_arg}' \
--scenario-channel auto --scenario-exploratory-drafts
```

For **getenv** input:

```bash
--scenario-command '/path/to/binary' \
--scenario-channel auto --scenario-exploratory-drafts
```

A unique literal `getenv("NAME")` in the source-acquisition function is used
to infer the variable name, otherwise specify `--scenario-input-env NAME`.
`argv` and environment variable values cannot contain NUL bytes; those requests
remain unproven rather than being truncated.

`file`, `argv`, and `env` are currently **single-shot subprocess** adapters.
A multi-request stateful sequence, mixed-channel input, or a mutable filesystem
lifecycle needs a separately evidenced state-preserving executor. A successful
stdout marker alone never grants causal proof.

## Useful artifacts

- `entries/`: source-derived Entry candidates, verified and unresolved records.
- `actions/inventory.jsonl`: recovered Actions across **all** input surfaces.
- `actions/execution-surfaces.json`: per-Action inferred executor and source proof.
- `scenarios/candidates.jsonl`: state-dependent scenario candidates.
- `scenarios/source-only-drafts.json`: selected unproven draft candidates.
- `harnesses/<id>/attempt-*/source-only-status.json`: `UNVERIFIED_SOURCE_DRAFT`
  or `NO_SOURCE_DRAFT_GENERATED`, never `QUALIFIED`.
- `harness-plans/`: preserved execution boundary contracts.

## Limits, not success claims

The new tests compile and execute a small C file/argv/env fixture and verify
that response-only runs are **not** labeled `PROVEN_RUNTIME`. This is not an
unseen-program end-to-end LLM success-rate measurement. Broad source discovery,
protocol synthesis, initialization/reset, threaded event handoffs, complete
file-based state transitions, crash equivalence, and generalized source
instrumentation remain difficult and need separate empirical evaluation.

Run `python -m pytest -q` for the current regression suite.
