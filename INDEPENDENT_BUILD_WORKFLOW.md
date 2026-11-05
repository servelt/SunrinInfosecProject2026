# HarnessCreator: OSS-Fuzz project registration is **not required**

## What changed

The CLI's default `--verification-backend auto` **never** selects an OSS-Fuzz
project recipe, even if an OSS-Fuzz checkout exists. Instead, it generates
separate native Clang/libFuzzer build commands for the C/C++ harness it just
created. No `projects/<name>`, `fuzzer_proxy`, existing OSS-Fuzz harness,
`Dockerfile`, or `patch.diff` is needed for this path.

- **Discovery**: all source-level Entries and Actions regardless of channel.
- **Original execution**: optional, scenario-specific stdin/TCP/UDP/file/argv/env
  adapters. Without proof, a draft stays unqualified.
- **Generated harness build**: independent Clang compiler, optional source
  `compile_commands.json`, ASan/UBSan/libFuzzer instrumentation.
- **Verification**: the existing Harness Verifier's build, deterministic replay,
  reachability, sanitizer and fuzz checks. Build success alone is not QUALIFIED.

No agent or Ollama model effort allocation was modified.

## OSS-Fuzz-free run for any source checkout

```bash
harnesscreator run /path/to/c-or-cpp-project \
  --output "$HOME/hc-runs" \
  --provider ollama \
  --ollama-url http://127.0.0.1:11434 \
  --allow-source-analysis --no-svf --allow-partial-indirect-calls \
  --verification-backend auto \
  --max-source-drafts 8 --workers 2 --agent-debug
```

`--scenario-command` and `--scenario-channel` are **not needed to discover**
source-level input paths. When omitted, the default source-only candidate path
can generate unqualified C drafts and try to compile them. Runtime qualification
still requires evidence from the original program; no invented witness is allowed.

For memcached's TCP original-execution case, append only the actual original
program configuration and any desired scenario options:

```bash
SRC=/mnt/c/memcached
harnesscreator run "$SRC" \
  --output "$HOME/hc-runs" \
  --provider ollama --ollama-url http://127.0.0.1:11434 \
  --allow-source-analysis --no-svf --allow-partial-indirect-calls \
  --verification-backend auto \
  --scenario-command "$SRC/memcached -p 11211 -U 0 -l 127.0.0.1 -u root" \
  --scenario-channel tcp --scenario-host 127.0.0.1 --scenario-port 11211 \
  --scenario-attribution gdb --scenario-response-protocol memcached_ascii \
  --scenario-exploratory-drafts --source-only-drafts --scenario-post-fuzz \
  --workers 2 --fuzz-seconds 60 --agent-debug
```

This tests only the explicitly configured TCP original-execution path. Source
discovery remains global. With GDB only, causal request-to-handler proof can be
missing, and this must remain unqualified. Auto native build is **not** proven
to support all of memcached's dependency and link layout.

## How auto native builds work

1. Read `compile_commands.json` from the checkout root, `build/`, or
   `out/build/` when one is available. Otherwise accept only a small,
   unambiguous root/`src/` C/C++ source layout.
2. Compile the selected original translation units with Clang plus
   sanitizer/fuzzer-no-link instrumentation, preserving supported compile-db
   macro and include settings. Never execute `command` entries from the JSON.
3. Rename the single original program `main` at compile time to avoid a clash
   with the libFuzzer runtime; reject multiple main definitions.
4. Compile the newly generated harness as a separate translation unit.
5. Link with libFuzzer/ASan/UBSan. Write `build-plan.json` under the attempt's
   `.native-build/` directory for audit.
6. Run the existing independent verification gates if a runtime witness exists.

## Fail-closed boundaries

A `compile_commands.json` is only compilation metadata; it does not always
specify link closures, generated sources or required external libraries.
Complex projects (large servers, multiple executables, custom code-generation
steps, missing system libraries) can fail the standalone build. This is
reported as `NATIVE_BUILD_UNRESOLVED`, not concealed or counted as a verified
harness. **There is no guarantee that unmodified memcached is auto-linkable.**

For such projects, the existing command backend can reuse their *actual*
custom build script, without registering them in OSS-Fuzz:

```bash
harnesscreator run /path/to/project \
  --verification-backend command \
  --build-command 'python3 /trusted/project-specific-build.py {harness} {output}' \
  --binary '{output}/fuzz_target' \
  --provider ollama --ollama-url http://127.0.0.1:11434
```

The script/path above is an **example interface**, not a script bundled in
HarnessCreator. Do not execute it unless you have that actual build script.
Only the caller can provide trusted build commands; LLMs must not create or
execute arbitrary shell commands through this interface.

`--verification-backend oss-fuzz` still exists as an explicitly requested
legacy adapter for already-registered upstream projects. It is no longer
selected by default and is not used by the standalone backend.

## Testing scope

The standalone backend has been exercised using real Clang/LLVM on a synthetic
single-file C program with `main` renaming, a two-file C program, and a
libFuzzer smoke run. The tests also verify that projects with multiple
competing executables or unresolved symbols fail closed, and that the CLI
will not silently switch to OSS-Fuzz when an OSS-Fuzz path is present.

Those tests are **not** proof that arbitrary real-world daemons will compile,
or that the LLM will autonomously generate valid harnesses for them.
