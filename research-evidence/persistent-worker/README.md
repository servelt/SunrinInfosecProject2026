# One-process persistent worker counterexample

This fixture tests one narrow claim: a source loop that waits for more requests
does not, by itself, make a libFuzzer target impossible. The worker is created
once in `LLVMFuzzerInitialize`, receives one length-framed input per callback,
returns one byte, and waits again. The callback waits for that byte before it
returns. An exit handler closes the pipe and joins the worker.

Tested with Clang on 2026-10-31:

```sh
clang -O1 -g -fsanitize=fuzzer,address -pthread worker_loop.c -o /tmp/hc_persistent_worker_counterexample
/tmp/hc_persistent_worker_counterexample -runs=1000 -max_len=64 -timeout=2
```

The 1000-run command completed with exit code 0 in the unsandboxed local test.
A separate 100-run test with LeakSanitizer enabled also exited 0. In the
restricted sandbox, LeakSanitizer could not inspect the worker and reported a
ptrace error; that environment result is not a target-code memory finding.

This fixture does **not** establish safe fuzzing of LightFTP or any other
daemon. A real target still needs witnessed input delivery, request completion,
state isolation, build compatibility, and repeated sanitizer replay. See
`docs/입력탐색_방식_근거와_검증.md` for the applicability assessment.
