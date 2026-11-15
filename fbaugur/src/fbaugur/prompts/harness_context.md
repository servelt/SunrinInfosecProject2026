## Target harness (read this as "the fuzzer" in the instructions above)

The fuzzer is the libFuzzer harness `{harness_name}`, built from the original program `{project}`
with {sanitizer_text}.

{delivery_text}

- get_fuzzer_info returns the harness source. Read it when you need the exact delivery logic.
- Function names refer to the original program. File paths in all tools are relative to the source root.
- {target_count} functions of the program are reachable from this harness's input entry points
  ({entry_text}). The call graph comes from static analysis and misses some function-pointer calls.
- Generator code for create_pov / create_seed / trace_pov defines `generate(...)` returning either
  `bytes` (the whole harness input) or a `list` of `bytes` messages. {message_rule}
