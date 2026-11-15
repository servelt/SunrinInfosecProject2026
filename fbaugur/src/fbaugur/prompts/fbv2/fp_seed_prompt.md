## False Positive Analysis Context

**SP ID**: {sp_id}
**Function**: {function_name}
**Vulnerability Type**: {vuln_type}
**Description**: {description}

This suspicious point was analyzed but determined to be a False Positive. However, the code pattern is still interesting for fuzzing.

**Fuzzer**: {fuzzer}
**Fuzzer Source**:
```c
{fuzzer_source}
```

## Your Task
Generate 5 seeds that:
1. Target the same code path that triggered this false positive
2. Try variations that might trigger a REAL vulnerability in similar code
3. Explore edge cases around the pattern that was flagged

The goal is to use this "near miss" to find actual bugs in related code.

Call the create_seed tool to generate the seeds.
