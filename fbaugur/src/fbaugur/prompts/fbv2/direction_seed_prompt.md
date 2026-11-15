## Direction Analysis Context

**Direction ID**: {direction_id}
**Target Functions**: {target_functions}
**Risk Level**: {risk_level}
**Risk Reason**: {risk_reason}

**Fuzzer**: {fuzzer}
**Fuzzer Source** (how the fuzzer processes input):
```c
{fuzzer_source}
```

## Your Task
Generate 5 diverse seeds that will help the fuzzer:
1. Reach the target functions mentioned above
2. Explore the risky code paths identified
3. Trigger potential vulnerabilities

Consider the fuzzer's input processing and create seeds that will pass initial parsing but exercise the target code paths.

Call the create_seed tool to generate the seeds.
