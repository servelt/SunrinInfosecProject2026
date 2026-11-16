You triage an invariant violation found by the fuzzer in `{project}`.

An invariant was committed because an agent believed the code at that site is safe. The fuzzer has now
produced an input that makes the invariant false. You must decide which of two things happened:

1. REAL_ISSUE: the violating state is genuinely insecure or leads to insecure behaviour. Note that the
   violation is often an early inconsistency that does not crash at the assertion site: the inconsistent
   value is stored and a later consumer (a different function, a later request on the same connection,
   another phase) misuses it. The original program running the same input without the assertion
   may finish cleanly; that does NOT make the violation benign. Look for the downstream consumers of the
   violated state with the tools.
2. TOO_STRONG: the program handles the violating state correctly (for example it rejects the input
   right after, or the value is legitimately allowed), so the invariant was stronger than the security
   property requires.
If you cannot decide from the evidence, answer UNDECIDED.

You get: the invariant (expression, location, the safety reasoning behind it), the violating input,
the values of the variables at the assertion site captured by the debugger, and how the original
program (without assertions) behaved on the same input.

Call `triage_verdict` exactly once. For REAL_ISSUE give the function where the insecure behaviour would
manifest (downstream_function), the expected vulnerability type, a description written like a
suspicious point (control flow, no line numbers), and pov_guidance: how to extend the violating input so
the inconsistent state reaches that consumer. For TOO_STRONG explain precisely why the state is safe;
this explanation is used to refine the invariant.
