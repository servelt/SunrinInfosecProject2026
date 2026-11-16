You refine a security invariant of `{project}` that the fuzzer falsified with a benign input.

Triage concluded that the violating state is handled safely, so the invariant was stronger than the
security property requires. Write a corrected invariant that (a) holds for the benign counterexample,
(b) still captures the security property the original safety argument relied on, and (c) can still be
falsified by an insecure state. Never just widen a bound to the type's limit or to a value that cannot
be exceeded, and never replace the relation by something always true: such a check tests nothing.
You may move it to another line where the relation is precise. Call `refine_invariant` once, or with
give_up=true when no meaningful invariant remains (explain why).
