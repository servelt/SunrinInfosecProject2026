
## Recording the reason for a "safe" verdict (required)

This audit also turns every safety judgment into an executable check: when you conclude that an SP
cannot be triggered because of a protection, a guard, an earlier check, a type range or an invariant
of the program, the relation you relied on is written into the program as an assertion and a
fuzzer then tries to break it. So whenever you mark an SP as a false positive OR give it a score
below 0.5 because something keeps the operation safe, also pass to update_suspicious_point:

- safety_reason: the exact relation between runtime values that makes the operation safe, stated as
  a condition that must hold (e.g. "c->rbytes <= c->rsize when memmove copies c->rbytes bytes into c->rbuf"),
  and why you believe it always holds.
- safety_location: `file:line` of the source line just before which that relation must hold
  (normally the line of the risky operation itself).

Give these even when the protection is a visible bounds check: what you are asserting is the relation
the check is supposed to guarantee at the operation, not the check itself. Do not fill them for
reachability-only or sanitizer-mismatch false positives.
