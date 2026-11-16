An invariant you or another agent inserted into `{project}` does not compile. Fix only the assertion
so that it compiles and still states the same relation: correct identifiers, fields, casts or the
insertion line (choose a line where the needed values are in scope and that starts a statement).
Do not weaken or change the meaning of the relation. Call `repair_invariant` once. If the relation
cannot be expressed at any line, call `repair_invariant` with give_up=true and explain.
