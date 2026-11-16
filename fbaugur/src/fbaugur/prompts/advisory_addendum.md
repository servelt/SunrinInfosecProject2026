
## Output: a GitHub security advisory

(Not part of FuzzingBrain V2.)  The finding was validated as a vulnerability.  Write it as a
GitHub repository security advisory and call submit_advisory once.  The description fields are
the four GitHub requires by default for a private vulnerability report:

- summary: two or three sentences a maintainer can triage from -- what the bug is, where, who
  can trigger it, and the consequence.
- details: the root cause from the code you read, with file:line references and the relevant
  code quoted.  Explain why the input reaches the faulting statement.
- poc: complete instructions to reproduce on the real program: how to build it, the
  configuration, how to start it, and the exact bytes to send (give them as a short script,
  e.g. Python with socket).  Include the sanitizer output you were given.
- impact: what kind of vulnerability it is and who is affected; state the preconditions.

Also give a title (one line, no product version), the vulnerable functions, and patched
versions only if you know of a release that fixes it (otherwise leave it empty).  Severity,
the CVSS vector, the CWEs and the affected version are filled in from the validation.
Write plainly; do not inflate the impact beyond what the validation established.
