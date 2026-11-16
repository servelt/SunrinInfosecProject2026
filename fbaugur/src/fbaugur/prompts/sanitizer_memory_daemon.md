### MemorySanitizer: state one request leaves for another (addition for daemon harnesses)

A long-running server keeps per-connection or per-session state across requests, and the read
of uninitialized memory is often not visible inside one function:

- A buffer or field allocated per connection (malloc, not calloc) and written by one command,
  then read by another command.  Requests arrive in whatever order the peer chooses, so the
  reader can run first and read memory nothing has written yet.  For every field this function
  reads, check where it is allocated and which command writes it -- not only whether this
  function initializes it.
- A "current user", "current file", "pending operation" or "offset" value that a later command
  assumes an earlier command has already set.
