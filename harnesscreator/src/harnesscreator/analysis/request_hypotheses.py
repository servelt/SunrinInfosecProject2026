"""Source-located request *trials* for the original daemon.

These bytes are never static proof.  A runtime experiment may refute
them without blocking the other Action candidates.  The helper does not ask
an LLM to invent a protocol or treat a server response as a client request.
"""

from __future__ import annotations

import re


_STRING_COMPARISON = re.compile(
    r"\b(?:strcmp|strncmp|strcasecmp|strncasecmp|memcmp)\s*\("
)
_LITERAL = re.compile(r'"([A-Za-z][A-Za-z0-9_\- ]{0,30})"')
_MEMCACHED_COMMAND_CASE = re.compile(r"^CMD_(GET|GETS|SET|ADD|REPLACE)$")


def source_literal_request_trials(
    discriminator: str,
    *,
    channel: str,
    response_protocol: str = "markers",
) -> list[bytes]:
    """Offer one syntax-supported request guess for a command comparison.

    A branch such as ``strcmp(token, "version") == 0`` names the command,
    but does not prove its framing, argument grammar or state prerequisites.
    Only an independently attributed original-program run can upgrade it.
    """

    lower_channel = channel.casefold()
    if not any(word in lower_channel for word in ("tcp", "udp", "socket", "network", "datagram")):
        return []
    # Modern memcached parses command characters in proto_parser.c, then
    # dispatches on CMD_GET / CMD_SET in proto_text.c. A literal strcmp is
    # therefore *not* present in its request dispatcher. CMD_* case names
    # are syntax candidates only; the parser mapping still needs a runtime
    # trial and an independently attributed causal path.
    enum_case = (_MEMCACHED_COMMAND_CASE.fullmatch(discriminator.strip())
                 if response_protocol == "memcached_ascii" else None)
    if enum_case is not None:
        command = enum_case.group(1).lower().encode("ascii")
    else:
        if not _STRING_COMPARISON.search(discriminator):
            return []
        match = _LITERAL.search(discriminator)
        if match is None:
            return []
        command = match.group(1).strip().encode("ascii")
    if not command or b" " in command:
        return []

    if response_protocol == "memcached_ascii":
        # Memcached's response parser already supports these request forms.
        # Each recipe still requires the source dispatcher to contain its
        # literal command.  The recipe alone is not a source-proof claim.
        if command in {b"get", b"gets"}:
            request = command + b" hc_probe_key\r\n"
        elif command in {b"set", b"add", b"replace"}:
            request = command + b" hc_probe_key 0 0 1\r\nX\r\n"
        else:
            return []
        if any(word in lower_channel for word in ("udp", "datagram")):
            # The standard memcached UDP datagram header: request ID=1,
            # sequence=0, total=1, reserved=0.
            request = b"\x00\x01\x00\x00\x00\x01\x00\x00" + request
    else:
        # A newline is only a trial heuristic, not a universal framing rule.
        request = command + b"\r\n"
    return [request]
