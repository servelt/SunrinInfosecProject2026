"""One source-backed transport classifier shared by planning and trials.

An acquisition API such as read/fgets alone does not identify the origin of
the supplied bytes. Unsupported encrypted channels remain unresolved rather
than being replayed as unencrypted TCP.
"""

from __future__ import annotations

import re

from .models import EntryRecord, EntrySiteKind


def _channel_words(channel: str) -> set[str]:
    channel = channel.casefold().replace("-", "_")
    # A source label may explicitly say "non-SSL". That negation is not
    # positive TLS evidence, and it still supplies no TCP family evidence.
    positive_channel = re.sub(
        r"(?<![a-z0-9])non_(?:ssl|tls)(?![a-z0-9])", "", channel,
    )
    return set(re.findall(r"[a-z0-9]+", positive_channel))


def classify_external_transport(channel_kind: str, source_api: str) -> str:
    """Return a concrete executor only when the source identifies one.

    Socket receive APIs and stream/datagram shape do not identify the socket
    family or protocol. Keep their transport unresolved until source
    provenance provides TCP, UDP, or AF_UNIX stream evidence.
    """
    channel = channel_kind.casefold().replace("-", "_")
    words = _channel_words(channel)
    api = source_api.rsplit("::", 1)[-1].casefold()
    if api in {"argv", "argc"}:
        return "argv"
    if api in {"getenv", "envp", "environ"}:
        return "env"
    if words & {"tls", "ssl", "encrypted"} or api in {
        "ssl_read", "ssl_read_ex", "bio_read", "gnutls_record_recv",
    }:
        return "unknown"
    # A single Entry can receive from distinct socket families selected by
    # startup configuration. A union label is not one concrete transport.
    internet_family = bool(words & {"tcp", "udp"}) or any(
        family in channel for family in ("af_inet", "af_inet6", "pf_inet", "pf_inet6")
    )
    unix_family = "unix" in words or "af_unix" in channel or "af_local" in channel
    if internet_family and unix_family:
        return "unknown"
    if unix_family:
        if ("stream" in words and not words & {
            "dgram", "datagram", "seqpacket", "tcp", "udp", "tls", "ssl",
        }):
            return "unix_stream"
        return "unknown"
    if words & {"local", "ipc", "rpc", "netlink", "vsock", "pipe", "fifo"}:
        return "unknown"
    if "tcp" in words and "udp" in words:
        return "unknown"
    if "udp" in words:
        return "udp"
    if "tcp" in words:
        return "tcp"
    if any(token in channel for token in (
        "argv", "command_line", "command line", "argument",
    )):
        return "argv"
    if any(token in channel for token in (
        "environment", "envp", "getenv",
    )):
        return "env"
    if ("stdin" in words or "standard input" in channel) and words & {
        "file", "filesystem", "disk",
    }:
        return "unknown"
    if "stdin" in words or "standard input" in channel or api in {
        "getchar", "getchar_unlocked", "scanf",
    }:
        return "stdin"
    if words & {"filesystem", "file", "disk", "procfs"}:
        return "unknown" if "_or_" in channel or " or " in channel else "file"
    return "unknown"


def permits_explicit_socket_trial(
    channel_kind: str, source_api: str, selected_transport: str,
) -> bool:
    """Allow a configured socket trial without claiming source provenance.

    Only generic network socket reads or unresolved AF_UNIX stream reads are
    eligible. TLS, a known conflicting transport, and datagram/seqpacket Unix
    sockets are not silently replayed over a stream connection.
    """
    if classify_external_transport(channel_kind, source_api) != "unknown":
        return False
    words = _channel_words(channel_kind)
    api = source_api.rsplit("::", 1)[-1].casefold()
    if api not in {"recv", "recvfrom", "recvmsg", "read", "readv", "wsarecv", "wsarecvfrom"}:
        return False
    if selected_transport == "unix_stream":
        return (
            api in {"recv", "recvfrom", "recvmsg", "read", "readv"}
            and "unix" in words
            and not words & {"dgram", "datagram", "seqpacket", "tcp", "udp", "tls", "ssl"}
        )
    if selected_transport not in {"tcp", "udp"}:
        return False
    # An Internet socket family plus type is sufficient for an explicitly
    # configured *trial*, including a source-backed union with Unix sockets.
    # AF_INET/SOCK_STREAM alone does not prove TCP or request delivery; the
    # original request-correlated trace must establish the selected path.
    channel = channel_kind.casefold().replace("-", "_")
    inet4 = bool(re.search(r"(?<![a-z0-9])(?:af|pf)_inet(?![a-z0-9])", channel))
    if (
        selected_transport == "tcp"
        and inet4
        and "stream" in words
        and not words & {"dgram", "datagram", "udp", "tls", "ssl", "encrypted"}
    ):
        return True
    if (
        selected_transport == "udp"
        and inet4
        and bool(words & {"dgram", "datagram"})
        and not words & {"stream", "tcp", "tls", "ssl", "encrypted"}
    ):
        return True
    if words & {
        "unix", "local", "ipc", "rpc", "netlink", "vsock", "tls", "ssl",
        "encrypted", "tcp", "udp", "file", "stdin", "pipe", "fifo",
        "environment", "argv",
    }:
        return False
    return bool(words & {"network", "socket"})


def source_transport(entry: EntryRecord) -> str:
    if entry.site_kind is EntrySiteKind.EXPORTED_API:
        return "unknown"
    if entry.site_kind is EntrySiteKind.PROCESS_START:
        api = entry.source_api.rsplit("::", 1)[-1].casefold()
        if api in {"getenv", "environ", "envp"} or "env" in entry.channel_kind.casefold():
            return "env"
        return "argv"
    return classify_external_transport(entry.channel_kind, entry.source_api)
