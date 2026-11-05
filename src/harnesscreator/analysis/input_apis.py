"""Known external data-acquisition APIs shared by Entry and AST scheduling.

The list proposes sites to inspect; an API spelling never proves that the
caller is externally reachable or that a particular request selected it.
"""

SOURCE_APIS: dict[str, str] = {
    "recv": "network",
    "recvfrom": "network",
    "recvmsg": "network",
    "SSL_read": "network",
    "BIO_read": "network",
    "read": "fd_or_stream",
    "pread": "file_or_device",
    "readv": "fd_or_stream",
    "preadv": "file_or_device",
    "fread": "file",
    "fread_unlocked": "file",
    "fgets": "file_or_stdin",
    "getc": "file_or_stdin",
    "getchar": "stdin",
    "getchar_unlocked": "stdin",
    "scanf": "stdin",
    "getline": "file_or_stdin",
    "getdelim": "file_or_stdin",
    "readlink": "filesystem",
    "ioctl": "device",
    "ReadFile": "file_or_pipe",
    "WSARecv": "network",
    "WSARecvFrom": "network",
    "SSL_read_ex": "network",
    "gnutls_record_recv": "network",
    "getenv": "environment",
    "mq_receive": "ipc",
    "msgrcv": "ipc",
}

# Direct output-buffer parameters of documented acquisition APIs. This is a
# source-navigation aid only: a call can fail, read zero bytes, write through
# an alias, or be followed by a buffer overwrite. It is never runtime proof.
# read/recv/recvfrom: Linux man-pages read(2), recv(2);
# SSL_read/SSL_read_ex: OpenSSL SSL_read(3).
DIRECT_BUFFER_OUTPUT_ARGUMENTS: dict[str, tuple[int, ...]] = {
    "read": (1,),
    "recv": (1,),
    "recvfrom": (1,),
    "SSL_read": (1,),
    "SSL_read_ex": (1,),
}
