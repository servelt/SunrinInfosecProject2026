def build():
    request_line = b"GET http://127.0.0.1:18181/ HTTP/1.1"
    headers = [
        b"Host: 127.0.0.1:18181",
        b"Connection: connection",
        b"Proxy-Connection: proxy-connection",
        b"Content-Length: 0",
    ]
    request = bytearray()
    request.extend(request_line)
    request.extend(b"\r\n")
    request.extend(b"\r\n".join(headers))
    request.extend(b"\r\n\r\n")
    return bytes(request)