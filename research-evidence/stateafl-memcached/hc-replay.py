import json
import socket
import subprocess
import time


port = 19099
requests = [b"set hc_key 0 0 1\r\nx\r\n", b"get hc_key\r\n"]
process = subprocess.Popen([
    "/work/memcached", "-u", "root", "-p", str(port), "-U", "0",
    "-l", "127.0.0.1", "-t", "1", "-m", "16",
])
responses = []
try:
    for _ in range(100):
        try:
            connection = socket.create_connection(("127.0.0.1", port), 0.1)
            break
        except OSError:
            time.sleep(0.02)
    else:
        raise RuntimeError("memcached did not bind")
    with connection:
        connection.settimeout(2)
        for request in requests:
            connection.sendall(request)
            responses.append(connection.recv(1024))
finally:
    process.terminate()
    process.wait(timeout=3)
with open("/work/hc-replay.json", "w", encoding="utf-8") as output:
    json.dump({
        "requests": [item.hex() for item in requests],
        "responses": [item.hex() for item in responses],
    }, output)
