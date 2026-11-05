import json
import socket
import subprocess
import time

port = 19099
requests = [b"SET a\n", b"GET a\n"]
process = subprocess.Popen(["/work/daemon", str(port)])
responses = []
try:
    for attempt in range(100):
        try:
            connection = socket.create_connection(("127.0.0.1", port), 0.1)
            break
        except OSError:
            time.sleep(0.01)
    else:
        raise RuntimeError("daemon did not bind")
    with connection:
        connection.settimeout(1.0)
        for request in requests:
            connection.sendall(request)
            responses.append(connection.recv(128))
finally:
    process.terminate()
    process.wait(timeout=2)
with open("/work/replay.json", "w", encoding="utf-8") as output:
    json.dump({
        "requests": [item.hex() for item in requests],
        "responses": [item.hex() for item in responses],
    }, output)
