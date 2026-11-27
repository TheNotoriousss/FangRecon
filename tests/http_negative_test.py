
import socket
import threading

from service_detection.http import http_service_detection


server_ready = threading.Event()


def mock_http_server():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind(("127.0.0.1", 8081))
    server.listen(1)

    server_ready.set()

    conn, _ = server.accept()

    with conn:

        conn.recv(4096)

        response = (
            b"HELLO FANGRECON\r\n"
            b"Welcome to this test service\r\n"
        )

        conn.sendall(response)

    server.close()


thread = threading.Thread(
    target=mock_http_server,
    daemon=True
)

thread.start()

if not server_ready.wait(timeout=3):
    raise RuntimeError("HTTP mock server failed to start")

result = http_service_detection(
    "127.0.0.1",
    8081,
    3
)

print(result)

thread.join(timeout=3)
