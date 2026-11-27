
import socket
import threading

from service_detection.mysql import mysql_service_detection


server_ready = threading.Event()


def mock_server():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 3308))
        server.listen(1)

        # Tell the main thread that the server is ready.
        server_ready.set()

        conn, _ = server.accept()

        with conn:
            conn.sendall(b"HELLO FANGRECON\r\n")


thread = threading.Thread(
    target=mock_server,
    daemon=True
)

thread.start()

if not server_ready.wait(timeout=3):
    raise RuntimeError("MySQL mock server failed to start")

result = mysql_service_detection(
    "127.0.0.1",
    3308,
    3
)

print(result)

thread.join(timeout=3)
