
import socket
import threading

from service_detection.postgresql import postgresql_service_detection


HOST = "127.0.0.1"
PORT = 5434

server_ready = threading.Event()


def mock_server():

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:

        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(1)

        print(f"Fake service listening on {HOST}:{PORT}")

        server_ready.set()

        conn, address = server.accept()

        with conn:
            print(f"Connection received from {address}")

            # Receive PostgreSQL SSLRequest.
            request = conn.recv(8)
            print(f"Received: {request!r}")

            # Send an invalid PostgreSQL SSL response.
            conn.sendall(b"X")

            print("Sent invalid PostgreSQL SSL response.")


thread = threading.Thread(
    target=mock_server,
    daemon=True
)

thread.start()

if not server_ready.wait(timeout=3):
    raise RuntimeError("Mock server failed to start")

result = postgresql_service_detection(
    HOST,
    PORT,
    3
)

print("\nFangRecon result:")
print(result)

thread.join(timeout=3)
