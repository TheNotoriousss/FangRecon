import socket
import threading

from service_detection.smtp import smtp_service_detection


def mock_smtp_server():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind(("127.0.0.1", 2525))
    server.listen(1)

    conn , _ = server.accept()

    with conn:
        conn.sendall(
            b"220 mail.fangrecon.local ESMTP Postfix 3.8.6\r\n"
        )

        command = conn.recv(1024)

        if command.startswith(b"EHLO"):
            conn.sendall(
                b"500 Command not recognized\r\n"
            )
        server.close()


thread = threading.Thread(
    target=mock_smtp_server,
    daemon=True
)

thread.start()

result = smtp_service_detection(
    "127.0.0.1",
    2525,
    3
)

print(result)

thread.join()
