from csv import reader
import socket
import threading

from service_detection.ftp import ftp_service_detection


def mock_ftp_server():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind(("127.0.0.1", 2121))
    server.listen(1)

    conn, _ = server.accept()

    with conn:

        conn.sendall(
            b"220 Welcome to FangRecon FTP Server\r\n"
        )

        reader = conn.makefile("rb")

        command = reader.readline()

        if command.startswith(b"FEAT"):
            conn.sendall(b"502 FEAT not supported\r\n")

            command = reader.readline()

            if command.startswith(b"SYST"):
                conn.sendall(b"502 SYST not supported\r\n")

    server.close()


thread = threading.Thread(
    target=mock_ftp_server,
    daemon=True
)

thread.start()

result = ftp_service_detection(
    "127.0.0.1",
    2121,
    3
)

print(result)

thread.join()
