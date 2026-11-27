import socket
import ssl
import threading

from service_detection.https import https_service_detection


def mock_tls_server():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 8443))
    server.listen(1)

    conn, _ = server.accept()

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("test_cert.pem", "test_key.pem")

    with context.wrap_socket(conn, server_side=True) as tls_conn:

        tls_conn.recv(4096)

        tls_conn.sendall(b"HELLO FANGRECON\r\n")

    server.close()


thread = threading.Thread(
    target=mock_tls_server,
    daemon=True
)

thread.start()

result = https_service_detection(
    "127.0.0.1",
    8443,
    3
)

print(result)

thread.join()
