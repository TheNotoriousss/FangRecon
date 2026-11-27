
import socket
import threading
import time

HOST = "127.0.0.1"
PORT = 8082

connection_count = 0
count_lock = threading.Lock()


def handle_client(conn, address):
    global connection_count

    with count_lock:
        connection_count += 1
        attempt = connection_count

    with conn:
        print(f"[+] Connection {attempt} from {address}")

        if attempt <= 2:
            print(f"[+] Delaying connection {attempt}")
            time.sleep(0.8)
            return

        try:
            conn.settimeout(2)
            request = conn.recv(4096)

            print("[+] HTTP request received")

            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: FangRecon-Test/1.0\r\n"
                b"Content-Length: 2\r\n"
                b"Connection: close\r\n"
                b"\r\nOK"
            )

            conn.sendall(response)

        except (socket.timeout, OSError) as error:
            print(f"[-] Connection error: {error}")


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(10)

print(f"[+] Timeout test server listening on {HOST}:{PORT}")

try:
    while True:
        conn, address = server.accept()

        threading.Thread(
            target=handle_client,
            args=(conn, address),
            daemon=True
        ).start()

except KeyboardInterrupt:
    print("\n[!] Server stopped")

finally:
    server.close()
