import socket

HOST = "127.0.0.1"
PORT = 2121

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(10)

print(f"FTP mock server listening on {HOST}:{PORT}")

try:
    while True:
        conn, addr = server.accept()

        with conn:
            conn.settimeout(2)

            try:
                conn.sendall(
                    b"220 Welcome to FangRecon FTP Server\r\n"
                )

                command = conn.recv(1024).decode(
                    errors="replace"
                ).strip()

                print(f"Received: {command}")

                if command.upper() == "FEAT":
                    conn.sendall(
                        b"211-Features:\r\n"
                        b" UTF8\r\n"
                        b"211 End\r\n"
                    )

                elif command.upper().startswith("EHLO"):
                    conn.sendall(b"500 Command not recognized\r\n")

            except (socket.timeout, ConnectionError):
                pass

except KeyboardInterrupt:
    print("\nFTP mock server stopped.")

finally:
    server.close()
