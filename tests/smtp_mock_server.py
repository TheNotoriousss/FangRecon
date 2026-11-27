
import socket

HOST = "127.0.0.1"
PORT = 2525

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(10)

print(f"SMTP mock server listening on {HOST}:{PORT}")

try:
    while True:
        conn, addr = server.accept()

        with conn:
            conn.settimeout(2)

            try:
                conn.sendall(
                    b"220 mail.fangrecon.local ESMTP Postfix 3.8.6\r\n"
                )

                command = conn.recv(1024).decode(
                    errors="replace"
                ).strip()

                print(f"Received: {command}")

                if command.upper().startswith("EHLO"):
                    conn.sendall(
                        b"250-mail.fangrecon.local\r\n"
                        b"250-PIPELINING\r\n"
                        b"250 SIZE 1024000\r\n"
                    )
                else:
                    conn.sendall(b"500 Command not recognized\r\n")

            except (socket.timeout, ConnectionError):
                pass

except KeyboardInterrupt:
    print("\nSMTP mock server stopped.")

finally:
    server.close()
