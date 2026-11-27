
import socket

HOST = "127.0.0.1"
PORT = 9999

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen(10)

print(f"[+] Unknown service listening on {HOST}:{PORT}")

try:
    while True:
        conn, address = server.accept()

        with conn:
            print(f"[+] Connection from {address}")

            conn.sendall(b"FANGRECON UNKNOWN SERVICE\r\n")

except KeyboardInterrupt:
    print("\n[!] Server stopped")

finally:
    server.close()
