
import socket

servers = []

for port in range(10050, 10060):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    servers.append(sock)
    print(f"Silent UDP server listening on {port}")

print("All 10 silent UDP ports are ready.")

while True:
    for sock in servers:
        try:
            sock.recvfrom(4096)
        except BlockingIOError:
            pass
