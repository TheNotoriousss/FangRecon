
import socket
import threading

import dns.message
import dns.rcode


HOST = "127.0.0.1"
PORT = 5353


def build_response(data):
    try:
        query = dns.message.from_wire(data)
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response.to_wire()
    except Exception:
        return None


def udp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((HOST, PORT))

    print(f"[+] DNS UDP listening on {HOST}:{PORT}")

    while True:
        data, address = server.recvfrom(4096)
        response = build_response(data)

        if response:
            server.sendto(response, address)


def receive_exact(conn, size):
    data = b""

    while len(data) < size:
        chunk = conn.recv(size - len(data))

        if not chunk:
            return None

        data += chunk

    return data


def tcp_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)

    print(f"[+] DNS TCP listening on {HOST}:{PORT}")

    while True:
        conn, address = server.accept()

        with conn:
            try:
                conn.settimeout(3)

                header = receive_exact(conn, 2)

                if header is None:
                    continue

                length = int.from_bytes(header, "big")
                data = receive_exact(conn, length)

                if data is None:
                    continue

                response = build_response(data)

                if response:
                    conn.sendall(
                        len(response).to_bytes(2, "big") + response
                    )

            except (socket.timeout, OSError):
                pass


if __name__ == "__main__":

    threading.Thread(
        target=udp_server,
        daemon=True
    ).start()

    threading.Thread(
        target=tcp_server,
        daemon=True
    ).start()

    print("[+] DNS mock server started")

    try:
        threading.Event().wait()

    except KeyboardInterrupt:
        print("\n[!] DNS mock server stopped")
