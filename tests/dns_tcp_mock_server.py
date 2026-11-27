import socket

import dns.message
import dns.rcode


HOST = "127.0.0.1"
PORT = 5354


def receive_exact(conn, size):
    data = b""

    while len(data) < size:
        chunk = conn.recv(size - len(data))

        if not chunk:
            return None

        data += chunk

    return data


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(5)

    print(f"TCP-only DNS server listening on {HOST}:{PORT}")

    try:
        while True:
            conn, address = server.accept()

            with conn:
                header = receive_exact(conn, 2)

                if header is None:
                    continue

                length = int.from_bytes(header, "big")
                data = receive_exact(conn, length)

                if data is None:
                    continue

                query = dns.message.from_wire(data)
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.NXDOMAIN)

                response_data = response.to_wire()

                conn.sendall(
                    len(response_data).to_bytes(2, "big")
                    + response_data
                )

    except KeyboardInterrupt:
        print("\nTCP-only DNS server stopped.")

    finally:
        server.close()


if __name__ == "__main__":
    main()
