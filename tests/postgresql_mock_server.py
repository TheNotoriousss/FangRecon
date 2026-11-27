
import socket
import struct

HOST = "127.0.0.1"
PORT = 5433


def recv_exact(client, size):
    data = b""

    while len(data) < size:
        chunk = client.recv(size - len(data))

        if not chunk:
            return None

        data += chunk

    return data


def send_parameter_status(client, name, value):

    payload = (
        name.encode() + b"\x00" +
        value.encode() + b"\x00"
    )

    message = (
        b"S" +
        struct.pack("!I", len(payload) + 4) +
        payload
    )

    client.sendall(message)


def handle_client(client):

    # Receive SSLRequest
    request = recv_exact(client, 8)

    if request is None or len(request) != 8:
        print("[!] Invalid SSLRequest")
        return

    length, request_code = struct.unpack("!II", request)

    if length != 8 or request_code != 80877103:
        print("[!] Unexpected initial request")
        return

    # Refuse SSL so we can test plaintext startup
    client.sendall(b"N")

    print("[+] SSLRequest received; SSL refused")

    # Receive StartupMessage length
    header = recv_exact(client, 4)

    if header is None:
        return

    message_length = struct.unpack("!I", header)[0]

    if message_length < 8 or message_length > 10000:
        print("[!] Invalid StartupMessage length")
        return

    # Receive remaining StartupMessage
    startup_data = recv_exact(client, message_length - 4)

    if startup_data is None:
        return

    protocol_version = struct.unpack("!I", startup_data[:4])[0]

    print(f"[+] StartupMessage received")
    print(f"[+] Protocol version: {protocol_version}")

    # AuthenticationOk
    auth_ok = (
        b"R" +
        struct.pack("!II", 8, 0)
    )

    client.sendall(auth_ok)

    # ParameterStatus messages
    send_parameter_status(
        client, "server_version", "16.4-fangrecon-mock"
    )

    send_parameter_status(
        client, "server_encoding", "UTF8"
    )

    send_parameter_status(
        client, "client_encoding", "UTF8"
    )

    # ReadyForQuery
    ready = b"Z" + struct.pack("!I", 5) + b"I"

    client.sendall(ready)

    print("[+] Sent PostgreSQL server parameters")


def start_server():

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(5)

    print(f"[+] Mock PostgreSQL server listening on {HOST}:{PORT}")

    try:
        while True:

            client, address = server.accept()

            print(f"[+] Connection received from {address}")

            with client:
                client.settimeout(5)
                handle_client(client)

    except KeyboardInterrupt:
        print("\n[!] Mock server stopped")

    finally:
        server.close()


if __name__ == "__main__":
    start_server()
