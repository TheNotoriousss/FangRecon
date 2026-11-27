
import socket
import struct

from service_detection.postgresql import read_server_responses


def build_message(message_type, payload):
    return (
        message_type
        + struct.pack("!I", len(payload) + 4)
        + payload
    )


tests = [
    ("Valid server version", b"server_version\x0016.4\x00", True),
    ("Valid empty value", b"server_version\x00\x00", True),
    ("Empty parameter name", b"\x0016.4\x00", False),
    ("Missing final terminator", b"server_version\x0016.4", False),
    ("Extra field", b"server_version\x0016.4\x00extra\x00", False),
    ("Invalid UTF-8", b"\xff\x0016.4\x00", False),
]


for name, payload, expected in tests:

    server_sock, client_sock = socket.socketpair()

    try:
        message = build_message(b"S", payload)

        if expected:
            message += build_message(b"Z", b"I")

        server_sock.sendall(message)
        server_sock.close()

        details = {"server_parameters": {}, "error": None}

        version, confirmed = read_server_responses(
            client_sock,
            details
        )

        passed = confirmed == expected

        print(
            f"{'PASS' if passed else 'FAIL'}: {name} "
            f"| Confirmed: {confirmed} "
            f"| Details: {details}"
        )

    finally:
        client_sock.close()

        try:
            server_sock.close()
        except OSError:
            pass