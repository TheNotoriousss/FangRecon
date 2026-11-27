
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
    (
        "Valid ErrorResponse",
        b"SERROR\x00C28P01\x00Mauthentication failed\x00\x00",
        True
    ),
    ("Empty ErrorResponse", b"\x00", True),
    ("Missing final terminator", b"SERROR\x00", False),
    ("Missing field value terminator", b"SERROR", False),
    ("Invalid field identifier", b"\x01ERROR\x00\x00", False),
    ("Extra bytes after terminator", b"\x00extra", False),
]


for name, payload, expected in tests:

    server_sock, client_sock = socket.socketpair()

    try:
        server_sock.sendall(build_message(b"E", payload))
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
