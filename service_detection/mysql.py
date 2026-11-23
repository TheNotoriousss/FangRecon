
import socket

from service_detection.fingerprint import create_fingerprint


def receive_exact(sock, length):

    data = b""

    while len(data) < length:

        chunk = sock.recv(length - len(data))

        if not chunk:
            raise ConnectionError("Connection closed by server")

        data += chunk

    return data


def mysql_service_detection(target, port, timeout):

    details = {
        "protocol_version": None,
        "greeting": None,
        "error": None
    }

    try:

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)
            sock.connect((target, port))

            # Read MySQL packet header.
            header = receive_exact(sock, 4)

            payload_length = int.from_bytes(
                header[:3],
                byteorder="little"
            )

            sequence_id = header[3]

            if payload_length < 2 or payload_length > 65536:
                raise ValueError("Invalid MySQL greeting packet length")

            if sequence_id != 0:
                raise ValueError("Invalid MySQL greeting sequence ID")

            payload = receive_exact(sock, payload_length)

            protocol_version = payload[0]
            details["protocol_version"] = protocol_version

            if protocol_version != 10:
                raise ValueError("Invalid MySQL protocol version")

            # Server version must be null-terminated.
            version_end = payload.find(b"\x00", 1)

            if version_end == -1:
                raise ValueError("Invalid MySQL server version field")

            version_bytes = payload[1:version_end]

            if not version_bytes:
                raise ValueError("Empty MySQL server version")

            server_version = version_bytes.decode(
                errors="replace"
            )

            # Validate the minimum structure following server version.
            if len(payload) < version_end + 14:
                raise ValueError("Incomplete MySQL greeting packet")

            details["greeting"] = payload.decode(
                errors="replace"
            )

            return create_fingerprint(
                service="MySQL",
                product="MySQL",
                version=server_version,
                details=details
            )

    except (socket.timeout, OSError, ValueError) as e:

        details["error"] = str(e)

    return create_fingerprint(
        service=None,
        details=details
    )
