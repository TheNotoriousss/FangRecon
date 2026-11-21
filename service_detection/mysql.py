import socket


def receive_exact(sock, length):

    data = b""

    while len(data) < length:
        chunk = sock.recv(length - len(data))

        if not chunk:
            raise ConnectionError("Connection closed by server")

        data += chunk

    return data


def mysql_service_detection(target, port, timeout):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target, port))

        # MySQL packet header: 3-byte payload length + 1-byte sequence ID
        header = receive_exact(sock, 4)

        payload_length = int.from_bytes(
            header[:3],
            byteorder="little"
        )

        if payload_length < 2 or payload_length > 65536:
            return "Invalid MySQL greeting packet"

        payload = receive_exact(sock, payload_length)

        protocol_version = payload[0]

        if protocol_version != 10:
            return f"Unexpected MySQL protocol version: {protocol_version}"

        version_bytes = payload[1:].split(b"\x00", 1)[0]

        server_version = version_bytes.decode(
            errors="replace"
        )

        if server_version:
            return f"MySQL {server_version}"

        return "MySQL greeting received; version not disclosed"

    except socket.timeout:
        return "MySQL response timed out"

    except OSError as e:
        return f"MySQL connection error: {e}"

    finally:
        sock.close()
