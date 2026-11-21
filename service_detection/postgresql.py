import socket
import struct


def postgresql_service_detection(target, port, timeout):

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((target, port))

        # PostgreSQL SSLRequest:
        # Length = 8 bytes
        # Request code = 80877103
        ssl_request = struct.pack("!II", 8, 80877103)

        sock.sendall(ssl_request)

        response = sock.recv(1)

        if response == b"S":
            return "PostgreSQL protocol response: SSL supported"

        elif response == b"N":
            return "PostgreSQL protocol response: SSL not supported"

        elif not response:
            return "No PostgreSQL response received"

        return f"Unexpected PostgreSQL response: {response!r}"

    except socket.timeout:
        return "PostgreSQL response timed out"

    except OSError as e:
        return f"PostgreSQL connection error: {e}"

    finally:
        sock.close()
