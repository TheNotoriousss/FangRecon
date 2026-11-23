import socket
import re

from service_detection.fingerprint import create_fingerprint


def http_service_detection(target, port, timeout):

    response_data = b""

    details = {
        "status_line": None,
        "server_header": None,
        "error": None
    }

    try:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            sock.settimeout(timeout)
            sock.connect((target, port))

            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Connection: close\r\n\r\n"
            )

            sock.sendall(request.encode())

            while len(response_data) < 8192:

                remaining = 8192 - len(response_data)

                data = sock.recv(min(1024, remaining))

                if not data:
                    break

                response_data += data

                if b"\r\n\r\n" in response_data:
                    break

    except socket.timeout:
        details["error"] = "HTTP response timed out"

    except OSError as e:
        details["error"] = str(e)

    if not response_data:

        return create_fingerprint(
            service=None,
            details=details
        )

    status_line = response_data.split(b"\r\n", 1)[0].decode(
        errors="replace"
    )

    details["status_line"] = status_line

    # Validate the HTTP response status line.
    match = re.fullmatch(
        r"HTTP/(1\.0|1\.1) ([1-5][0-9]{2})(?: .*)?",
        status_line
    )

    if not match:

        details["error"] = "Invalid HTTP status line"

        return create_fingerprint(
            service=None,
            details=details
        )

    # Extract headers if the response contains them.
    header_data = response_data.split(b"\r\n\r\n", 1)

    if len(header_data) == 2:

        header_lines = header_data[0].decode(
            errors="replace"
        ).split("\r\n")

        for line in header_lines[1:]:

            if line.lower().startswith("server:"):

                details["server_header"] = (
                    line.split(":", 1)[1].strip()
                )

                break

    return create_fingerprint(
        service="HTTP",
        extra_info=details["server_header"],
        details=details
    )
