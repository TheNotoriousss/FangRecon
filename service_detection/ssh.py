
import socket
import re

from service_detection.fingerprint import create_fingerprint


def ssh_service_detection(target, port, timeout):

    banner = None

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            sock.settimeout(timeout)
            sock.connect((target, port))

            response_data = b""

            while len(response_data) < 4096:

                data = sock.recv(1024)

                if not data:
                    break

                response_data += data

                if b"\n" in response_data:
                    break

            lines = response_data.decode(
                errors="replace"
            ).splitlines()

            for line in lines:

                line = line.strip()

                if line.startswith("SSH-"):
                    banner = line
                    break

    except (socket.timeout, OSError):
        pass

    if not banner:
        return create_fingerprint(
            service=None,
            details={"banner": None}
        )

    match = re.fullmatch(
        r"SSH-([0-9]+\.[0-9]+)-([^\s]+)(?:\s+(.*))?",
        banner
    )

    if not match:
        return create_fingerprint(
            service=None,
            details={
                "banner": banner,
                "error": "Invalid SSH identification string"
            }
        )

    protocol_version = match.group(1)
    software = match.group(2)
    extra_info = match.group(3)

    product = software
    version = None

    software_match = re.match(
        r"^(.+?)_([\w.+~-]+)$",
        software
    )

    if software_match:
        product = software_match.group(1)
        version = software_match.group(2)

    return create_fingerprint(
        service="SSH",
        product=product,
        version=version,
        extra_info=extra_info,
        details={
            "protocol_version": protocol_version,
            "banner": banner
        }
    )
