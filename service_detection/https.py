
import socket
import ssl
import re

from service_detection.fingerprint import create_fingerprint


def https_service_detection(target, port, timeout):

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    details = {
        "status_line": None,
        "server_header": None,
        "tls_version": None,
        "cipher": None,
        "certificate": None,
        "certificate_verified": False,
        "error": None
    }

    try:

        with socket.create_connection(
            (target, port),
            timeout=timeout
        ) as sock:

            sock.settimeout(timeout)

            with context.wrap_socket(
                sock,
                server_hostname=target
            ) as tls_sock:

                details["tls_version"] = tls_sock.version()

                cipher_info = tls_sock.cipher()

                if cipher_info:

                    details["cipher"] = {
                        "name": cipher_info[0],
                        "protocol": cipher_info[1],
                        "bits": cipher_info[2]
                    }

                certificate = tls_sock.getpeercert(
                    binary_form=True
                )

                if certificate:

                    cert = ssl.DER_cert_to_PEM_cert(certificate)

                    details["certificate"] = {
                        "available": True,
                        "der_size": len(certificate)
                    }

                request = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {target}\r\n"
                    f"Connection: close\r\n\r\n"
                )

                tls_sock.sendall(request.encode())

                response_data = b""

                while len(response_data) < 8192:

                    remaining = 8192 - len(response_data)

                    data = tls_sock.recv(
                        min(1024, remaining)
                    )

                    if not data:
                        break

                    response_data += data

                    if b"\r\n" in response_data:
                        break

        if not response_data:

            details["error"] = "No HTTP response received"

            return create_fingerprint(
                service=None,
                details=details
            )

        status_line = response_data.split(
            b"\r\n", 1
        )[0].decode(errors="replace")

        details["status_line"] = status_line

        match = re.fullmatch(
            r"HTTP/(1\.0|1\.1|2|3) ([1-5][0-9]{2})(?: .*)?",
            status_line
        )

        if not match:

            details["error"] = "Invalid HTTP status line"

            return create_fingerprint(
                service=None,
                details=details
            )

        header_data = response_data.split(
            b"\r\n\r\n", 1
        )

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
            service="HTTPS",
            extra_info=details["server_header"],
            details=details
        )

    except ssl.SSLError as e:

        details["error"] = f"TLS error: {e}"

    except socket.timeout:

        details["error"] = "HTTPS response timed out"

    except OSError as e:

        details["error"] = str(e)

    return create_fingerprint(
        service=None,
        details=details
    )
