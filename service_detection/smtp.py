
import socket
import re

from service_detection.fingerprint import create_fingerprint


def read_smtp_reply(reader, expected_code):

    response_lines = []
    total_size = 0

    while total_size < 4096:

        line = reader.readline(1024)

        if not line:
            return None

        total_size += len(line)

        if total_size > 4096:
            return None

        match = re.match(
            rb"^(\d{3})([- ])",
            line
        )

        if not match:
            return None

        code = int(match.group(1))
        separator = match.group(2)

        if code != expected_code:
            return None

        response_lines.append(
            line.decode(errors="replace").strip()
        )

        # A space indicates the final line of the reply.
        if separator == b" ":
            return "\n".join(response_lines)

    return None


def parse_smtp_banner(banner):

    if not banner:
        return create_fingerprint(
            service=None,
            details={"banner": None}
        )

    if not re.match(r"^220[- ]", banner):
        return create_fingerprint(
            service=None,
            details={"banner": banner}
        )

    greeting = banner.splitlines()[-1][4:].strip()

    product = None
    version = None
    extra_info = greeting or None

    product_patterns = [
        r"\b(Postfix)\b(?:[/ ]([0-9][A-Za-z0-9_.+-]*))?",
        r"\b(Exim)\b(?:[/ ]([0-9][A-Za-z0-9_.+-]*))?",
        r"\b(Exchange)\b(?:[/ ]([0-9][A-Za-z0-9_.+-]*))?",
        r"\b(Sendmail)\b(?:[/ ]([0-9][A-Za-z0-9_.+-]*))?"
    ]

    for pattern in product_patterns:

        product_match = re.search(
            pattern,
            greeting,
            re.IGNORECASE
        )

        if product_match:

            product = product_match.group(1)
            version = product_match.group(2)

            extra_info = (
                greeting[:product_match.start()]
                + greeting[product_match.end():]
            ).strip() or None

            break

    return create_fingerprint(
        service="SMTP",
        product=product,
        version=version,
        extra_info=extra_info,
        details={"banner": banner}
    )


def smtp_service_detection(target, port, timeout):

    banner = None
    ehlo_response = None

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            sock.settimeout(timeout)
            sock.connect((target, port))

            with sock.makefile("rb") as reader:

                # Read and validate SMTP greeting.
                banner = read_smtp_reply(reader, 220)

                if not banner:
                    return create_fingerprint(
                        service=None,
                        details={
                            "banner": None,
                            "error": "Invalid SMTP greeting"
                        }
                    )

                # Confirm SMTP using EHLO.
                sock.sendall(b"EHLO fangrecon.local\r\n")

                ehlo_response = read_smtp_reply(
                    reader,
                    250
                )

                if not ehlo_response:
                    return create_fingerprint(
                        service=None,
                        details={
                            "banner": banner,
                            "error": "SMTP EHLO validation failed"
                        }
                    )

    except (socket.timeout, OSError) as e:

        return create_fingerprint(
            service=None,
            details={
                "banner": banner,
                "error": str(e)
            }
        )

    fingerprint = parse_smtp_banner(banner)

    fingerprint["details"]["ehlo_response"] = ehlo_response

    return fingerprint
