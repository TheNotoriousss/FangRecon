
import socket
import re

from service_detection.fingerprint import create_fingerprint



def read_ftp_reply(reader):

    response_lines = []
    total_size = 0
    expected_code = None

    while total_size < 4096:

        line = reader.readline(1024)

        if not line:
            return None, None

        total_size += len(line)

        if total_size > 4096:
            return None, None

        # First line must contain the response code.
        if expected_code is None:

            match = re.match(rb"^(\d{3})([- ])", line)

            if not match:
                return None, None

            expected_code = int(match.group(1))
            separator = match.group(2)

        else:

            # A multiline reply ends with the same code
            # followed by a space.
            match = re.match(
                rb"^(\d{3})([- ])",
                line
            )

            if match:

                code = int(match.group(1))
                separator = match.group(2)

                if code == expected_code and separator == b" ":
                    response_lines.append(
                        line.decode(errors="replace").strip()
                    )
                    return expected_code, "\n".join(response_lines)

        response_lines.append(
            line.decode(errors="replace").strip()
        )

        # A single-line reply ends immediately.
        if len(response_lines) == 1 and separator == b" ":
            return expected_code, "\n".join(response_lines)

    return None, None



def parse_ftp_banner(banner):

    if not banner:
        return create_fingerprint(
            service=None,
            details={"banner": None}
        )

    lines = banner.splitlines()

    greeting = lines[-1][4:].strip()

    # First, check for known multi-word product names.
    version_match = re.search(
        r"\b(FileZilla Server)[ /]([0-9][A-Za-z0-9_.+-]*)\b",
        greeting,
        re.IGNORECASE
    )

    # Fall back to the generic product/version pattern.
    if version_match is None:
        version_match = re.search(
            r"\b([A-Za-z][A-Za-z0-9_.+-]*)[ /]([0-9][A-Za-z0-9_.+-]*)\b",
            greeting
        )

    product = None
    version = None
    extra_info = greeting or None

    if version_match:
        product = version_match.group(1)
        version = version_match.group(2)

        extra_info = (
            greeting[:version_match.start()]
            + greeting[version_match.end():]
        ).strip() or None

    return create_fingerprint(
        service="FTP",
        product=product,
        version=version,
        extra_info=extra_info,
        details={"banner": banner}
    )


def ftp_service_detection(target, port, timeout):

    banner = None
    feat_response = None
    syst_response = None
    detection_method = None

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

            sock.settimeout(timeout)
            sock.connect((target, port))

            with sock.makefile("rb") as reader:

                # Read the complete FTP greeting.
                greeting_code, banner = read_ftp_reply(reader)

                if greeting_code != 220:
                    return create_fingerprint(
                        service=None,
                        details={
                            "banner": banner,
                            "error": "Invalid FTP greeting"
                        }
                    )

                # First attempt: FTP FEAT command.
                sock.sendall(b"FEAT\r\n")

                feat_code, feat_response = read_ftp_reply(reader)

                if feat_code == 211:
                    detection_method = "FEAT"

                else:
                    # Fallback: FTP SYST command.
                    sock.sendall(b"SYST\r\n")

                    syst_code, syst_response = read_ftp_reply(reader)

                    if syst_code == 215:
                        detection_method = "SYST"

    except (socket.timeout, OSError) as e:

        return create_fingerprint(
            service=None,
            details={
                "banner": banner,
                "error": str(e)
            }
        )

    if detection_method is None:
        return create_fingerprint(
            service=None,
            details={
                "banner": banner,
                "feat_response": feat_response,
                "syst_response": syst_response,
                "error": "FTP protocol validation failed"
            }
        )

    fingerprint = parse_ftp_banner(banner)

    fingerprint["details"]["feat_response"] = feat_response
    fingerprint["details"]["syst_response"] = syst_response
    fingerprint["details"]["detection_method"] = detection_method

    return fingerprint
