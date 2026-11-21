import socket


def ftp_service_detection(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    banner = "Unknown"
    response_data = b""

    try:
        sock.connect((target, port))

        while len(response_data) < 4096:
            data = sock.recv(1024)

            if not data:
                break

            response_data += data

            if b"\n" in response_data:
                break

        if response_data:
            banner = response_data.decode(
                errors="replace"
            ).strip()

        else:
            banner = "No FTP banner received"

    except socket.timeout:
        banner = "Connection timed out"

    except OSError as e:
        banner = f"Socket error: {e}"

    finally:
        sock.close()

    return banner
