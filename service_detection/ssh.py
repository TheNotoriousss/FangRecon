
import socket


def ssh_service_detection(target, port, timeout):
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
            lines = response_data.decode(
                errors="replace"
            ).splitlines()

            for line in lines:
                if line.startswith("SSH-"):
                    banner = line.strip()
                    break
            else:
                banner = "SSH identification string not received"

        else:
            banner = "No SSH banner received"

    except socket.timeout:
        banner = "Connection timed out"

    except OSError as e:
        banner = f"Socket error: {e}"

    finally:
        sock.close()

    return banner
