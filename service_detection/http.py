
import socket


def http_service_detection(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    server_version = "Unknown"
    response_data = b""

    try:
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
        server_version = "Response timed out"

    except OSError as e:
        server_version = f"Connection error: {e}"

    finally:
        sock.close()

    if response_data:
        response = response_data.decode(errors="replace")
        headers = response.split("\r\n\r\n")[0]
        header_lines = headers.split("\r\n")

        server_version = "Server version is not disclosed"

        for line in header_lines:
            if line.lower().startswith("server:"):
                server_version = line.split(":", 1)[1].strip()
                break

    elif server_version == "Unknown":
        server_version = "No response received from server"

    return server_version
