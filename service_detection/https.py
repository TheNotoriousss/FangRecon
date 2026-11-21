
import socket
import ssl


def https_service_detection(target, port, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    secure_sock = None
    response_data = b""
    server_version = "Unknown"

    context = ssl.create_default_context()

    try:
        sock.connect((target, port))

        secure_sock = context.wrap_socket(
            sock,
            server_hostname=target
        )

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target}\r\n"
            f"Connection: close\r\n\r\n"
        )

        secure_sock.sendall(request.encode())

        while len(response_data) < 8192:
            remaining = 8192 - len(response_data)
            data = secure_sock.recv(min(1024, remaining))

            if not data:
                break

            response_data += data

            if b"\r\n\r\n" in response_data:
                break

    except ssl.SSLCertVerificationError:
        server_version = "TLS certificate verification failed"

    except ssl.SSLError as e:
        server_version = f"TLS error: {e}"

    except socket.timeout:
        server_version = "Connection timed out"

    except OSError as e:
        server_version = f"Socket error: {e}"

    finally:
        if secure_sock is not None:
            secure_sock.close()
        else:
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
