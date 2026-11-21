import socket


def smtp_service_detection(target, port, timeout):
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
        
            lines = response_data.split(b"\r\n")
        
            complete_lines = lines[:-1]
        
            if complete_lines:
                last_line = complete_lines[-1]
        
                if len(last_line) >= 4 and last_line[3:4] == b" ":
                    break

        if response_data:
            banner = response_data.decode(
                errors="replace"
            ).strip()
        else:
            banner = "No SMTP banner received"

    except socket.timeout:
        banner = "Connection timed out"

    except OSError as e:
        banner = f"Socket error: {e}"

    finally:
        sock.close()

    return banner
