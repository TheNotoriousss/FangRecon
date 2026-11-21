from port_utils import parse_ports
import socket
import dns.message
import dns.exception
import dns.flags
import struct


def get_icmp_error(sock):
    if sock is None:
        return None

    try:
        data, ancdata, flags, address = sock.recvmsg(
            1024,
            1024,
            socket.MSG_ERRQUEUE | socket.MSG_DONTWAIT
        )

        for level, ctype, cdata in ancdata:

            if level == socket.SOL_IP and ctype == 11:
                if len(cdata) < 16:
                    return "INVALID ICMP ERROR"

                errno_value, origin, icmp_type, icmp_code, pad, info, extra = (
                    struct.unpack("=IBBBBII", cdata[:16])
                )

                if origin == 2:
                    if icmp_type == 3:
                        if icmp_code == 3:
                            return "CLOSED"

                        elif icmp_code in (9, 10, 13):
                            return "FILTERED"

                        elif icmp_code in (0, 1):
                            return "UNREACHABLE"

                    return f"ICMP ERROR (Type {icmp_type}, Code {icmp_code})"

        return None

    except (socket.timeout, BlockingIOError):
        return None

    except OSError:
        return None


def udp_scan(target, ports, timeout):
    all_ports = parse_ports(ports)
    result_dict = {}

    if not all_ports:
        print("[!] No valid ports to scan.")
        return result_dict

    for port in all_ports:
        print(f"[*] Scanning UDP {target}:{port}")

        sock = None

        try:
            # Create one socket for both DNS and generic UDP probes
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_DGRAM
            )

            # Enable Linux IP_RECVERR to receive ICMP errors
            sock.setsockopt(
                socket.SOL_IP,
                getattr(socket, "IP_RECVERR", 11),
                1
            )

            sock.settimeout(timeout)

            if port == 53:
                query = dns.message.make_query("example.com", "A")

                sock.sendto(
                    query.to_wire(),
                    (target, port)
                )

                response_data, address = sock.recvfrom(4096)

                response = dns.message.from_wire(response_data)

                if (
                    response.flags & dns.flags.QR
                    and response.id == query.id
                    and response.question == query.question
                ):
                    port_status = "OPEN"
                else:
                    port_status = "INVALID RESPONSE"

            else:
                sock.sendto(
                    b"FangRecon UDP probe",
                    (target, port)
                )

                response, address = sock.recvfrom(1024)
                port_status = "OPEN"

        except dns.exception.DNSException:
            port_status = "INVALID RESPONSE"

        except socket.timeout:
            icmp_status = get_icmp_error(sock)

            if icmp_status:
                port_status = icmp_status
            else:
                port_status = "OPEN|FILTERED"

        except ConnectionRefusedError:
            icmp_status = get_icmp_error(sock)

            if icmp_status:
                port_status = icmp_status
            else:
                port_status = "UNKNOWN ERROR"

        except OSError as e:
            port_status = f"ERROR: {e}"

        except Exception as e:
            port_status = f"ERROR: {e}"

        finally:
            if sock:
                sock.close()

        result_dict[port] = {
            "status": port_status
        }

    return result_dict
