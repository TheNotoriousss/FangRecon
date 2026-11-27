from port_utils import parse_ports
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import dns.message
import dns.exception
import dns.flags
import struct


def validate_dns_response(response_data, query):

    response = dns.message.from_wire(response_data)

    if not response.flags & dns.flags.QR:
        return False

    if response.id != query.id:
        return False

    if response.opcode() != query.opcode():
        return False

    if response.question != query.question:
        return False

    return True

def get_icmp_error(sock):

    if sock is None:
        return None

    try:
        # Explicitly switch to non-blocking mode before reading
        # the Linux ICMP error queue.
        sock.setblocking(False)

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

def scan_udp_port(target, resolved_target, port, timeout):

    dns_timeout = min(timeout, 0.5)
    sock = None

    try:
        print(f"[*] Scanning UDP {target}:{port}")

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        sock.setsockopt(
            socket.SOL_IP,
            getattr(socket, "IP_RECVERR", 11),
            1
        )

        sock.settimeout(dns_timeout)

        query = dns.message.make_query(
            "fangrecon-test.invalid",
            "A"
        )

        sock.sendto(
            query.to_wire(),
            (resolved_target, port)
        )

        try:
            response_data, address = sock.recvfrom(4096)

            if (
                address[0] == resolved_target
                and address[1] == port
            ):

                if validate_dns_response(response_data, query):
                    return {
                        "status": "OPEN",
                        "service": "DNS"
                    }

                return {
                    "status": "OPEN",
                    "service": "UNKNOWN"
                }

        except dns.exception.DNSException:
            pass

        except socket.timeout:
            pass

        sock.settimeout(timeout)

        sock.sendto(
            b"FangRecon UDP probe",
            (resolved_target, port)
        )

        response, address = sock.recvfrom(1024)

        if (
            address[0] == resolved_target
            and address[1] == port
        ):
            return {
                "status": "OPEN",
                "service": None
            }

        return {
            "status": "INVALID RESPONSE",
            "service": None
        }

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

        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    return {
        "status": port_status,
        "service": None
    }

def udp_scan(target, ports, timeout):

    all_ports = parse_ports(ports)
    result_dict = {}

    if not all_ports:
        print("[!] No valid ports to scan.")
        return result_dict

    try:
        resolved_target = socket.gethostbyname(target)

    except socket.gaierror:
        print(f"[!] Unable to resolve target hostname: {target}")
        return result_dict

    max_workers = min(100, len(all_ports))

    print(
        f"[*] Scanning {len(all_ports)} UDP ports "
        f"using {max_workers} workers"
    )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:

        futures = {
            executor.submit(
                scan_udp_port,
                target,
                resolved_target,
                port,
                timeout
            ): port
            for port in all_ports
        }

        for future in as_completed(futures):

            port = futures[future]

            try:
                result_dict[port] = future.result()

            except Exception as e:
                result_dict[port] = {
                    "status": f"ERROR: {e}"
                }

    return dict(sorted(result_dict.items()))
