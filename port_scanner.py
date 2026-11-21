
import socket
import errno
import argparse
from pathlib import Path

from service_detection.http import http_service_detection
from service_detection.https import https_service_detection
from service_detection.ssh import ssh_service_detection
from service_detection.ftp import ftp_service_detection
from service_detection.smtp import smtp_service_detection
from service_detection.dns import dns_service_detection
from service_detection.mysql import mysql_service_detection
from service_detection.postgresql import postgresql_service_detection


common_services = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP-SUBMISSION",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT"
}


def get_arguments():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-x", "--target",
        dest="target",
        help="Target IP address or hostname",
        required=True
    )

    parser.add_argument(
        "-p", "--port",
        dest="port",
        type=str,
        help="Ports to scan (example: 22,80,443 or 1-100)",
        default=None
    )

    parser.add_argument(
        "-t", "--timeout",
        dest="timeout",
        type=float,
        help="Connection timeout",
        default=2
    )

    return parser.parse_args()


def validate_port(port):

    return 1 <= port <= 65535


def parse_ports(port):

    all_ports = []

    if isinstance(port, str):
        port_list = port.split(",")
    else:
        port_list = port

    for item in port_list:

        if isinstance(item, int):
            if validate_port(item):
                all_ports.append(item)
            else:
                print(f"[!] Invalid port: {item}")
            continue

        item = item.strip()

        if "-" in item:

            range_list = item.split("-")

            if len(range_list) != 2 or not all(range_list):
                print(f"[!] Invalid port range: {item}")
                continue

            try:
                start = int(range_list[0])
                end = int(range_list[1])

            except ValueError:
                print(f"[!] Invalid port range: {item}")
                continue

            if not validate_port(start) or not validate_port(end):
                print(f"[!] Invalid port range: {item}")
                continue

            if start > end:
                print(f"[!] Invalid port range: {item}")
                continue

            all_ports.extend(range(start, end + 1))

        else:

            try:
                single_port = int(item)

            except ValueError:
                print(f"[!] Invalid port input: {item}")
                continue

            if validate_port(single_port):
                all_ports.append(single_port)
            else:
                print(f"[!] Invalid port: {single_port}")

    # Remove duplicate ports while preserving order
    return list(dict.fromkeys(all_ports))


def detect_service(target, port, service, timeout):

    if port in [80, 8080]:
        return http_service_detection(target, port, timeout)

    elif port in [443, 8443]:
        return https_service_detection(target, port, timeout)

    elif port == 22:
        return ssh_service_detection(target, port, timeout)

    elif port == 21:
        return ftp_service_detection(target, port, timeout)

    elif port in [25, 587]:
        return smtp_service_detection(target, port, timeout)

    elif port == 53:

        dns_result = dns_service_detection(
            target,
            timeout,
            port
        )

        udp = dns_result["udp"]
        tcp = dns_result["tcp"]

        udp_result = udp["status"]
        tcp_result = tcp["status"]

        if udp["response_code"]:
            udp_result += f" ({udp['response_code']})"

        if tcp["response_code"]:
            tcp_result += f" ({tcp['response_code']})"

        return f"UDP: {udp_result} | TCP: {tcp_result}"

    elif port == 3306:
        return mysql_service_detection(target, port, timeout)

    elif port == 5432:
        return postgresql_service_detection(target, port, timeout)

    return "Not detected"


def print_scan_info(target, status):

    print(f"\nTarget: {target}\n")

    print(
        f"{'PORT':<10}"
        f"{'STATUS':<18}"
        f"{'SERVICE':<20}"
        f"VERSION"
    )

    print("-" * 85)

    for port, state in status.items():

        if state["status"] != "CLOSED":

            print(
                f"{port:<10}"
                f"{state['status']:<18}"
                f"{state['service']:<20}"
                f"{state['version']}"
            )


def port_scan(target, port, timeout):

    result_dict = {}

    all_ports = parse_ports(port)

    if not all_ports:
        print("[!] No valid ports to scan.")
        return result_dict

    for single_port in all_ports:

        print(f"[*] Scanning {target}:{single_port}")

        service = common_services.get(single_port, "UNKNOWN")
        version = "Not detected"

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(timeout)

        try:
            result = sock.connect_ex((target, single_port))

        except OSError as e:
            result = e.errno if e.errno is not None else -1

        finally:
            sock.close()

        if result == 0:

            port_status = "OPEN"

            try:
                version = detect_service(
                    target,
                    single_port,
                    service,
                    timeout
                )

            except Exception as e:
                version = f"Detection error: {e}"

        elif result == errno.ECONNREFUSED:

            port_status = "CLOSED"

        elif result in [
            errno.ETIMEDOUT,
            errno.EHOSTUNREACH,
            errno.ENETUNREACH
        ]:

            port_status = "NO RESPONSE"

        else:

            port_status = "UNKNOWN ERROR"
            version = errno.errorcode.get(
                result,
                "Unknown socket error"
            )

        result_dict[single_port] = {
            "status": port_status,
            "service": service,
            "version": version
        }

    return result_dict


def main():

    options = get_arguments()

    if options.timeout <= 0:
        print("[!] Timeout must be greater than zero.")
        return

    if options.port is None:

        base_dir = Path(__file__).resolve().parent
        data_file = base_dir / "top-1000.txt"

        with open(data_file, "r") as file:
            usable_ports = [
                int(line.strip())
                for line in file
                if line.strip()
            ]

        ports_to_scan = usable_ports

    else:
        ports_to_scan = options.port

    scan_result = port_scan(
        options.target,
        ports_to_scan,
        options.timeout
    )

    print_scan_info(options.target, scan_result)


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
