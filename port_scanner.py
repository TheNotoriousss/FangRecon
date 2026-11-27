import socket
import errno
import argparse
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from port_utils import parse_ports
from udp_scanner import udp_scan
from service_detection.engine import detect_service
from service_detection.fingerprint import create_fingerprint

def validate_target(target):

    try:
        socket.getaddrinfo(
            target,
            None,
            socket.AF_INET,
            socket.SOCK_STREAM
        )
        return True

    except socket.gaierror:
        print(f"[!] Invalid target IP address or hostname: {target}")
        return False

def get_arguments():

    parser = argparse.ArgumentParser()

    parser.add_argument("-x", "--target", dest="target", help="Target IP address or hostname", required=True)

    parser.add_argument("-p", "--port", dest="port", type=str, help="Ports to scan (example: 22,80,443 or 1-100)", default=None)

    parser.add_argument("-t", "--timeout", dest="timeout", type=float, help="Connection timeout", default=2)

    parser.add_argument("-s", choices=["T", "U"], default="T", dest="scan_type",metavar="TYPE",help="Scan type: T for TCP (default), U for UDP")

    return parser.parse_args()

def print_scan_info(target, status):

    print(f"\nTarget: {target}\n")

    print(
        f"{'PORT':<8}"
        f"{'STATUS':<16}"
        f"{'SERVICE':<15}"
        f"{'PRODUCT':<18}"
        f"{'VERSION':<25}"
        f"EXTRA INFO"
    )

    print("-" * 100)

    for port, state in sorted(status.items()):

        if state["status"] != "OPEN":
            continue

        fingerprint = state["fingerprint"]

        product = fingerprint.get("product") or "-"
        version = fingerprint.get("version") or "-"
        extra_info = fingerprint.get("extra_info") or "-"

        print(
            f"{port:<8}"
            f"{state['status']:<16}"
            f"{fingerprint.get('service') or 'UNKNOWN':<15}"
            f"{product:<18}"
            f"{version:<25}"
            f"{extra_info}"
        )

def print_udp_results(target, results):

    print(f"\nTarget: {target}\n")

    print(
        f"{'PORT':<8}"
        f"{'STATUS':<16}"
        f"{'SERVICE':<15}"
        f"{'PRODUCT':<18}"
        f"{'VERSION':<25}"
        f"EXTRA INFO"
    )

    print("-" * 100)

    for port, state in sorted(results.items()):

        if state["status"] not in ("OPEN","CLOSED","FILTERED","OPEN|FILTERED","UNREACHABLE"):
            continue

        service = state.get("service") or (
            "UNKNOWN" if state["status"] == "OPEN" else "-"
        )

        print(
            f"{port:<8}"
            f"{state['status']:<16}"
            f"{service:<15}"
            f"{'-':<18}"
            f"{'-':<25}"
            f"-"
        )

def tcp_connect(target, port, timeout):

    sock = None

    try:
        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(timeout)

        result = sock.connect_ex((target, port))

        return port, result

    except OSError as e:

        return port, e.errno if e.errno is not None else -1

    finally:

        if sock is not None:

            try:
                sock.close()

            except OSError:
                pass

def port_scan(target, port, timeout):

    result_dict = {}

    all_ports = port

    if not all_ports:
        print("[!] No valid ports to scan.")
        return result_dict

    max_workers = min(100, len(all_ports))

    print(f"[*] Scanning {len(all_ports)} ports using {max_workers} workers")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:

        futures = {
            executor.submit(
                tcp_connect,
                target,
                single_port,
                timeout
            ): single_port
            for single_port in all_ports
        }

        for future in as_completed(futures):

            single_port = futures[future]

            try:
                _, result = future.result()

            except Exception:
                result = -1

            fingerprint = create_fingerprint(service=None)

            if result == 0:

                port_status = "OPEN"

                try:
                    fingerprint = detect_service(
                        target,
                        single_port,
                        timeout
                    )

                except Exception as e:

                    fingerprint = create_fingerprint(
                        service=None,
                        details={"error": str(e)}
                    )

            elif result == errno.ECONNREFUSED:

                port_status = "CLOSED"

            elif result in [
                errno.ETIMEDOUT,
                errno.EAGAIN,
                errno.EHOSTUNREACH,
                errno.ENETUNREACH
            ]:

                port_status = "NO RESPONSE"

            else:

                port_status = "UNKNOWN ERROR"

                fingerprint = create_fingerprint(
                    service=None,
                    details={
                        "error": errno.errorcode.get(
                            result,
                            "Unknown socket error"
                        )
                    }
                )

            result_dict[single_port] = {
                "status": port_status,
                "service": None,
                "fingerprint": fingerprint
            }

    return result_dict

def main():

    options = get_arguments()

    if options.timeout <= 0:
        print("[!] Timeout must be greater than zero.")
        return

    if not validate_target(options.target):
        return

    if options.port is None:

        base_dir = Path(__file__).resolve().parent
        data_file = base_dir / "top-1000.txt"

        try:
            with open(data_file, "r") as file:
                usable_ports = [
                    int(line.strip())
                    for line in file
                    if line.strip()
                ]

        except FileNotFoundError:
            print("[!] top-1000.txt file not found.")
            return

        except ValueError:
            print("[!] Invalid entry found in top-1000.txt.")
            return

        ports_to_scan = usable_ports

    else:
        ports_to_scan = options.port
    ports_to_scan = parse_ports(ports_to_scan)

    if not ports_to_scan:
        print("[!] No valid ports to scan. Exiting.")
        return
    if options.scan_type == "T":

        scan_result = port_scan( options.target, ports_to_scan, options.timeout)

        print_scan_info(options.target, scan_result)

    elif options.scan_type == "U":

        scan_result = udp_scan(options.target, ports_to_scan, options.timeout)

        print_udp_results(options.target, scan_result)


if __name__ == "__main__":
    try:
        main()

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
