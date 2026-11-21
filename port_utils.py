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

    return list(dict.fromkeys(all_ports))
