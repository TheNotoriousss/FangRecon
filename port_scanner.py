import socket
import errno
import argparse
from pathlib import Path

def print_scan_info(target, status):
    print(f"Target: {target}","\n")
    print("Port\t\tStatus")
    for port, state in status.items():
        print(f"{port}\t\t{state}")

def get_arguments():

    parse = argparse.ArgumentParser()
    parse.add_argument("-x","--target", dest="target", help="Defining target", required=True)
    parse.add_argument("-p","--port", dest="port", type=str, help="Define Port", required=False, default=None)
    parse.add_argument("-t","--timeout", dest="timeout", type=float, help="Maximum waiting time", default=2, required=False)
    args=parse.parse_args()
    return args

def validate_port(port):

    if 1 <= port <= 65535:
        return True
    return False

def port_scan(target, port, timeout):
    result_dict = {}
    all_port = []
    # creating a port_list which contain int value instead of string values from port
    if isinstance(port, str):
        port_list = port.split(",")
    else:
        port_list = port

    for item in port_list:
        if isinstance(port, str) and "-" in item: #changes range str into integer range
            range_list = item.split("-")

            if len(range_list) != 2 or not all(range_list):
                print(f"Invalid port range: {item}")
                continue
            try:
                start = int(range_list[0])
                end = int(range_list[1])
            except ValueError:
                print(f"Invalid port range: {item}")
                continue
            if not validate_port(start) or not validate_port(end):
                print(f"Invalid port range: {item}")
                continue

            if start > end:
                    print(f"Invalid port range: {item}")
                    continue
            
            for single_port in range(start, end+1):
                all_port.append(single_port)
        
        else: #changes individual str into usable integer 
            try:
             single_port = int(item)
            except ValueError:
                print(f"Invalid port input: {item}")
                continue

            if validate_port(single_port):
                all_port.append(single_port)
            else:
                print(f"Invalid port: {single_port}")
    
    all_port = list(dict.fromkeys(all_port))
    if not all_port:
        print("No valid ports to scan.")
        return result_dict

    for single_port in all_port:
        single_port = int(single_port)

        print(f"[*] Scanning {target}:{single_port}")
        # socket.socket is use to create an endpoint for two way communication
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        print("[+] Socket created. Attempting connection...")
        # check if target with specific port is connecting or giving other results.
        try:
            result = sock.connect_ex((target, single_port))
            print(f"[+] Connection result: {result}")
            if result == 0:
                result_dict[single_port] = "OPEN"
            elif result == errno.ECONNREFUSED:
                result_dict[single_port] = "CLOSED"
            elif result == errno.ETIMEDOUT:
                result_dict[single_port] = "TIMEOUT / N0 RESPONSE"
            else:
                result_dict[single_port] = "UNKNOWN ERROR"
        finally:
            sock.close()
    
    return result_dict


options = get_arguments()
if options.port is None:
    BASE_DIR = Path(__file__).resolve().parent
    data_folder = BASE_DIR / "top-1000.txt"
    with open(data_folder,"r") as file:
        usable_ports = []
        ports = file.readlines()
        for str_ports in ports:
            usable_ports.append(int(str_ports.strip()))
    scan_result = port_scan(options.target, usable_ports, options.timeout)
else :
    scan_result = port_scan(options.target, options.port, options.timeout)


print("\n")
print_scan_info(options.target, scan_result)
