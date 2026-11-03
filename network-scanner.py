import argparse  #a better newer version of optparse
import scapy.all as scapy #scapy.all module is use for network packets, it capture 2 lists, answered and unanswered in which both have 2 lists of it's own
import ipaddress # let use work we every types of ip 
from mac_vendor_lookup import MacLookup, VendorNotFoundError # let use verify the OUI 
import socket # reverse DNS lookup
import subprocess # let us pass terminal commands
import platform
import signal # tracks pressed keys

def clean_terminal():
    command = 'cls' if platform.system() == "Windows" else "clear"
    subprocess.run([command], check=False)

def banner():
    print("=" * 60)
    print("                  FangRecon v1.0")
    print("         Network Discovery & Enumeration")
    print("=" * 60)

def print_scan_info(ip_add, interface, timeout, retires):
    print(f"[+] Target Network : {ip_add}")
    print(f"[+] Interface      : {interface}")
    print(f"[+] Timeout        : {timeout:g} seconds")
    print(f"[+] Retry Count    : {retires}","\n")
    print("[*] Starting Network Discovery ...")

def scan_banner():
    print("=" * 88)
    print("                                     SCAN RESULTS")
    print("=" * 88)

def get_arguments():
    parse = argparse.ArgumentParser()
    parse.add_argument("-ip","--ip_add",dest="ip_add", help="Target IP / IP range.", required = True)
    parse.add_argument("-in","--interface",dest="interface", help="Network Interface to use.")
    parse.add_argument("-t","--timeout",dest="timeout", type=float, default=2, help="Time to wait for ARP response (default timing = 2sec)")
    parse.add_argument("-r","--retry",dest="retries", type=int , default=2, help="Number of retries for Unanswered ARP requests (default retry : 2)")
    args = parse.parse_args()
    return args

interrupted = False

def handle_interrupt(signum, frame):
    global interrupted
    interrupted = True

signal.signal(signal.SIGINT, handle_interrupt)

def scan(ip_add, interface, timeout, retries):

    #lets convert target into a network object
    network = ipaddress.ip_network(ip_add, strict=False) #.ip_network it takes cidr notation and create an IPv4Network object

    #let's ensure if entered Ip is version 4
    if network.version != 4:
        raise ValueError("Only IP version 4 are supported")

    print("[+] Creating ARP requests...")
    arp_request_lists = []
    # this FOR loop is to generate all the arp requests needed
    for ip in network.hosts(): # .hosts returns the usable ip addresses in the network
    
        #scapy.arping(ip) -> we will build our own arping
        arp_requests=scapy.ARP(pdst=str(ip))
        broadcast= scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast=broadcast/arp_requests # combines arp requests with ethernet header
        arp_request_lists.append(arp_request_broadcast) #makes a lists of all arp_request
        #arp_request_broadcast.show() -> show() it just show what is inside the variable


    print("[+] Total ARP requests:", len(arp_request_lists))
    print("[+] Sending packets...")
    try:
        answered_lists, unanswered_lists = scapy.srp(arp_request_lists, iface=interface, timeout=timeout, verbose=False, threaded=False) #scapy.srp it is a standard send and recieve packets and [0] will select the 1st list field which have answered list
        if interrupted:
            print("\n[!] Scan interrupted by user.")
            raise SystemExit(130)
            

    # logic to retry unanswered packets till intented retries
        unanswered_retry = unanswered_lists
        counter = 0
        while unanswered_retry and counter < retries:
            print(f"[+] Retry attempt : {counter+1}", flush=True)
            answered_retry, unanswered_retry = scapy.srp(unanswered_retry, iface=interface, timeout=timeout, verbose=False, threaded=False)
            if interrupted:
                print("\n[!] Scan interrupted by user.")
                raise SystemExit(130)
            answered_lists.extend(answered_retry)
            counter+=1

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        raise

    print("[+] Packet scanning completed!")
    print("[+] Answered:", len(answered_lists))
    print("[+] Unanswered packets:", len(unanswered_retry))


    client_list = []
    # this FOR loop makes a list of dictionary for ip and mac address 
    for element in answered_lists:
        # MAC vendor identification
        mac_address = element[1].hwsrc
        try:
            vendor = MacLookup().lookup(mac_address)
        except VendorNotFoundError:
            vendor = "Unknown"

        # hostname identification
        ip = element[1].psrc
        try:
            hostname = socket.gethostbyaddr(ip)[0] # .gethostbyaddr prints a tuple with three value, but we only needed hostname which is 1st value of the tuple
        except (socket.herror, socket.gaierror):
            hostname = "Unknown"

        client_dict = {"ip":ip, "mac address":mac_address, "vendor":vendor, "hostname":hostname}
        client_list.append(client_dict) # this will create a list of dictionaries
    return client_list


def print_result(results_lists):
    print(f"{'IP ADDRESS':<18}{'MAC ADDRESS':<20}{'VENDOR':<30}{'HOSTNAME':<20}")
    print("-" * 88)

    for client in results_lists:
        print(
            f"{client['ip']:<18}"
            f"{client['mac address']:<20}"
            f"{client['vendor']:<30}"
            f"{client['hostname']:<20}"
        )


try:
    clean_terminal()
    banner()

    options = get_arguments()

    print_scan_info(options.ip_add, options.interface, options.timeout, options.retries)
    scan_results = scan(options.ip_add, options.interface, options.timeout, options.retries)


    scan_banner()
    print_result(scan_results)

except KeyboardInterrupt:
    print("\n[!] FangRecon interupted by user.")
    print("Exiting...")
