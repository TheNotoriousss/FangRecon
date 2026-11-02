import argparse  #a better newer version of optparse
import scapy.all as scapy #scapy.all module is use for network packets, it capture 2 lists, answered and unanswered in which both have 2 lists of it's own
import ipaddress # let use work we every types of ip 
from mac_vendor_lookup import MacLookup # let use verify the OUI 
import socket # reverse DNS lookup


def get_arguments():
    parse = argparse.ArgumentParser()
    parse.add_argument("-ip","--ip_add",dest="ip_add", help="Target IP / IP range.", required = True)
    parse.add_argument("-in","--interface",dest="interface", help="Network Interface to use.")
    parse.add_argument("-t","--timeout",dest="timeout", type=float, default=2, help="Time to wait for ARP response (default timing = 2sec)")
    args = parse.parse_args()
    return args


def scan(ip_add, interface, timeout):

    #lets convert target into a network object
    network = ipaddress.ip_network(ip_add, strict=False) #.ip_network it takes cidr notation and create an IPv4Network object

    #let's ensure if entered Ip is version 4
    if network.version != 4:
        raise ValueError("Only IP version 4 are supported")

    print("[+] Creating ARP requests...")
    arp_requests = []
    # this FOR loop is to generate all the arp requests needed
    for ip in network.hosts(): # .hosts returns the usable ip addresses in the network
    
        #scapy.arping(ip) -> we will build our own arping
        arp_request=scapy.ARP(pdst=str(ip))
        broadcast= scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast=broadcast/arp_request # combines arp requests with ethernet header
        arp_requests.append(arp_request_broadcast) #makes a lists of all arp_request
        #arp_request_broadcast.show() -> show() it just show what is inside the variable


    print("[+] Total ARP requests:", len(arp_requests))
    print("[+] Sending packets...")

    answered_lists = scapy.srp(arp_requests, iface=interface, timeout=2, verbose=False)[0] #scapy.srp it is a standard send and recieve packets and [0] is to select the 1st list field which have answered list
    
    print("[+] Packet scanning completed!")


    client_list = []
    # this FOR loop makes a list of dictionary for ip and mac address 
    for element in answered_lists:
        # MAC vendor identification
        mac_address = element[1].hwsrc
        try:
            vendor = MacLookup().lookup(mac_address)
        except Exception:
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


options = get_arguments()
scan_results = scan(options.ip_add, options.interface, options.timeout)
print_result(scan_results)

