import argparse  #a better newer version of optparse
import scapy.all as scapy #scapy.all module is use for network packets, it capture 2 lists, answered and unanswered in which both have 2 lists of it's own
import ipaddress # let use work we every types of ip 


def get_arguments():
    parse = argparse.ArgumentParser()
    parse.add_argument("-t","--target",dest="target", help="Target IP / IP range.", required = True)
    parse.add_argument("-i","--interface",dest="interface", help="Network Interface to use.")
    args = parse.parse_args()
    return args


def scan(target, interface):

    #lets convert target into a network object
    network = ipaddress.ip_network(target, strict=False) #.ip_network it takes cidr notation and create an IPv4Network object

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
        client_dict = {"ip":element[1].psrc, "mac address":element[1].hwsrc}
        client_list.append(client_dict) # this will create a list of dictionaries
    return client_list


def print_result(results_lists):
    print("IP\t\t\tMAC address\n---------------------------------------------------------------------------")
    for client in results_lists:
        print(client["ip"]+"\t\t"+client["mac address"])


options = get_arguments()
scan_results = scan(options.target, options.interface)
print_result(scan_results)

