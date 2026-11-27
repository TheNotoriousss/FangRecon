
import time
import socket
import dns.message
from udp_scanner import get_icmp_error

target = "127.0.0.1"
port = 10050
timeout = 2
dns_timeout = min(timeout, 0.5)

total_start = time.perf_counter()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(
    socket.SOL_IP,
    getattr(socket, "IP_RECVERR", 11),
    1
)

query = dns.message.make_query(
    "fangrecon-test.invalid",
    "A"
)

# DNS probe
start = time.perf_counter()

sock.settimeout(dns_timeout)
sock.sendto(query.to_wire(), (target, port))

try:
    sock.recvfrom(4096)
except socket.timeout:
    print("DNS probe timed out")

print(f"DNS stage: {time.perf_counter() - start:.3f}s")

# Generic UDP probe
start = time.perf_counter()

sock.settimeout(timeout)
sock.sendto(b"FangRecon UDP probe", (target, port))

try:
    sock.recvfrom(1024)
except socket.timeout:
    print("Generic probe timed out")

print(f"Generic stage: {time.perf_counter() - start:.3f}s")

# ICMP error queue
start = time.perf_counter()

icmp_result = get_icmp_error(sock)

print("ICMP result:", icmp_result)
print(f"ICMP check: {time.perf_counter() - start:.3f}s")

sock.close()

print(f"Total execution: {time.perf_counter() - total_start:.3f}s")
