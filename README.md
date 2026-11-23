# FangRecon

**FangRecon** is a Python-based network reconnaissance tool designed to discover active devices, scan TCP and UDP ports, and identify network services and their versions.

Built as a learning-oriented cybersecurity project, FangRecon focuses on network discovery, port scanning, service identification, and protocol-based fingerprinting.

## Features

- **Network Discovery:** ARP-based discovery of active devices on a local network.
- **Host Identification:** Retrieves IP addresses, MAC addresses, MAC vendors, and hostnames.
- **TCP Port Scanning:** Supports individual ports, port ranges, and a default Top 1000 port list.
- **UDP Port Scanning:** Supports UDP probing, DNS detection, and ICMP-based port-state classification.
- **Service Detection:** Identifies common services, including HTTP, HTTPS, SSH, FTP, SMTP, DNS, MySQL, and PostgreSQL.
- **Version Fingerprinting:** Extracts available product names, service versions, and additional banner information.
- **Protocol Validation:** Validates service responses instead of relying solely on port numbers.
- **Configurable Scanning:** Supports custom timeouts and scan parameters.

## Technologies

- Python
- Scapy
- Socket Programming
- dnspython
- Argparse
- SSL/TLS
- Linux networking and ICMP error handling

## Installation

Clone the repository:

```bash
git clone https://github.com/TheNotoriousss/FangRecon.git
cd FangRecon
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirement.txt
```

## Usage

### 1. Network Discovery

Discover active devices on a local network:

```bash
sudo ./.venv/bin/python3 network_scanner.py -ip 192.168.1.0/24
```

Specify a network interface when required:

```bash
sudo ./.venv/bin/python3 network_scanner.py -ip 192.168.1.0/24 -in eth0
```

### 2. TCP Port Scanning

Scan specific TCP ports:

```bash
python3 port_scanner.py -x 192.168.1.1 -p 22,80,443
```

### 3. UDP Port Scanning

Scan specific UDP ports:

```bash
python3 port_scanner.py -x 192.168.1.1 -p 53,123,161 -s U
```

### 4. Configurable Timeout

Set a custom timeout:

```bash
python3 port_scanner.py -x 192.168.1.1 -p 22,80,443 -t 3
```

Use `-h` with either script to view its available arguments.

## UDP Port States

FangRecon distinguishes between different UDP scan outcomes:

| Status | Meaning |
|---|---|
| OPEN | A valid response was received |
| CLOSED | Port unreachable response received |
| FILTERED | Traffic administratively prohibited |
| OPEN\|FILTERED | No response received; state remains uncertain |
| UNREACHABLE | Network or host unreachable response |

## Project Status

| Phase | Description | Status |
|---|---|---|
| 1 | Network Discovery | Completed |
| 2 | Scanner Improvements | Completed |
| 3 | TCP Port Scanning & Service Detection | Completed |
| 4 | UDP Port Scanning | Completed |
| 5 | Advanced Service & Version Fingerprinting | Completed |
| 6 | Performance Optimization | Upcoming |
| 7 | Final Integration | Upcoming |

## Disclaimer

FangRecon is intended for educational purposes and authorized security testing only. Scan only networks and systems you own or have explicit permission to assess.

FangRecon is a reconnaissance tool. It does not perform exploitation or attempt to authenticate to discovered services.
