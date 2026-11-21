# FangRecon

**FangRecon** is a Python-based network reconnaissance tool designed to discover active devices, scan TCP ports, and identify commonly used network services.

The project is built as a learning-oriented security tool, with a focus on understanding network discovery and enumeration.

## Features

- **Network Discovery:** ARP-based discovery of active devices on a local network.
- **Host Identification:** Retrieves IP addresses, MAC addresses, MAC vendors, and hostnames.
- **TCP Port Scanning:** Supports individual ports, port ranges, and a default Top 1000 port list.
- **Service Detection:** Identifies common services such as HTTP, HTTPS, SSH, FTP, SMTP, DNS, MySQL, and PostgreSQL.
- **DNS Detection:** Tests DNS responses over both UDP and TCP.
- **Configurable Scanning:** Supports custom timeouts and scan parameters.

## Technologies

- Python
- Scapy
- Socket Programming
- dnspython
- Argparse
- SSL/TLS

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

### Network Discovery

```bash
sudo ./.venv/bin/python3 network-scanner.py -ip 192.168.1.0/24
```

### TCP Port Scanning and Service Detection

```bash
python3 port_scanner.py -x 192.168.1.1 -p 22,80,443
```

Use `-h` with either script to view its available arguments.

## Project Status

| Phase | Description | Status |
|---|---|---|
| 1 | Network Discovery | Completed |
| 2 | Scanner Improvements | Completed |
| 3 | TCP Port Scanning & Service Detection | Completed |
| 4 | UDP Port Scanning | Completed |
| 5 | Advanced Service & Version Fingerprinting | Upcoming |
| 6 | Performance Optimization | Upcoming |
| 7 | Final Integration | Upcoming |

## Disclaimer

FangRecon is intended for educational purposes and authorized security testing only. Scan only networks and systems you own or have explicit permission to assess.
