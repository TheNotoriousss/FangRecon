# FangRecon – Network Discovery & Reconnaissance Tool

FangRecon is a Python-based network discovery tool built using Scapy and ARP. It identifies active devices on a local IPv4 network and gathers information such as IP addresses, MAC addresses, MAC vendors, and hostnames.

The project is being developed as a learning-oriented network reconnaissance tool, with plans to introduce additional network enumeration capabilities.

## Features

- ARP-based network discovery
- Single IP and CIDR-based scanning
- Network interface selection
- IP and MAC address identification
- MAC vendor identification
- Reverse DNS hostname resolution
- Configurable ARP response timeout
- Configurable retry mechanism for unanswered ARP requests
- Ctrl+C interruption handling

## Technologies Used

- Python
- Scapy
- Argparse
- IPaddress
- Socket
- Mac Vendor Lookup
- Subprocess
- Signal

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/TheNotoriousss/FangRecon.git
cd FangRecon
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run FangRecon

Packet scanning requires root privileges.

```bash
sudo ./.venv/bin/python3 network_scanner.py -ip 192.168.1.0/24
```

## Usage

### Basic network scan

```bash
sudo ./.venv/bin/python3 network_scanner.py -ip 192.168.1.0/24
```

### Specify a network interface

```bash
sudo ./.venv/bin/python3 network_scanner.py -ip 192.168.1.0/24 -in eth0
```

### Configure timeout

```bash
sudo ./.venv/bin/python3 network_scanner.py -ip 192.168.1.0/24 -t 5
```

### Configure retry count

```bash
sudo ./.venv/bin/python3 network_scanner.py -ip 192.168.1.0/24 -r 3
```

### Combine arguments

```bash
sudo ./.venv/bin/python3 network_scanner.py -ip 192.168.1.0/24 -in eth0 -t 5 -r 3
```

## Command-Line Arguments

| Argument | Description | Default |
|---|---|---|
| `-ip`, `--ip_add` | Target IPv4 address or CIDR range | Required |
| `-in`, `--interface` | Network interface to use | Default interface |
| `-t`, `--timeout` | Time to wait for ARP responses (seconds) | 2 |
| `-r`, `--retry` | Number of retries for unanswered requests | 2 |

## Project Status

- Phase 1 – Basic ARP Network Scanner: Completed
- Phase 2 – Network Discovery Improvements: Completed

Further development is in progress.

## Limitations

- ARP discovery is limited to the local Layer 2 network.
- Devices that do not respond to ARP requests may not be discovered.
- Hostname resolution depends on available reverse DNS records.
- MAC vendor identification depends on the vendor database.
- Currently supports IPv4 only.
- Ctrl+C handling exits after the current Scapy operation returns; it does not guarantee immediate cancellation.

## Disclaimer

This tool is intended for educational purposes and authorized network security testing only. Only scan networks you own or have explicit permission to assess.
