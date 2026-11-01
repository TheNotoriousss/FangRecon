# FangRecon – Network Discovery Tool

A Python-based network discovery tool built using Scapy and ARP.

## Features

- ARP-based network discovery
- Single IP and CIDR-based scanning
- Network interface selection
- IP and MAC address identification
- Command-line argument handling

## Technologies

- Python
- Scapy
- Argparse
- IPaddress

## Installation

Clone the repository:

```bash
git clone https://github.com/TheNotoriousss/FangRecon.git
cd FangRecon
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Scan a target network:

```bash
sudo .venv/bin/python network_scanner.py -t 192.168.1.0/24
```

Specify a network interface:

```bash
sudo .venv/bin/python network_scanner.py -t 192.168.1.0/24 -i eth0
```

## Project Status

Phase 1 – Basic Network Scanner: Completed.

Further development is in progress.

## Disclaimer

This tool is intended for educational purposes and authorized network security testing only. Only scan networks you own or have explicit permission to assess.
