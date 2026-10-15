# Network Packet Sniffer

A Python-based network packet sniffer built with **Scapy**. It captures
packets on a network interface and displays useful information to help
users understand network traffic and packet structure.

## Features

-   Captures a specified number of packets (20 by default).
-   Displays packet timestamp and packet length.
-   Shows source and destination IPv4 or IPv6 addresses.
-   Identifies TCP, UDP, ICMP, and other IP protocols.
-   Displays TCP/UDP source and destination ports.
-   Shows TCP flags and ICMP type when available.
-   Detects and displays DNS queries.
-   Displays a short payload preview in hexadecimal and readable text.
-   Supports optional interface selection and BPF capture filters.

## Requirements

-   Python 3
-   Scapy
-   Administrator/root permissions may be required to capture packets.
-   On Windows, install Npcap if required by your environment.

## Installation

Install Scapy:

``` bash
python -m pip install scapy
```

## Run the Program

Run the script from a terminal with the permissions needed for packet
capture:

``` bash
python "py rehan_task_one.py.py"
```

If you rename the script to `packet_sniffer.py`, use:

``` bash
python packet_sniffer.py
```

## Configuration

Edit these settings near the top of the Python file:

``` python
PACKET_COUNT = 20
INTERFACE = None
BPF_FILTER = None
```

-   `PACKET_COUNT`: Number of packets to capture. Set to `0` to continue
    until you press `Ctrl+C`.
-   `INTERFACE`: Network interface to monitor, such as `Wi-Fi` or
    `eth0`. `None` uses the default interface.
-   `BPF_FILTER`: Optional filter, such as `"tcp port 80"`,
    `"udp port 53"`, or `"icmp"`.

## Example Output

``` text
Python Network Packet Sniffer
Time           : 12:00:00.123
Packet Length  : 74
IP Version     : 4
Source IP      : 192.168.1.10
Destination IP : 8.8.8.8
Protocol       : UDP
Source Port    : 53000
Dest Port      : 53
```

Output varies depending on the packets captured on your network.

## Technologies Used

-   Python
-   Scapy
-   IPv4 / IPv6
-   TCP, UDP, ICMP, DNS

## Learning Objectives

-   Understand the structure of network packets.
-   Learn how IP addresses and ports identify network endpoints.
-   Explore common network protocols.
-   Practice basic packet capture and inspection with Python.

## Safety and Responsible Use

Only capture traffic on networks and devices you own or have explicit
permission to monitor. Packet payloads can contain sensitive
information; do not collect or share other people's private traffic.

## Author

Add your name, course, and project links here.
