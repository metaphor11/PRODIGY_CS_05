# Python Packet Sniffer

This is a simple Python packet sniffer tool that captures and analyzes network packets. It displays relevant information such as source and destination IP addresses, protocols, and payload data.

## Features

- Capture network packets in real-time
- Display source and destination IP addresses
- Identify protocols (TCP, UDP, ICMP, etc.)
- Display ports for TCP and UDP packets
- Display payload data (first 30 bytes)

## Prerequisites

- Python 3.x
- `scapy` library

## Installation

1. **Install Python 3.x**: Make sure Python 3.x is installed on your system.

2. **Install `scapy` library**:
    ```sh
    pip install scapy
    ```

## Usage

1. **Run the script with appropriate permissions**:
    ```sh
    sudo python packet_sniffer.py
    ```
    or
    ```sh
    python packet_sniffer.py
    ```
    (depending on your OS and whether root privileges are required).

2. The script will start capturing packets and display information in the console.

## Script Overview

### `packet_sniffer.py`

```python
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"\n[+] New Packet: {ip_src} -> {ip_dst} (Protocol: {protocol})")

        # Handle different protocols
        if protocol == 6:  # TCP
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                print(f"TCP Segment: {ip_src}:{sport} -> {ip_dst}:{dport}")
                payload = bytes(packet[TCP].payload)
        elif protocol == 17:  # UDP
            if UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                print(f"UDP Datagram: {ip_src}:{sport} -> {ip_dst}:{dport}")
                payload = bytes(packet[UDP].payload)
        elif protocol == 1:  # ICMP
            if ICMP in packet:
                icmp_type = packet[ICMP].type
                icmp_code = packet[ICMP].code
                print(f"ICMP Packet: Type {icmp_type}, Code {icmp_code}")
                payload = bytes(packet[ICMP].payload)
        else:
            print(f"Other Protocol: {protocol}")
            payload = bytes(packet[IP].payload)

        if payload:
            print(f"Payload: {payload[:30]}...")

def main():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    main()
```

### Explanation

1. **Import Required Libraries**:
   - `from scapy.all import sniff`: Import the `sniff` function from the `scapy` library for packet capturing.
   - `from scapy.layers.inet import IP, TCP, UDP, ICMP`: Import necessary layers from the `scapy.layers.inet` module to work with different protocols.

2. **Packet Callback Function**:
   - `packet_callback(packet)`: This function is called whenever a packet is captured.
   - It checks if the packet contains an IP layer (`if IP in packet`).
   - Extracts source and destination IP addresses, and the protocol number.
   - Depending on the protocol (TCP, UDP, ICMP), it extracts additional information like ports and payload.
   - Prints the relevant information for each packet.

3. **Sniffer Initialization**:
   - `sniff(prn=packet_callback, store=False)`: Starts the packet sniffer, calling `packet_callback` for each captured packet. The `store=False` argument prevents storing packets in memory.

4. **Main Function**:
   - `main()`: Prints a start message and initiates the packet sniffer.
   - The script runs the `main()` function if executed as the main module.

## Notes

- **Permissions**: Capturing network packets typically requires root or administrative privileges. Ensure you have the necessary permissions to run the script.
- **Network Interface**: By default, `scapy` listens on all available network interfaces. You can specify a particular interface by adding the `iface` argument to the `sniff` function (e.g., `sniff(iface="eth0", prn=packet_callback, store=False)`).

## License

This project is licensed under the MIT License.
