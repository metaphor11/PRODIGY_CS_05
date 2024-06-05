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
