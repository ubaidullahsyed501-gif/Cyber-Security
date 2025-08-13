from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

def process_packet(packet):
    print("=" * 80)
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check if packet has IP layer
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = ip_layer.proto

        protocol_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, "Other")

        print(f"[+] Source IP      : {src_ip}")
        print(f"[+] Destination IP : {dst_ip}")
        print(f"[+] Protocol       : {protocol_name}")

        # If TCP or UDP, display ports
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"[+] Source Port    : {tcp_layer.sport}")
            print(f"[+] Dest Port      : {tcp_layer.dport}")

        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"[+] Source Port    : {udp_layer.sport}")
            print(f"[+] Dest Port      : {udp_layer.dport}")

        # Display payload if available
        if Raw in packet:
            payload = packet[Raw].load
            try:
                print(f"[+] Payload        : {payload.decode('utf-8', errors='ignore')}")
            except Exception as e:
                print("[!] Could not decode payload")

    else:
        print("[!] Non-IP Packet Detected")

def main():
    print("Starting packet capture... (Press Ctrl+C to stop)")
    sniff(prn=process_packet, store=False)

if __name__ == "__main__":
    main()
