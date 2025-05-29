from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        print(f"\n📦 Packet:")
        print(f"🔹 From: {src} --> To: {dst}")
        print(f"🔹 Protocol: {proto}", end='')

        if TCP in packet:
            print(" (TCP)")
        elif UDP in packet:
            print(" (UDP)")
        else:
            print(" (Other)")

        if Raw in packet:
            payload = packet[Raw].load
            print(f"🔹 Payload: {payload[:50]}...") 
        else:
            print("🔹 No payload")

def main():
    print("=== Network Packet Sniffer ===")
    print("Listening for packets (Press Ctrl+C to stop)...")
    
   
    sniff(filter="ip", prn=process_packet, store=False, count=10)


if __name__ == "__main__":
    main()
