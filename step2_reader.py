# step2_reader.py
from scapy.all import *
import sys

def analyze_pcap(filename):
    print("=" * 60)
    print(f"ANALYZING: {filename}")
    print("=" * 60)
    
    try:
        # Load the PCAP file
        packets = rdpcap(filename)
        print(f"Total packets: {len(packets)}")
        print("-" * 60)
        
        # Show each packet
        for i, packet in enumerate(packets):
            print(f"\nPacket #{i+1}")
            print(f"Summary: {packet.summary()}")
            
            # Show IP details if available
            if packet.haslayer(IP):
                print(f"IP: {packet[IP].src} -> {packet[IP].dst}")
            
            # Show TCP details if available
            if packet.haslayer(TCP):
                print(f"TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
                print(f"TCP Flags: {packet[TCP].flags}")
            
            # Show raw data if available
            if packet.haslayer(Raw):
                data = packet[Raw].load
                print(f"Raw Data: {data}")
            
            print("-" * 40)
            
    except Exception as e:
        print(f"Error: {e}")

# Run the analysis
if __name__ == "__main__":
    analyze_pcap("test.pcap")
    import sys
    if sys.stdin.isatty():
        input("\nPress Enter to exit...")