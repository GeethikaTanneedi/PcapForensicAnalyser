# create_test_pcap.py
from scapy.all import *

print("Creating test PCAP file...")

# Create some test packets
packets = []

# Packet 1: Normal web traffic
packets.append(
    IP(src="192.168.1.100", dst="8.8.8.8")/
    TCP(sport=12345, dport=80, flags='S')
)

# Packet 2: DNS query
packets.append(
    IP(src="192.168.1.101", dst="8.8.8.8")/
    UDP(sport=54321, dport=53)/
    Raw(load="google.com query")
)

# Packet 3: Port scan attempt (SYN to different ports)
packets.append(
    IP(src="10.0.0.5", dst="192.168.1.1")/
    TCP(sport=55555, dport=22, flags='S')
)
packets.append(
    IP(src="10.0.0.5", dst="192.168.1.1")/
    TCP(sport=55555, dport=80, flags='S')
)
packets.append(
    IP(src="10.0.0.5", dst="192.168.1.1")/
    TCP(sport=55555, dport=443, flags='S')
)

# Packet 4: FTP login attempt (with password)
packets.append(
    IP(src="192.168.1.200", dst="10.0.0.10")/
    TCP(sport=33333, dport=21)/
    Raw(load="USER admin\r\nPASS password123\r\n")
)

# Packet 5: Failed login
packets.append(
    IP(src="192.168.1.200", dst="10.0.0.10")/
    TCP(sport=33333, dport=21)/
    Raw(load="530 Login incorrect\r\n")
)

# Save to file
wrpcap("test.pcap", packets)

print(f"Created test.pcap with {len(packets)} packets")
print("File is saved in:", "D:\\pcap_analyzer\\test.pcap")