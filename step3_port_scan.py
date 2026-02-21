# step3_port_scan.py - UPDATED to show OPEN PORTS
from scapy.all import *
from collections import defaultdict
import argparse

def get_port_service(port):
    """Return common service names for ports"""
    services = {
        20: "FTP-data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPCbind",
        135: "Windows RPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        9200: "Elasticsearch",
        27017: "MongoDB"
    }
    return services.get(port, "Unknown")

def detect_open_ports(packets, scanner_ip, victim_ip):
    """
    Detect which ports are actually open based on SYN-ACK responses
    """
    print(f"\n    [*] Checking which ports are OPEN on {victim_ip}...")
    
    open_ports = set()
    open_port_details = []
    
    for packet in packets:
        # Look for SYN-ACK responses from victim to scanner
        if (packet.haslayer(IP) and packet.haslayer(TCP) and
            packet[IP].src == victim_ip and 
            packet[IP].dst == scanner_ip):
            
            # SYN-ACK (flags = 'SA') means port is OPEN
            if packet[TCP].flags == 'SA':
                port = packet[TCP].sport
                open_ports.add(port)
                open_port_details.append({
                    'port': port,
                    'service': get_port_service(port),
                    'time': float(packet.time)
                })
    
    if open_ports:
        print(f"    [!!!] OPEN PORTS FOUND on {victim_ip}:")
        for port in sorted(open_ports):
            service = get_port_service(port)
            print(f"          Port {port}: {service} - OPEN")
        
        # Show which ports the attacker can now target
        print(f"\n    [⚠] ATTACK SURFACE DETECTED:")
        for port in sorted(open_ports)[:10]:  # Show first 10
            service = get_port_service(port)
            if port == 22:
                print(f"          → Port {port} (SSH): Can be brute-forced")
            elif port == 21:
                print(f"          → Port {port} (FTP): Credentials sent in clear text")
            elif port == 80 or port == 443:
                print(f"          → Port {port} ({service}): Web attacks possible")
            elif port == 3389:
                print(f"          → Port {port} (RDP): Remote desktop vulnerable")
            else:
                print(f"          → Port {port} ({service}): Potential vulnerability")
    else:
        print(f"    No open ports detected (all ports closed or filtered)")
    
    return open_ports

def detect_port_scan(packets, threshold=3):
    """
    Detect port scans by counting unique ports accessed by each source IP
    threshold: minimum number of unique ports to consider as scan
    """
    print("\n" + "=" * 70)
    print("PORT SCAN DETECTION - WITH OPEN PORT ANALYSIS")
    print("=" * 70)
    
    # Dictionary to store: source IP -> set of destination ports
    port_scanners = defaultdict(set)
    
    # Dictionary to store victims per scanner
    scanner_victims = defaultdict(set)
    
    # Dictionary to store detailed info for reporting
    scan_details = defaultdict(list)
    
    # Analyze each packet
    for packet in packets:
        # Check if packet has IP and TCP layers
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            
            # Track scanning attempts (SYN packets)
            if packet[TCP].flags == 'S':
                port_scanners[src_ip].add(dst_port)
                scanner_victims[src_ip].add(dst_ip)
                
                # Store details for reporting
                scan_details[src_ip].append({
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'flags': packet[TCP].flags,
                    'time': float(packet.time)
                })
    
    # Report findings
    scans_found = False
    for src_ip, ports in port_scanners.items():
        if len(ports) >= threshold:
            scans_found = True
            print(f"\n{'!'*60}")
            print(f"!!! POTENTIAL PORT SCAN DETECTED!")
            print(f"{'!'*60}")
            print(f"    Attacker IP: {src_ip}")
            print(f"    Target(s): {', '.join(scanner_victims[src_ip])}")
            print(f"    Unique ports scanned: {len(ports)}")
            
            # Show port range
            port_list = sorted(ports)
            if len(port_list) > 20:
                print(f"    Port range: {port_list[0]} - {port_list[-1]} ({len(port_list)} total)")
                print(f"    Sample ports: {port_list[:10]} ... {port_list[-10:]}")
            else:
                print(f"    Ports: {port_list}")
            
            # Show the first few scan attempts
            print(f"\n    First 5 scan attempts:")
            for i, detail in enumerate(scan_details[src_ip][:5]):
                time_str = f"Packet {i+1}"
                print(f"      {time_str}: To {detail['dst_ip']}:{detail['dst_port']} (Flags: {detail['flags']})")
            
            # NOW CHECK FOR OPEN PORTS ON EACH VICTIM
            print(f"\n    {'-'*50}")
            print(f"    ANALYZING ATTACK RESULTS:")
            print(f"    {'-'*50}")
            for victim_ip in scanner_victims[src_ip]:
                open_ports = detect_open_ports(packets, src_ip, victim_ip)
                
                # If open ports found, show attack summary
                if open_ports:
                    print(f"\n    [🔥] CRITICAL: Attacker found {len(open_ports)} open ports on {victim_ip}")
                    
                    # Most dangerous open ports
                    dangerous_ports = [p for p in open_ports if p in [21,22,23,3389,3306,5432]]
                    if dangerous_ports:
                        print(f"    [⚠] DANGEROUS PORTS EXPOSED:")
                        for p in dangerous_ports:
                            service = get_port_service(p)
                            risk = "HIGH" if p in [21,22,23] else "MEDIUM"
                            print(f"          Port {p} ({service}) - {risk} RISK")
    
    if not scans_found:
        print("\n[+] No port scans detected")
    
    # Summary
    if scans_found:
        print("\n" + "="*70)
        print("SCAN SUMMARY")
        print("="*70)
        print(f"Total scanners detected: {len([ip for ip in port_scanners if len(port_scanners[ip]) >= threshold])}")
        print(f"Most scanned port: Find with further analysis")
        print("="*70)
    
    return port_scanners

def main():
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description="Port Scan Detector - Analyze PCAP files for port scans and show open ports")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("--threshold", type=int, default=3, 
                       help="Port count threshold for scan detection (default: 3)")
    
    args = parser.parse_args()
    
    # Load the PCAP file
    print(f"[*] Loading {args.pcap_file}...")
    try:
        packets = rdpcap(args.pcap_file)
        print(f"[+] Loaded {len(packets)} packets")
        print(f"[+] Time range: {packets[0].time} - {packets[-1].time}")
        
        # Detect port scans and open ports
        detect_port_scan(packets, threshold=args.threshold)
        
        # Bonus: Show top talkers
        print("\n" + "="*70)
        print("TRAFFIC SUMMARY")
        print("="*70)
        ip_count = defaultdict(int)
        for packet in packets:
            if packet.haslayer(IP):
                ip_count[packet[IP].src] += 1
                ip_count[packet[IP].dst] += 1
        
        print("Top 5 busiest IPs:")
        for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip}: {count} packets")
        
    except FileNotFoundError:
        print(f"[!] Error: File '{args.pcap_file}' not found!")
    except Exception as e:
        print(f"[!] Error loading file: {e}")
    
    print("\n" + "=" * 70)
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()