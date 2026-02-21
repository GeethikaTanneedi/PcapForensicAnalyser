# step3_port_scan.py - UPDATED with connection tracking and data capture
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

def detect_port_scan(packets, threshold=3):
    """
    Detect port scans by counting unique ports accessed by each source IP
    Also track completed handshakes and data capture
    threshold: minimum number of unique ports to consider as scan
    """
    print("\n" + "=" * 70)
    print("PORT SCAN DETECTION - WITH CONNECTION TRACKING")
    print("=" * 70)
    
    # Dictionary to store: source IP -> set of destination ports
    port_scanners = defaultdict(set)
    
    # Dictionary to store victims per scanner
    scanner_victims = defaultdict(set)
    
    # Dictionary to store detailed info for reporting
    scan_details = defaultdict(list)
    
    # NEW: Track open ports per victim
    open_ports = defaultdict(lambda: defaultdict(set))
    
    # NEW: Track completed handshakes
    completed_handshakes = defaultdict(lambda: defaultdict(list))
    
    # NEW: Track data captured
    data_captured = defaultdict(lambda: defaultdict(list))
    
    # Track TCP connection states
    connections = {}  # (src, dst, sport, dport) -> state
    
    # Analyze each packet
    for packet in packets:
        # Check if packet has IP and TCP layers
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            conn_key = (src_ip, dst_ip, sport, dst_port)
            
            # Track scanning attempts (SYN packets)
            if flags == 'S':
                port_scanners[src_ip].add(dst_port)
                scanner_victims[src_ip].add(dst_ip)
                
                # Store details for reporting
                scan_details[src_ip].append({
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'flags': 'SYN',
                    'time': float(packet.time)
                })
                connections[conn_key] = 'SYN_SENT'
            
            # SYN-ACK response means port is open
            elif flags == 'SA':
                # This is response from victim to scanner
                if dst_ip in port_scanners:  # dst_ip is the scanner
                    victim_ip = src_ip
                    scanner_ip = dst_ip
                    open_port = sport
                    
                    open_ports[scanner_ip][victim_ip].add(open_port)
                    
                    # Track potential handshake completion
                    reverse_key = (dst_ip, src_ip, dst_port, sport)  # (scanner, victim, scanner_port, victim_port)
                    connections[reverse_key] = 'SYN_RCVD'
            
            # ACK might complete handshake
            elif flags == 'A':
                if conn_key in connections and connections[conn_key] == 'SYN_RCVD':
                    connections[conn_key] = 'ESTABLISHED'
                    
                    # Handshake completed!
                    scanner_ip = src_ip
                    victim_ip = dst_ip
                    victim_port = dst_port
                    
                    completed_handshakes[scanner_ip][victim_ip].append({
                        'port': victim_port,
                        'time': float(packet.time),
                        'service': get_port_service(victim_port)
                    })
            
            # Data packets on established connections
            if packet.haslayer(Raw):
                if conn_key in connections and connections[conn_key] == 'ESTABLISHED':
                    scanner_ip = src_ip
                    victim_ip = dst_ip
                    victim_port = dst_port
                    
                    # Check direction
                    if scanner_ip in port_scanners:
                        direction = "ATTACKER -> VICTIM"
                    else:
                        scanner_ip = dst_ip
                        victim_ip = src_ip
                        victim_port = sport
                        direction = "VICTIM -> ATTACKER (DATA LEAK)"
                    
                    payload = bytes(packet[Raw].load)
                    
                    # Try to decode
                    try:
                        data_str = payload.decode('utf-8', errors='ignore')[:100]
                    except:
                        data_str = str(payload)[:100]
                    
                    data_captured[scanner_ip][victim_ip].append({
                        'port': victim_port,
                        'time': float(packet.time),
                        'direction': direction,
                        'data': data_str,
                        'size': len(payload)
                    })
    
    # Report findings
    scans_found = False
    total_handshakes = 0
    total_data_packets = 0
    
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
            
            # Show open ports for each victim
            for victim_ip in scanner_victims[src_ip]:
                if victim_ip in open_ports[src_ip]:
                    print(f"\n    🎯 TARGET: {victim_ip}")
                    print(f"    🔓 OPEN PORTS FOUND:")
                    
                    for port in sorted(open_ports[src_ip][victim_ip]):
                        service = get_port_service(port)
                        
                        # Check if handshake completed
                        handshake_completed = False
                        for h in completed_handshakes[src_ip][victim_ip]:
                            if h['port'] == port:
                                handshake_completed = True
                                total_handshakes += 1
                                break
                        
                        if handshake_completed:
                            print(f"        • Port {port} ({service}) - 🔴 HANDSHAKE COMPLETE")
                            
                            # Show captured data
                            captured = [d for d in data_captured[src_ip][victim_ip] if d['port'] == port]
                            if captured:
                                total_data_packets += len(captured)
                                print(f"          📥 DATA CAPTURED ({len(captured)} packets):")
                                for cap in captured[:2]:
                                    print(f"            [{cap['direction']}] {cap['data']}")
                        else:
                            print(f"        • Port {port} ({service}) - 🟢 OPEN")
                    
                    # Show attack impact for this victim
                    if completed_handshakes[src_ip][victim_ip]:
                        print(f"\n    🔴 ATTACK IMPACT:")
                        print(f"        • Handshakes completed: {len(completed_handshakes[src_ip][victim_ip])}")
                        
                        victim_data = len(data_captured[src_ip][victim_ip])
                        if victim_data > 0:
                            print(f"        • Data packets captured: {victim_data}")
                            
                            victim_bytes = sum(d['size'] for d in data_captured[src_ip][victim_ip])
                            print(f"        • Total data volume: {victim_bytes} bytes")
            
            print(f"\n    First 5 scan attempts:")
            for i, detail in enumerate(scan_details[src_ip][:5]):
                time_str = f"Packet {i+1}"
                print(f"      {time_str}: To {detail['dst_ip']}:{detail['dst_port']}")
    
    if not scans_found:
        print("\n[+] No port scans detected")
    
    # Summary
    if scans_found:
        print("\n" + "="*70)
        print("SCAN SUMMARY")
        print("="*70)
        print(f"Total scanners detected: {len([ip for ip in port_scanners if len(port_scanners[ip]) >= threshold])}")
        
        if total_handshakes > 0:
            print(f"Total completed handshakes: {total_handshakes} - 🔴 ATTACKER CONNECTED")
        if total_data_packets > 0:
            print(f"Total data packets captured: {total_data_packets} - 🔴 DATA COMPROMISED")
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