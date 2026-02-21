#!/usr/bin/env python3
"""
PCAP Forensic Analyzer - Final Version
Detects port scans, brute-force attacks, and clear-text credentials
"""

from scapy.all import *
from collections import defaultdict
import argparse
import sys
from datetime import datetime

class PCAPAnalyzer:
    def __init__(self, pcap_file, port_scan_threshold=5, brute_force_threshold=3):
        self.pcap_file = pcap_file
        self.packets = []
        self.port_scan_threshold = port_scan_threshold
        self.brute_force_threshold = brute_force_threshold
        
        # Results storage
        self.port_scans = []
        self.brute_force_attacks = []
        self.credentials = []
        
    def load_pcap(self):
        """Load the PCAP file"""
        try:
            print(f"[*] Loading {self.pcap_file}...")
            self.packets = rdpcap(self.pcap_file)
            print(f"[+] Loaded {len(self.packets)} packets")
            return True
        except Exception as e:
            print(f"[!] Error loading file: {e}")
            return False
    
    def detect_port_scans(self):
        """Detect potential port scans"""
        print("\n" + "=" * 60)
        print("PORT SCAN DETECTION")
        print("=" * 60)
        
        scanners = defaultdict(set)
        scanner_details = defaultdict(list)
        
        for packet in self.packets:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                src_ip = packet[IP].src
                dst_port = packet[TCP].dport
                
                # Look for SYN packets (flag 'S')
                if packet[TCP].flags == 'S':
                    scanners[src_ip].add(dst_port)
                    scanner_details[src_ip].append({
                        'port': dst_port,
                        'dst_ip': packet[IP].dst,
                        'time': float(packet.time)  # FIXED: Convert to float
                    })
        
        # Report findings
        for src_ip, ports in scanners.items():
            if len(ports) >= self.port_scan_threshold:
                scan_info = {
                    'src_ip': src_ip,
                    'ports_scanned': len(ports),
                    'port_list': sorted(ports),
                    'details': scanner_details[src_ip][:5]  # First 5 details
                }
                self.port_scans.append(scan_info)
                
                print(f"\n[!] PORT SCAN DETECTED from {src_ip}")
                print(f"    Scanned {len(ports)} unique ports")
                print(f"    Ports: {sorted(ports)[:10]}{'...' if len(ports) > 10 else ''}")
        
        if not self.port_scans:
            print("[+] No port scans detected")
    
    def detect_brute_force(self):
        """Detect potential brute-force attacks"""
        print("\n" + "=" * 60)
        print("BRUTE-FORCE DETECTION")
        print("=" * 60)
        
        # Failure patterns
        failure_patterns = [
            b"530", b"Login incorrect", b"401 Unauthorized",
            b"Authentication failed", b"invalid password", b"login failed"
        ]
        
        failures = defaultdict(int)
        failure_details = defaultdict(list)
        
        for packet in self.packets:
            if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
                src_ip = packet[IP].src
                payload = bytes(packet[Raw].load)
                
                for pattern in failure_patterns:
                    if pattern.lower() in payload.lower():
                        failures[src_ip] += 1
                        failure_details[src_ip].append({
                            'dst_ip': packet[IP].dst,
                            'dst_port': packet[TCP].dport,
                            'time': float(packet.time),  # FIXED: Convert to float
                            'pattern': pattern.decode('utf-8', errors='ignore')
                        })
                        break
        
        # Report findings
        for src_ip, count in failures.items():
            if count >= self.brute_force_threshold:
                attack_info = {
                    'src_ip': src_ip,
                    'attempts': count,
                    'details': failure_details[src_ip][-5:]  # Last 5 failures
                }
                self.brute_force_attacks.append(attack_info)
                
                print(f"\n[!] BRUTE-FORCE ATTACK DETECTED from {src_ip}")
                print(f"    Failed attempts: {count}")
        
        if not self.brute_force_attacks:
            print("[+] No brute-force attacks detected")
    
    def detect_credentials(self):
        """Detect clear-text credentials"""
        print("\n" + "=" * 60)
        print("CLEAR-TEXT CREDENTIAL DETECTION")
        print("=" * 60)
        
        insecure_ports = {21: "FTP", 23: "TELNET", 80: "HTTP", 110: "POP3", 143: "IMAP"}
        cred_patterns = [(b"USER", "username"), (b"PASS", "password"), 
                        (b"Authorization: Basic", "basic auth")]
        
        for packet in self.packets:
            if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
                dst_port = packet[TCP].dport
                src_port = packet[TCP].sport
                
                protocol = insecure_ports.get(dst_port, insecure_ports.get(src_port, None))
                
                if protocol:
                    payload = bytes(packet[Raw].load)
                    for pattern, cred_type in cred_patterns:
                        if pattern in payload:
                            # FIXED: Convert timestamp properly
                            try:
                                # Convert packet.time to float first
                                time_float = float(packet.time)
                                time_str = datetime.fromtimestamp(time_float).strftime('%Y-%m-%d %H:%M:%S')
                            except:
                                time_str = "Unknown time"
                            
                            cred_info = {
                                'time': time_str,
                                'src_ip': packet[IP].src,
                                'src_port': src_port,
                                'dst_ip': packet[IP].dst,
                                'dst_port': dst_port,
                                'protocol': protocol,
                                'type': cred_type,
                                'data': payload[:100]
                            }
                            self.credentials.append(cred_info)
        
        # Report findings
        if self.credentials:
            print(f"\n[!] FOUND {len(self.credentials)} CLEAR-TEXT CREDENTIALS")
            for cred in self.credentials[:5]:  # Show first 5
                print(f"\n    [{cred['time']}] {cred['protocol']}: {cred['src_ip']} -> {cred['dst_ip']}")
                print(f"      {cred['type']}: {cred['data']}")
        else:
            print("[+] No clear-text credentials detected")
    
    def generate_report(self):
        """Generate final report"""
        print("\n" + "=" * 60)
        print("FINAL ANALYSIS REPORT")
        print("=" * 60)
        print(f"PCAP File: {self.pcap_file}")
        print(f"Total Packets: {len(self.packets)}")
        print(f"Analysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 60)
        print(f"Port Scans Detected: {len(self.port_scans)}")
        print(f"Brute-Force Attacks: {len(self.brute_force_attacks)}")
        print(f"Clear-Text Credentials: {len(self.credentials)}")
        print("=" * 60)

def main():
    parser = argparse.ArgumentParser(description="PCAP Forensic Analyzer")
    parser.add_argument("pcap_file", help="Path to PCAP file")
    parser.add_argument("--port-threshold", type=int, default=5, 
                       help="Ports scanned threshold (default: 5)")
    parser.add_argument("--brute-threshold", type=int, default=3,
                       help="Failed login threshold (default: 3)")
    
    args = parser.parse_args()
    
    # Create analyzer and run
    analyzer = PCAPAnalyzer(args.pcap_file, args.port_threshold, args.brute_threshold)
    
    if analyzer.load_pcap():
        analyzer.detect_port_scans()
        analyzer.detect_brute_force()
        analyzer.detect_credentials()
        analyzer.generate_report()
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()