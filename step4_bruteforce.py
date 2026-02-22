# step4_bruteforce.py - UPDATED with detailed attack analysis
from scapy.all import *
from collections import defaultdict
import argparse
from datetime import datetime

def get_protocol_name(port):
    """Return protocol name based on port"""
    protocols = {
        21: "FTP",
        22: "SSH",
        23: "TELNET",
        25: "SMTP",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3389: "RDP",
        3306: "MySQL"
    }
    return protocols.get(port, f"Port-{port}")

def analyze_attack_pattern(failures_details):
    """Analyze the pattern of attack"""
    if len(failures_details) < 3:
        return "Basic attempt"
    
    # Check if same username repeated
    usernames = set()
    passwords = set()
    
    for detail in failures_details:
        if 'username' in detail:
            usernames.add(detail['username'])
        # Try to extract passwords from payload
        payload_lower = detail['payload'].lower()
        if b'pass' in detail['payload']:
            # Simple extraction - in real tool would be more sophisticated
            passwords.add("password attempt")
    
    if len(usernames) == 1 and len(failures_details) > 5:
        return "Dictionary attack (same username, many passwords)"
    elif len(usernames) > 5:
        return "Username enumeration attempt"
    else:
        return "Hydra/Medusa style brute-force"

def detect_bruteforce(packets, threshold=2):
    """
    Detect brute-force attempts by counting failed logins
    threshold: minimum number of failures to consider as attack
    """
    print("\n" + "=" * 70)
    print("BRUTE-FORCE ATTACK DETECTION - WITH PATTERN ANALYSIS")
    print("=" * 70)
    
    # Patterns that indicate failed login
    failure_patterns = [
        (b"530", "FTP Login Failed"),
        (b"Login incorrect", "FTP/Telnet Failed"),
        (b"401 Unauthorized", "HTTP Auth Failed"),
        (b"403 Forbidden", "HTTP Access Denied"),
        (b"Authentication failed", "Generic Auth Failed"),
        (b"invalid password", "Invalid Password"),
        (b"login failed", "Login Failed"),
        (b"Permission denied", "Permission Denied"),
        (b"Failed password", "SSH Failed"),  # Common in SSH
        (b"Invalid user", "Invalid Username")  # SSH username enum
    ]
    
    # Patterns that indicate successful login
    success_patterns = [
        (b"230", "FTP Login Success"),
        (b"200 OK", "HTTP Success"),
        (b"successful", "Login Success"),
        (b"Welcome", "Welcome Message"),
        (b"authenticated", "Authenticated")
    ]
    
    # Track failures by source IP
    failures = defaultdict(int)
    successes = defaultdict(int)
    failure_details = defaultdict(list)
    success_details = defaultdict(list)
    target_ports = defaultdict(set)
    target_ips = defaultdict(set)
    
    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load)
                
                # Check for failure patterns
                for pattern, pattern_name in failure_patterns:
                    if pattern.lower() in payload.lower():
                        failures[src_ip] += 1
                        target_ports[src_ip].add(dst_port)
                        target_ips[src_ip].add(dst_ip)
                        
                        # Try to extract username if present
                        username = "Unknown"
                        if b"user" in payload.lower() or b"username" in payload.lower():
                            lines = payload.split(b'\n')
                            for line in lines:
                                if b"user" in line.lower() or b"username" in line.lower():
                                    try:
                                        username = line.decode('utf-8', errors='ignore').strip()
                                    except:
                                        username = "Binary data"
                        
                        failure_details[src_ip].append({
                            'dst_ip': dst_ip,
                            'dst_port': dst_port,
                            'protocol': get_protocol_name(dst_port),
                            'pattern': pattern_name,
                            'payload': payload[:100],
                            'username': username,
                            'time': float(packet.time)
                        })
                        break
                
                # Check for success patterns
                for pattern, pattern_name in success_patterns:
                    if pattern.lower() in payload.lower():
                        successes[src_ip] += 1
                        success_details[src_ip].append({
                            'dst_ip': dst_ip,
                            'dst_port': dst_port,
                            'protocol': get_protocol_name(dst_port),
                            'pattern': pattern_name,
                            'payload': payload[:100],
                            'time': float(packet.time)
                        })
                        break
    
    # Report findings
    attacks_found = False
    for src_ip in failures.keys():
        failure_count = failures[src_ip]
        success_count = successes[src_ip]
        
        if failure_count >= threshold:
            attacks_found = True
            print(f"\n{'!'*60}")
            print(f"!!! BRUTE-FORCE ATTACK DETECTED!")
            print(f"{'!'*60}")
            print(f"    Attacker IP: {src_ip}")
            print(f"    Target(s): {', '.join(target_ips[src_ip])}")
            print(f"    Target Port(s): {', '.join([f'{p} ({get_protocol_name(p)})' for p in target_ports[src_ip]])}")
            print(f"    Failed attempts: {failure_count}")
            print(f"    Successful logins: {success_count}")
            
            # Calculate success rate
            total_attempts = failure_count + success_count
            if total_attempts > 0:
                success_rate = (success_count / total_attempts) * 100
                print(f"    Success rate: {success_rate:.1f}%")
                
                if success_count > 0:
                    print(f"    [!!!] ATTACK SUCCEEDED! Attacker gained access!")
            
            # Analyze attack pattern
            pattern = analyze_attack_pattern(failure_details[src_ip])
            print(f"    Attack pattern: {pattern}")
            
            # Show attack timeline
            if failure_details[src_ip]:
                times = [d['time'] for d in failure_details[src_ip]]
                time_span = max(times) - min(times)
                attempts_per_second = failure_count / time_span if time_span > 0 else failure_count
                print(f"    Attack speed: {attempts_per_second:.1f} attempts/second")
                
                if attempts_per_second > 5:
                    print(f"    [⚠] HIGH SPEED ATTACK - Automated tool detected")
            
            # Show recent failures
            print(f"\n    Last 5 failure attempts:")
            for i, detail in enumerate(failure_details[src_ip][-5:]):
                try:
                    time_str = datetime.fromtimestamp(float(detail['time'])).strftime('%H:%M:%S')
                except:
                    time_str = "Unknown"
                print(f"      {i+1}. {time_str} - To {detail['dst_ip']}:{detail['dst_port']} ({detail['protocol']})")
                print(f"         Reason: {detail['pattern']}")
                if detail['username'] != "Unknown":
                    print(f"         Username tried: {detail['username'][:50]}")
            
            # Show successes if any
            if success_count > 0:
                print(f"\n    [!!!] SUCCESSFUL LOGINS FOUND:")
                for i, detail in enumerate(success_details[src_ip]):
                    try:
                        time_str = datetime.fromtimestamp(float(detail['time'])).strftime('%H:%M:%S')
                    except:
                        time_str = "Unknown"
                    print(f"      {i+1}. {time_str} - To {detail['dst_ip']}:{detail['dst_port']}")
                    print(f"         Success pattern: {detail['pattern']}")
    
    if not attacks_found:
        print("\n[+] No brute-force attacks detected")
    
    # Summary statistics
    if attacks_found:
        print("\n" + "="*70)
        print("BRUTE-FORCE SUMMARY")
        print("="*70)
        print(f"Total attacking IPs: {len([ip for ip,count in failures.items() if count >= threshold])}")
        print(f"Total failed attempts: {sum(failures.values())}")
        print(f"Total successful logins: {sum(successes.values())}")
        
        if sum(successes.values()) > 0:
            print("\n[!!!] CRITICAL: Some attacks succeeded! Investigate immediately!")
        print("="*70)
    
    return failures, successes

def main():
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description="Brute-Force Detector - Analyze PCAP files for brute-force attacks with pattern analysis")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    parser.add_argument("--threshold", type=int, default=3, 
                       help="Failure count threshold for brute-force detection (default: 3)")
    
    args = parser.parse_args()
    
    # Load the PCAP file
    print(f"[*] Loading {args.pcap_file}...")
    try:
        packets = rdpcap(args.pcap_file)
        print(f"[+] Loaded {len(packets)} packets")
        
        # Detect brute-force
        detect_bruteforce(packets, threshold=args.threshold)
        
    except FileNotFoundError:
        print(f"[!] Error: File '{args.pcap_file}' not found!")
    except Exception as e:
        print(f"[!] Error loading file: {e}")
    
    print("\n" + "=" * 70)
    import sys
    if sys.stdin.isatty():
        import sys
    if sys.stdin.isatty():
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()