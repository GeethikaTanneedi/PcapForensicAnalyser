# step5_credentials.py - UPDATED with credential analysis and risk assessment
from scapy.all import *
from datetime import datetime
import argparse
import re

def assess_password_strength(password):
    """Assess password strength"""
    if not password:
        return "Unknown"
    
    strength = 0
    feedback = []
    
    if len(password) >= 8:
        strength += 1
    else:
        feedback.append("Too short")
    
    if re.search(r'[A-Z]', password):
        strength += 1
    else:
        feedback.append("No uppercase")
    
    if re.search(r'[a-z]', password):
        strength += 1
    else:
        feedback.append("No lowercase")
    
    if re.search(r'[0-9]', password):
        strength += 1
    else:
        feedback.append("No numbers")
    
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        strength += 1
    else:
        feedback.append("No special chars")
    
    if strength >= 4:
        return "STRONG"
    elif strength >= 2:
        return "WEAK - " + ", ".join(feedback[:2])
    else:
        return "VERY WEAK - " + ", ".join(feedback)

def get_risk_level(protocol, credential_type, data):
    """Determine risk level based on context"""
    high_risk_protocols = ['TELNET', 'FTP', 'POP3', 'IMAP']
    medium_risk_protocols = ['HTTP']
    
    if protocol in high_risk_protocols:
        return "CRITICAL"
    elif protocol in medium_risk_protocols:
        return "HIGH"
    else:
        return "MEDIUM"

def detect_clear_text_creds(packets):
    """
    Detect clear-text credentials in network traffic
    """
    print("\n" + "=" * 70)
    print("CLEAR-TEXT CREDENTIAL DETECTION - WITH RISK ANALYSIS")
    print("=" * 70)
    
    # Protocols that commonly send credentials in clear text
    insecure_ports = {
        21: "FTP",
        23: "TELNET",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        25: "SMTP",
        20: "FTP-data"
    }
    
    # Patterns to look for with context
    cred_patterns = [
        (b"USER", "username", "FTP/Telnet username"),
        (b"PASS", "password", "FTP/Telnet password"),
        (b"login", "login", "Generic login"),
        (b"Authorization: Basic", "basic_auth", "HTTP Basic Auth"),
        (b"password", "password_field", "Password field"),
        (b"username", "username_field", "Username field"),
        (b"passwd", "password", "Password field"),
        (b"&pass=", "url_password", "URL password parameter"),
        (b"&user=", "url_username", "URL username parameter")
    ]
    
    credentials_found = []
    
    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            src_port = packet[TCP].sport
            payload = bytes(packet[Raw].load)
            
            # Check if it's an insecure protocol
            protocol = insecure_ports.get(dst_port, insecure_ports.get(src_port, None))
            
            # Also check for HTTP (port 80) specifically
            if not protocol and (dst_port == 80 or src_port == 80):
                protocol = "HTTP"
            
            if protocol:
                # Search for credentials
                for pattern, cred_type, description in cred_patterns:
                    if pattern in payload:
                        # Convert timestamp
                        try:
                            time_str = datetime.fromtimestamp(float(packet.time)).strftime('%Y-%m-%d %H:%M:%S')
                        except:
                            time_str = "Unknown time"
                        
                        # Try to extract the full credential
                        try:
                            # Decode as much as possible
                            text = payload.decode('utf-8', errors='ignore')
                            lines = text.split('\n')
                            
                            for line in lines:
                                if pattern.decode('utf-8', errors='ignore').lower() in line.lower():
                                    # Extract actual credential value
                                    credential_value = ""
                                    if ":" in line:
                                        credential_value = line.split(":", 1)[1].strip()
                                    elif " " in line:
                                        parts = line.split()
                                        if len(parts) > 1:
                                            credential_value = parts[1].strip()
                                    else:
                                        credential_value = line.strip()
                                    
                                    # Assess password strength if it's a password
                                    password_strength = "N/A"
                                    if cred_type in ['password', 'password_field', 'url_password']:
                                        password_strength = assess_password_strength(credential_value)
                                    
                                    risk_level = get_risk_level(protocol, cred_type, credential_value)
                                    
                                    credential_info = {
                                        'timestamp': time_str,
                                        'src_ip': src_ip,
                                        'src_port': src_port,
                                        'dst_ip': dst_ip,
                                        'dst_port': dst_port,
                                        'protocol': protocol,
                                        'type': cred_type,
                                        'description': description,
                                        'data': line.strip(),
                                        'credential': credential_value,
                                        'password_strength': password_strength,
                                        'risk_level': risk_level
                                    }
                                    credentials_found.append(credential_info)
                        except:
                            # If decoding fails, show raw bytes
                            credential_info = {
                                'timestamp': time_str,
                                'src_ip': src_ip,
                                'src_port': src_port,
                                'dst_ip': dst_ip,
                                'dst_port': dst_port,
                                'protocol': protocol,
                                'type': cred_type,
                                'description': description,
                                'data': str(payload[:100]),
                                'credential': 'Binary data',
                                'password_strength': 'Unknown',
                                'risk_level': risk_level
                            }
                            credentials_found.append(credential_info)
    
    # Group credentials by source-destination pair
    cred_groups = defaultdict(list)
    for cred in credentials_found:
        key = f"{cred['src_ip']}:{cred['src_port']} -> {cred['dst_ip']}:{cred['dst_port']}"
        cred_groups[key].append(cred)
    
    # Report findings
    if credentials_found:
        print(f"\n[!] FOUND {len(credentials_found)} POTENTIAL CREDENTIALS IN CLEAR TEXT!")
        
        # Show by connection
        for connection, creds in cred_groups.items():
            print(f"\n{'─'*50}")
            print(f"CONNECTION: {connection}")
            print(f"{'─'*50}")
            print(f"  Protocol: {creds[0]['protocol']}")
            print(f"  Time: {creds[0]['timestamp']}")
            print(f"  Risk Level: {creds[0]['risk_level']}")
            
            # Separate username and password
            usernames = [c for c in creds if 'user' in c['type']]
            passwords = [c for c in creds if 'pass' in c['type']]
            
            if usernames:
                print(f"\n  📧 USERNAME(S) FOUND:")
                for u in usernames:
                    print(f"      {u['credential']}")
            
            if passwords:
                print(f"\n  🔑 PASSWORD(S) FOUND:")
                for p in passwords:
                    strength_icon = "💪" if p['password_strength'] == "STRONG" else "⚠️"
                    print(f"      {strength_icon} {p['credential']}")
                    print(f"         Strength: {p['password_strength']}")
            
            # Risk assessment
            print(f"\n  ⚠️  RISK ASSESSMENT:")
            if creds[0]['risk_level'] == "CRITICAL":
                print(f"      CRITICAL: Credentials sent in clear text over insecure protocol!")
                print(f"      Anyone on the network can capture these credentials.")
            elif creds[0]['risk_level'] == "HIGH":
                print(f"      HIGH: Credentials exposed - consider using HTTPS")
            
            # Show raw data for verification
            print(f"\n  📄 Raw credential data:")
            for cred in creds[:2]:  # Show first 2
                print(f"      {cred['data']}")
        
        # Overall statistics
        print("\n" + "="*70)
        print("CREDENTIAL EXPOSURE SUMMARY")
        print("="*70)
        print(f"Total credentials exposed: {len(credentials_found)}")
        print(f"Unique connections compromised: {len(cred_groups)}")
        print(f"Protocols involved: {', '.join(set([c['protocol'] for c in credentials_found]))}")
        
        weak_passwords = [c for c in credentials_found if 'pass' in c['type'] and c['password_strength'] != 'STRONG']
        if weak_passwords:
            print(f"Weak passwords found: {len(weak_passwords)}")
        
        print("\n[!!!] CRITICAL SECURITY ISSUE: Passwords sent in clear text!")
        print("    Recommended actions:")
        print("    - Use encrypted protocols (SFTP instead of FTP, HTTPS instead of HTTP)")
        print("    - Implement VPN for remote access")
        print("    - Change all exposed passwords immediately")
        
    else:
        print("\n[+] No clear-text credentials detected")
    
    return credentials_found

def main():
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description="Credential Detector - Find and analyze clear-text credentials in PCAP files")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    
    args = parser.parse_args()
    
    # Load the PCAP file
    print(f"[*] Loading {args.pcap_file}...")
    try:
        packets = rdpcap(args.pcap_file)
        print(f"[+] Loaded {len(packets)} packets")
        
        # Detect clear-text credentials
        detect_clear_text_creds(packets)
        
    except FileNotFoundError:
        print(f"[!] Error: File '{args.pcap_file}' not found!")
    except Exception as e:
        print(f"[!] Error loading file: {e}")
    
    print("\n" + "=" * 70)
    import sys
    if sys.stdin.isatty():
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()
    import sys
    if sys.stdin.isatty():
        input("\nPress Enter to exit...")