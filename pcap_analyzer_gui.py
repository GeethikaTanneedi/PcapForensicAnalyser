# pcap_analyzer_gui_enhanced.py - Complete GUI with Enhanced Analysis
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
from scapy.all import *
from collections import defaultdict
from datetime import datetime
import threading
import os
import time

class PCAPAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("PCAP Forensic Analyzer")
        self.root.geometry("1300x750")
        self.root.configure(bg='#1e1e1e')
        
        # Variables
        self.pcap_file = None
        self.packets = None
        self.port_threshold = tk.IntVar(value=5)
        self.brute_threshold = tk.IntVar(value=3)
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'total_ips': set(),
            'port_scans': 0,
            'brute_attacks': 0,
            'credentials': 0,
            'attackers': set(),
            'victims': set(),
            'start_time': None,
            'end_time': None
        }
        
        self.create_widgets()
        
    def create_widgets(self):
        """Create all GUI widgets"""
        
        # ========== TOP FRAME ==========
        top_frame = tk.Frame(self.root, bg='#2d2d2d', height=70)
        top_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Title
        tk.Label(top_frame, text="🔍 PCAP FORENSIC ANALYZER", 
                fg='#00ff00', bg='#2d2d2d', font=('Arial', 16, 'bold')).pack(side=tk.LEFT, padx=20)
        
        # File selection
        file_frame = tk.Frame(top_frame, bg='#2d2d2d')
        file_frame.pack(side=tk.RIGHT, padx=10)
        
        tk.Label(file_frame, text="PCAP File:", fg='white', bg='#2d2d2d').pack(side=tk.LEFT)
        self.file_label = tk.Label(file_frame, text="No file selected", fg='#ff6b6b', 
                                   bg='#2d2d2d', width=30)
        self.file_label.pack(side=tk.LEFT, padx=5)
        
        tk.Button(file_frame, text="Browse", command=self.browse_file,
                 bg='#4CAF50', fg='white', padx=10).pack(side=tk.LEFT)
        
        # ========== CONTROL FRAME ==========
        control_frame = tk.Frame(self.root, bg='#333333')
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Thresholds
        tk.Label(control_frame, text="⚙️ Thresholds:", fg='white', bg='#333333',
                font=('Arial', 10, 'bold')).pack(side=tk.LEFT, padx=10)
        
        tk.Label(control_frame, text="Port Scan:", fg='#87CEEB', bg='#333333').pack(side=tk.LEFT, padx=5)
        tk.Spinbox(control_frame, from_=1, to=100, textvariable=self.port_threshold,
                  width=5).pack(side=tk.LEFT)
        
        tk.Label(control_frame, text="Brute-Force:", fg='#87CEEB', bg='#333333').pack(side=tk.LEFT, padx=20)
        tk.Spinbox(control_frame, from_=1, to=100, textvariable=self.brute_threshold,
                  width=5).pack(side=tk.LEFT)
        
        # Analysis buttons
        tk.Button(control_frame, text="▶ RUN FULL ANALYSIS", 
                 command=self.run_full_analysis,
                 bg='#4CAF50', fg='white', padx=15, font=('Arial', 10, 'bold')).pack(side=tk.RIGHT, padx=5)
        
        # ========== NOTEBOOK (TABS) ==========
        style = ttk.Style()
        style.theme_use('default')
        style.configure('TNotebook.Tab', padding=[10, 5])
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create all tabs
        self.create_dashboard_tab()
        self.create_portscan_tab()
        self.create_bruteforce_tab()
        self.create_credentials_tab()
        self.create_timeline_tab()
        self.create_reports_tab()
        
        # ========== STATUS BAR ==========
        status_frame = tk.Frame(self.root, bg='#2d2d2d', height=25)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = tk.Label(status_frame, text="✅ Ready", fg='#4CAF50',
                                     bg='#2d2d2d', anchor=tk.W, padx=10)
        self.status_label.pack(side=tk.LEFT)
        
        self.progress_bar = ttk.Progressbar(status_frame, mode='indeterminate', length=200)
        self.progress_bar.pack(side=tk.RIGHT, padx=10)
        
    def create_dashboard_tab(self):
        """Dashboard with overview"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📊 DASHBOARD")
        
        # Stats cards
        cards_frame = tk.Frame(tab, bg='#2d2d2d')
        cards_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Create stat cards
        self.stat_cards = {}
        stats = [
            ("📦 Total Packets", "0", "#2196F3"),
            ("🔍 Port Scans", "0", "#FF9800"),
            ("🔑 Brute-Force", "0", "#F44336"),
            ("🔐 Credentials", "0", "#9C27B0"),
            ("👥 Attackers", "0", "#795548"),
            ("🎯 Victims", "0", "#607D8B")
        ]
        
        for i, (title, value, color) in enumerate(stats):
            card = tk.Frame(cards_frame, bg=color, width=200, height=100)
            card.grid(row=0, column=i, padx=5, pady=5)
            card.grid_propagate(False)
            
            tk.Label(card, text=title, fg='white', bg=color,
                    font=('Arial', 10)).pack(pady=(10,0))
            
            value_label = tk.Label(card, text=value, fg='white', bg=color,
                                   font=('Arial', 20, 'bold'))
            value_label.pack(expand=True)
            
            self.stat_cards[title] = value_label
        
        # File info
        info_frame = tk.Frame(tab, bg='#333333')
        info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(info_frame, text="📄 File Information", fg='white', bg='#333333',
                font=('Arial', 12, 'bold')).pack(anchor=tk.W, padx=10, pady=5)
        
        self.file_info_text = tk.Text(info_frame, height=5, bg='#1e1e1e', fg='#00ff00',
                                      font=('Consolas', 10))
        self.file_info_text.pack(fill=tk.X, padx=10, pady=5)
        
        # Recent alerts
        alerts_frame = tk.Frame(tab, bg='#333333')
        alerts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(alerts_frame, text="🚨 Recent Alerts", fg='white', bg='#333333',
                font=('Arial', 12, 'bold')).pack(anchor=tk.W, padx=10, pady=5)
        
        self.alerts_text = scrolledtext.ScrolledText(alerts_frame, height=10,
                                                     bg='#1e1e1e', fg='#ff5555',
                                                     font=('Consolas', 10))
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
    def create_portscan_tab(self):
        """Enhanced Port Scan Analysis Tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔍 PORT SCAN ANALYSIS")
        
        # Control buttons
        control_frame = tk.Frame(tab, bg='#333333')
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(control_frame, text="▶ Run Port Scan Analysis", 
                 command=lambda: self.run_single_analysis('port'),
                 bg='#2196F3', fg='white').pack(side=tk.LEFT, padx=5)
        
        tk.Button(control_frame, text="📋 Export Results", 
                 command=lambda: self.export_results('port'),
                 bg='#4CAF50', fg='white').pack(side=tk.LEFT, padx=5)
        
        # Results area with tags
        self.port_text = scrolledtext.ScrolledText(tab, wrap=tk.WORD,
                                                   bg='#1e1e1e', fg='white',
                                                   font=('Consolas', 10))
        self.port_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags
        self.port_text.tag_config('critical', foreground='#ff5555', font=('Consolas', 10, 'bold'))
        self.port_text.tag_config('warning', foreground='#ffaa00')
        self.port_text.tag_config('info', foreground='#8888ff')
        self.port_text.tag_config('success', foreground='#55ff55')
        self.port_text.tag_config('port', foreground='#ff79c6')
        self.port_text.tag_config('ip', foreground='#8be9fd')
        
    def create_bruteforce_tab(self):
        """Enhanced Brute-Force Analysis Tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔑 BRUTE-FORCE ANALYSIS")
        
        # Control buttons
        control_frame = tk.Frame(tab, bg='#333333')
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(control_frame, text="▶ Run Brute-Force Analysis", 
                 command=lambda: self.run_single_analysis('brute'),
                 bg='#FF9800', fg='white').pack(side=tk.LEFT, padx=5)
        
        tk.Button(control_frame, text="📋 Export Results", 
                 command=lambda: self.export_results('brute'),
                 bg='#4CAF50', fg='white').pack(side=tk.LEFT, padx=5)
        
        self.brute_text = scrolledtext.ScrolledText(tab, wrap=tk.WORD,
                                                    bg='#1e1e1e', fg='white',
                                                    font=('Consolas', 10))
        self.brute_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags
        self.brute_text.tag_config('critical', foreground='#ff5555', font=('Consolas', 10, 'bold'))
        self.brute_text.tag_config('warning', foreground='#ffaa00')
        self.brute_text.tag_config('info', foreground='#8888ff')
        self.brute_text.tag_config('success', foreground='#55ff55')
        
    def create_credentials_tab(self):
        """Enhanced Credentials Analysis Tab"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="🔐 CREDENTIALS ANALYSIS")
        
        # Control buttons
        control_frame = tk.Frame(tab, bg='#333333')
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(control_frame, text="▶ Run Credentials Analysis", 
                 command=lambda: self.run_single_analysis('creds'),
                 bg='#9C27B0', fg='white').pack(side=tk.LEFT, padx=5)
        
        tk.Button(control_frame, text="📋 Export Results", 
                 command=lambda: self.export_results('creds'),
                 bg='#4CAF50', fg='white').pack(side=tk.LEFT, padx=5)
        
        self.creds_text = scrolledtext.ScrolledText(tab, wrap=tk.WORD,
                                                    bg='#1e1e1e', fg='white',
                                                    font=('Consolas', 10))
        self.creds_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configure tags
        self.creds_text.tag_config('critical', foreground='#ff5555', font=('Consolas', 10, 'bold'))
        self.creds_text.tag_config('warning', foreground='#ffaa00')
        self.creds_text.tag_config('info', foreground='#8888ff')
        self.creds_text.tag_config('username', foreground='#50fa7b')
        self.creds_text.tag_config('password', foreground='#ff79c6')
        
    def create_timeline_tab(self):
        """Timeline of events"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="⏱️ TIMELINE")
        
        self.timeline_text = scrolledtext.ScrolledText(tab, wrap=tk.WORD,
                                                       bg='#1e1e1e', fg='white',
                                                       font=('Consolas', 10))
        self.timeline_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def create_reports_tab(self):
        """Generate reports"""
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="📄 REPORTS")
        
        # Report controls
        control_frame = tk.Frame(tab, bg='#333333')
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Button(control_frame, text="📊 Generate Summary Report", 
                 command=self.generate_report,
                 bg='#4CAF50', fg='white', padx=10).pack(side=tk.LEFT, padx=5)
        
        tk.Button(control_frame, text="⚠️ Generate Security Report", 
                 command=self.generate_security_report,
                 bg='#F44336', fg='white', padx=10).pack(side=tk.LEFT, padx=5)
        
        self.report_text = scrolledtext.ScrolledText(tab, wrap=tk.WORD,
                                                     bg='#1e1e1e', fg='white',
                                                     font=('Consolas', 10))
        self.report_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    # ========== ANALYSIS FUNCTIONS ==========
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select PCAP File",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if filename:
            self.pcap_file = filename
            self.file_label.config(text=os.path.basename(filename), fg='#4CAF50')
            self.status_label.config(text=f"✅ Loaded: {os.path.basename(filename)}")
            
            try:
                self.packets = rdpcap(filename)
                self.stats['total_packets'] = len(self.packets)
                self.stats['start_time'] = self.packets[0].time
                self.stats['end_time'] = self.packets[-1].time
                
                # Update dashboard
                self.stat_cards["📦 Total Packets"].config(text=str(len(self.packets)))
                
                # Show file info
                info = f"File: {filename}\n"
                info += f"Packets: {len(self.packets)}\n"
                info += f"Duration: {self.packets[-1].time - self.packets[0].time:.2f} seconds\n"
                self.file_info_text.delete(1.0, tk.END)
                self.file_info_text.insert(1.0, info)
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load PCAP: {str(e)}")
                
    def run_full_analysis(self):
        if not self.pcap_file:
            messagebox.showerror("Error", "Please select a PCAP file first!")
            return
            
        self.progress_bar.start()
        self.status_label.config(text="⏳ Running full analysis...")
        
        # Clear previous results
        self.port_text.delete(1.0, tk.END)
        self.brute_text.delete(1.0, tk.END)
        self.creds_text.delete(1.0, tk.END)
        self.alerts_text.delete(1.0, tk.END)
        
        thread = threading.Thread(target=self._run_full_analysis)
        thread.daemon = True
        thread.start()
        
    def _run_full_analysis(self):
        try:
            # Run all analyses
            self.enhanced_port_scan_analysis()
            self.enhanced_bruteforce_analysis()
            self.enhanced_credentials_analysis()
            
            # Update dashboard
            self.root.after(0, self.update_dashboard)
            
            self.progress_bar.stop()
            self.status_label.config(text="✅ Analysis complete!")
            
        except Exception as e:
            self.progress_bar.stop()
            self.status_label.config(text=f"❌ Error: {str(e)}")
            
    def enhanced_port_scan_analysis(self):
        """Enhanced port scan detection with more details"""
        self.port_text.insert(tk.END, "="*80 + "\n", 'info')
        self.port_text.insert(tk.END, "🔍 ENHANCED PORT SCAN ANALYSIS\n", 'warning')
        self.port_text.insert(tk.END, "="*80 + "\n\n", 'info')
        
        scanners = defaultdict(lambda: {'ports': set(), 'victims': set(), 'packets': []})
        
        for packet in self.packets:
            if packet.haslayer(IP) and packet.haslayer(TCP):
                if packet[TCP].flags == 'S':
                    src = packet[IP].src
                    dst = packet[IP].dst
                    port = packet[TCP].dport
                    
                    scanners[src]['ports'].add(port)
                    scanners[src]['victims'].add(dst)
                    scanners[src]['packets'].append({
                        'time': packet.time,
                        'dst': dst,
                        'port': port
                    })
        
        scan_count = 0
        for scanner, data in scanners.items():
            if len(data['ports']) >= self.port_threshold.get():
                scan_count += 1
                self.stats['attackers'].add(scanner)
                
                self.port_text.insert(tk.END, f"⚠️ SCANNER DETECTED: ", 'critical')
                self.port_text.insert(tk.END, f"{scanner}\n", 'ip')
                
                self.port_text.insert(tk.END, f"   📊 Statistics:\n", 'info')
                self.port_text.insert(tk.END, f"   • Ports Scanned: {len(data['ports'])}\n", 'warning')
                self.port_text.insert(tk.END, f"   • Targets: {len(data['victims'])}\n", 'warning')
                self.port_text.insert(tk.END, f"   • Scan Rate: {len(data['packets'])/10:.1f} pps\n", 'warning')
                
                # Show port range
                ports = sorted(data['ports'])
                self.port_text.insert(tk.END, f"   • Port Range: {ports[0]} - {ports[-1]}\n", 'warning')
                
                # Show common ports scanned
                common_ports = [p for p in ports if p in [21,22,23,25,80,443,445,3389,3306]]
                if common_ports:
                    self.port_text.insert(tk.END, f"   • Common Ports: {common_ports}\n", 'critical')
                
                # Check open ports
                for victim in data['victims']:
                    open_ports = self.check_open_ports(scanner, victim)
                    if open_ports:
                        self.stats['victims'].add(victim)
                        self.port_text.insert(tk.END, f"\n   🔓 OPEN PORTS on {victim}:\n", 'critical')
                        for port in sorted(open_ports):
                            service = self.get_service_name(port)
                            self.port_text.insert(tk.END, f"      • Port {port}", 'port')
                            self.port_text.insert(tk.END, f" ({service}) - VULNERABLE\n", 'critical')
                            
                            # Add alert
                            self.alerts_text.insert(tk.END, 
                                f"🚨 Open port {port} ({service}) exposed on {victim}\n", 'critical')
                
                self.port_text.insert(tk.END, "-"*60 + "\n\n")
        
        self.stats['port_scans'] = scan_count
        
    def enhanced_bruteforce_analysis(self):
        """Enhanced brute-force detection with pattern analysis"""
        self.brute_text.insert(tk.END, "="*80 + "\n", 'info')
        self.brute_text.insert(tk.END, "🔑 ENHANCED BRUTE-FORCE ANALYSIS\n", 'warning')
        self.brute_text.insert(tk.END, "="*80 + "\n\n", 'info')
        
        failures = defaultdict(list)
        patterns = [b"530", b"Login incorrect", b"401", b"403", b"Failed", b"Invalid"]
        
        for packet in self.packets:
            if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
                src = packet[IP].src
                dst = packet[IP].dst
                dport = packet[TCP].dport
                payload = bytes(packet[Raw].load)
                
                for pattern in patterns:
                    if pattern.lower() in payload.lower():
                        failures[src].append({
                            'time': packet.time,
                            'target': f"{dst}:{dport}",
                            'service': self.get_service_name(dport),
                            'pattern': pattern.decode()
                        })
                        break
        
        attack_count = 0
        for attacker, attempts in failures.items():
            if len(attempts) >= self.brute_threshold.get():
                attack_count += 1
                self.stats['attackers'].add(attacker)
                
                self.brute_text.insert(tk.END, f"⚠️ BRUTE-FORCE ATTACK from ", 'critical')
                self.brute_text.insert(tk.END, f"{attacker}\n", 'ip')
                
                self.brute_text.insert(tk.END, f"   📊 Statistics:\n", 'info')
                self.brute_text.insert(tk.END, f"   • Attempts: {len(attempts)}\n", 'warning')
                
                # Calculate attack duration
                times = [a['time'] for a in attempts]
                duration = max(times) - min(times)
                rate = len(attempts) / duration if duration > 0 else len(attempts)
                self.brute_text.insert(tk.END, f"   • Duration: {duration:.1f} seconds\n", 'warning')
                self.brute_text.insert(tk.END, f"   • Rate: {rate:.1f} attempts/sec\n", 'warning')
                
                # Show targets
                targets = defaultdict(int)
                for a in attempts:
                    targets[a['target']] += 1
                
                self.brute_text.insert(tk.END, f"\n   🎯 Targets:\n", 'info')
                for target, count in targets.items():
                    self.brute_text.insert(tk.END, f"      • {target}", 'warning')
                    self.brute_text.insert(tk.END, f" - {count} attempts\n")
                    
                    # Add alert for high frequency
                    if count > 10:
                        self.alerts_text.insert(tk.END, 
                            f"🚨 High-frequency brute-force on {target}\n", 'critical')
                
                self.brute_text.insert(tk.END, "-"*60 + "\n\n")
        
        self.stats['brute_attacks'] = attack_count
        
    def enhanced_credentials_analysis(self):
        """Enhanced credentials detection with risk assessment"""
        self.creds_text.insert(tk.END, "="*80 + "\n", 'info')
        self.creds_text.insert(tk.END, "🔐 ENHANCED CREDENTIALS ANALYSIS\n", 'warning')
        self.creds_text.insert(tk.END, "="*80 + "\n\n", 'info')
        
        insecure_ports = {21: "FTP", 23: "TELNET", 80: "HTTP", 110: "POP3", 143: "IMAP"}
        creds_found = []
        
        for packet in self.packets:
            if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
                dport = packet[TCP].dport
                sport = packet[TCP].sport
                
                protocol = insecure_ports.get(dport, insecure_ports.get(sport))
                if protocol:
                    payload = bytes(packet[Raw].load)
                    
                    # Look for credentials
                    if b"USER" in payload or b"PASS" in payload:
                        try:
                            data = payload.decode('utf-8', errors='ignore')
                            lines = data.split('\n')
                            
                            for line in lines:
                                if "USER" in line.upper():
                                    creds_found.append({
                                        'time': packet.time,
                                        'src': packet[IP].src,
                                        'dst': packet[IP].dst,
                                        'protocol': protocol,
                                        'type': 'USERNAME',
                                        'data': line.strip()
                                    })
                                elif "PASS" in line.upper():
                                    creds_found.append({
                                        'time': packet.time,
                                        'src': packet[IP].src,
                                        'dst': packet[IP].dst,
                                        'protocol': protocol,
                                        'type': 'PASSWORD',
                                        'data': line.strip()
                                    })
                        except:
                            pass
        
        if creds_found:
            self.stats['credentials'] = len(creds_found)
            
            # Group by connection
            connections = defaultdict(list)
            for cred in creds_found:
                key = f"{cred['src']} → {cred['dst']} ({cred['protocol']})"
                connections[key].append(cred)
            
            for conn, creds in connections.items():
                self.creds_text.insert(tk.END, f"⚠️ CREDENTIALS LEAK: ", 'critical')
                self.creds_text.insert(tk.END, f"{conn}\n", 'warning')
                
                for cred in creds:
                    self.creds_text.insert(tk.END, f"   • {cred['type']}: ", 'info')
                    self.creds_text.insert(tk.END, f"{cred['data']}\n", 'password')
                    
                    # Add alert
                    self.alerts_text.insert(tk.END, 
                        f"🚨 {cred['type']} exposed: {cred['data']}\n", 'critical')
                
                self.creds_text.insert(tk.END, "\n")
        else:
            self.creds_text.insert(tk.END, "✅ No credentials found in clear text\n", 'success')
            
    def run_single_analysis(self, analysis_type):
        """Run single analysis type"""
        if not self.pcap_file:
            messagebox.showerror("Error", "Please select a PCAP file first!")
            return
            
        self.progress_bar.start()
        
        if analysis_type == 'port':
            self.port_text.delete(1.0, tk.END)
            self.enhanced_port_scan_analysis()
            self.notebook.select(1)
        elif analysis_type == 'brute':
            self.brute_text.delete(1.0, tk.END)
            self.enhanced_bruteforce_analysis()
            self.notebook.select(2)
        elif analysis_type == 'creds':
            self.creds_text.delete(1.0, tk.END)
            self.enhanced_credentials_analysis()
            self.notebook.select(3)
            
        self.progress_bar.stop()
        self.update_dashboard()
        
    def check_open_ports(self, scanner, victim):
        """Check which ports are actually open"""
        open_ports = set()
        for packet in self.packets:
            if (packet.haslayer(IP) and packet.haslayer(TCP) and
                packet[IP].src == victim and packet[IP].dst == scanner):
                if packet[TCP].flags == 'SA':
                    open_ports.add(packet[TCP].sport)
        return open_ports
        
    def get_service_name(self, port):
        """Get service name for port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            80: "HTTP", 443: "HTTPS", 445: "SMB", 3389: "RDP",
            3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-Alt"
        }
        return services.get(port, "Unknown")
        
    def update_dashboard(self):
        """Update dashboard statistics"""
        self.stat_cards["🔍 Port Scans"].config(text=str(self.stats['port_scans']))
        self.stat_cards["🔑 Brute-Force"].config(text=str(self.stats['brute_attacks']))
        self.stat_cards["🔐 Credentials"].config(text=str(self.stats['credentials']))
        self.stat_cards["👥 Attackers"].config(text=str(len(self.stats['attackers'])))
        self.stat_cards["🎯 Victims"].config(text=str(len(self.stats['victims'])))
        
    def export_results(self, analysis_type):
        """Export results to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    if analysis_type == 'port':
                        f.write(self.port_text.get(1.0, tk.END))
                    elif analysis_type == 'brute':
                        f.write(self.brute_text.get(1.0, tk.END))
                    elif analysis_type == 'creds':
                        f.write(self.creds_text.get(1.0, tk.END))
                
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
                
    def generate_report(self):
        """Generate summary report"""
        self.report_text.delete(1.0, tk.END)
        
        report = []
        report.append("="*80)
        report.append("PCAP FORENSIC ANALYSIS REPORT")
        report.append("="*80)
        report.append(f"\nAnalysis Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"PCAP File: {self.pcap_file}")
        report.append(f"Total Packets: {self.stats['total_packets']}")
        
        if self.stats['start_time']:
            start = datetime.fromtimestamp(float(self.stats['start_time']))
            end = datetime.fromtimestamp(float(self.stats['end_time']))
            report.append(f"Capture Duration: {end - start}")
        
        report.append("\n" + "="*80)
        report.append("FINDINGS SUMMARY")
        report.append("="*80)
        report.append(f"Port Scans Detected: {self.stats['port_scans']}")
        report.append(f"Brute-Force Attacks: {self.stats['brute_attacks']}")
        report.append(f"Credentials Found: {self.stats['credentials']}")
        report.append(f"Unique Attackers: {len(self.stats['attackers'])}")
        report.append(f"Unique Victims: {len(self.stats['victims'])}")
        
        if self.stats['attackers']:
            report.append("\nAttackers:")
            for ip in self.stats['attackers']:
                report.append(f"  • {ip}")
        
        report.append("\n" + "="*80)
        report.append("END OF REPORT")
        report.append("="*80)
        
        self.report_text.insert(1.0, "\n".join(report))
        self.notebook.select(5)  # Switch to reports tab
        
    def generate_security_report(self):
        """Generate security-focused report"""
        self.report_text.delete(1.0, tk.END)
        
        report = []
        report.append("="*80)
        report.append("SECURITY INCIDENT REPORT")
        report.append("="*80)
        
        critical_issues = []
        
        # Check for critical issues
        if self.stats['port_scans'] > 0:
            critical_issues.append(f"• {self.stats['port_scans']} port scan(s) detected - Network reconnaissance in progress")
        
        if self.stats['brute_attacks'] > 0:
            critical_issues.append(f"• {self.stats['brute_attacks']} brute-force attack(s) - Active password guessing")
        
        if self.stats['credentials'] > 0:
            critical_issues.append(f"• {self.stats['credentials']} credentials exposed in clear text - IMMEDIATE ACTION REQUIRED")
        
        report.append("\n🔴 CRITICAL ISSUES FOUND:")
        if critical_issues:
            for issue in critical_issues:
                report.append(f"  {issue}")
        else:
            report.append("  No critical issues detected")
        
        report.append("\n📋 RECOMMENDED ACTIONS:")
        
        if self.stats['port_scans'] > 0:
            report.append("  • Block scanning IPs at firewall")
            report.append("  • Close unnecessary open ports")
            report.append("  • Implement port knocking for sensitive services")
        
        if self.stats['brute_attacks'] > 0:
            report.append("  • Implement account lockout policies")
            report.append("  • Use strong passwords and 2FA")
            report.append("  • Monitor for successful breaches")
        
        if self.stats['credentials'] > 0:
            report.append("  • 🔴 CHANGE ALL EXPOSED PASSWORDS IMMEDIATELY")
            report.append("  • Switch to encrypted protocols (SFTP/HTTPS/SSH)")
            report.append("  • Implement network encryption (VPN/TLS)")
        
        report.append("\n" + "="*80)
        report.append("INCIDENT RESPONSE CHECKLIST")
        report.append("="*80)
        report.append("❌ Initial Assessment Complete")
        report.append("❌ Affected Systems Identified")
        report.append("❌ Attackers Blocked")
        report.append("❌ Passwords Rotated")
        report.append("❌ Security Patches Applied")
        report.append("❌ Incident Documented")
        
        self.report_text.insert(1.0, "\n".join(report))
        self.notebook.select(5)

def main():
    root = tk.Tk()
    app = PCAPAnalyzerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()