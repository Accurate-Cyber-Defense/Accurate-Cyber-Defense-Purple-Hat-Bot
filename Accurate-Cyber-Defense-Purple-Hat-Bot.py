#!/usr/bin/env python3
"""
Accurate Cyber Defense Purple Bot 
Version: 19.1
Author: Ian Carter Kulani
Description: Real-time network threat detection system with Telegram integration
"""

import os
import sys
import time
import socket
import threading
import subprocess
import json
import requests
from datetime import datetime
from scapy.all import *
from collections import defaultdict, deque
import platform
import re
import readline
import signal
from prettytable import PrettyTable
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

# Purple theme colors
PURPLE = Fore.MAGENTA
LIGHT_PURPLE = Fore.LIGHTMAGENTA_EX
DARK_PURPLE = Fore.BLUE
BOLD = Style.BRIGHT
RESET = Style.RESET_ALL

# Global configuration
CONFIG_FILE = "accuratecyberbot_config.json"
DEFAULT_CONFIG = {
    "telegram_token": "",
    "telegram_chat_id": "",
    "monitored_ips": [],
    "thresholds": {
        "port_scan": 10,  # Ports per minute
        "dos_attack": 100,  # Packets per second
        "http_flood": 50   # Requests per second
    },
    "alert_cooldown": 300  # 5 minutes in seconds
}

# Global variables
monitoring = False
monitored_ips = set()
packet_counts = defaultdict(lambda: defaultdict(int))
port_scan_counts = defaultdict(lambda: defaultdict(int))
http_request_counts = defaultdict(int)
alerts_sent = defaultdict(float)
traffic_thread = None
stop_event = threading.Event()

class Accuratecyberdefense:
    def __init__(self):
        self.config = self.load_config()
        self.running = True
        self.command_history = []
        self.setup_signal_handlers()
        
        # Apply purple theme
        self.banner_color = PURPLE
        self.prompt_color = LIGHT_PURPLE
        self.text_color = PURPLE
        self.highlight_color = BOLD + LIGHT_PURPLE
        self.warning_color = Fore.YELLOW
        self.error_color = Fore.RED
        self.success_color = Fore.GREEN
        
        # Initialize packet capture
        self.sniffer = None
        self.sniffer_thread = None
        
        # Initialize threat detection
        self.threats_detected = defaultdict(list)
        self.last_alert_time = defaultdict(float)
        
        # Load monitored IPs from config
        for ip in self.config["monitored_ips"]:
            monitored_ips.add(ip)
    
    def load_config(self):
        """Load configuration from file or create default"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    config = json.load(f)
                    # Merge with default config to ensure all keys exist
                    for key, value in DEFAULT_CONFIG.items():
                        if key not in config:
                            config[key] = value
                    return config
            except Exception as e:
                print(f"{self.error_color}Error loading config: {e}. Using default configuration.")
                return DEFAULT_CONFIG.copy()
        else:
            return DEFAULT_CONFIG.copy()
    
    def save_config(self):
        """Save configuration to file"""
        try:
            with open(CONFIG_FILE, "w") as f:
                json.dump(self.config, f, indent=4)
            return True
        except Exception as e:
            print(f"{self.error_color}Error saving config: {e}")
            return False
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n{self.warning_color}Received shutdown signal. Stopping monitoring...")
        self.stop_monitoring()
        self.running = False
        sys.exit(0)
    
    def display_banner(self):
        """Display the CyberGuard banner"""
        banner = f"""
        {self.banner_color}{BOLD}
         ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗ █████╗ ██████╗ ██████╗ 
        ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗
        ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║     ███████║██████╔╝██║  ██║
        ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║     ██╔══██║██╔══██╗██║  ██║
        ╚██████╗   ██║   ██║  ██║███████╗██║  ██║╚██████╗██║  ██║██║  ██║██████╔╝
         ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
        {RESET}
        {self.text_color}Accuarete Cyber Defense Purple Hat Bot | Version 19.1 | Ian Carter Kulani{RESET}
        """
        print(banner)
    
    def display_help(self):
        """Display help information"""
        help_text = f"""
        {self.highlight_color}Accuratecyber Command Reference:{RESET}
        
        {self.text_color}General Commands:{RESET}
        {self.highlight_color}help{RESET}               - Show this help message
        {self.highlight_color}clear{RESET}              - Clear the screen
        {self.highlight_color}exit{RESET}               - Exit the program
        {self.highlight_color}stop{RESET}               - Stop monitoring and exit
        
        {self.text_color}Network Diagnostic Commands:{RESET}
        {self.highlight_color}ping <IP>{RESET}          - Ping an IP address
        {self.highlight_color}scan <IP>{RESET}         - Perform a basic port scan
        {self.highlight_color}tracert <IP>{RESET}      - Trace route to an IP
        {self.highlight_color}ip a{RESET}              - Show network interfaces (Linux)
        {self.highlight_color}ifconfig{RESET}          - Show network interfaces (macOS/Unix)
        {self.highlight_color}netstat{RESET}           - Show network statistics
        
        {self.text_color}Monitoring Commands:{RESET}
        {self.highlight_color}start monitoring <IP>{RESET} - Start monitoring an IP for threats
        {self.highlight_color}add ip <IP>{RESET}        - Add an IP to monitoring list
        {self.highlight_color}remove ip <IP>{RESET}     - Remove an IP from monitoring list
        {self.highlight_color}view{RESET}               - View current monitoring status
        
        {self.text_color}Threat Simulation:{RESET}
        {self.highlight_color}generate traffic <IP> <type> <duration>{RESET} - Generate test traffic
            Types: portscan, dos, httpflood, httpsflood
        
        {self.text_color}Telegram Integration:{RESET}
        {self.highlight_color}config_telegram token <TOKEN>{RESET} - Set Telegram bot token
        {self.highlight_color}config_telegram chat_id <ID>{RESET} - Set Telegram chat ID
        {self.highlight_color}test telegram{RESET}      - Test Telegram notification
        {self.highlight_color}export to telegram{RESET} - Export current alerts to Telegram
        """
        print(help_text)
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        self.display_banner()
    
    def show_network_interfaces(self):
        """Show network interface information"""
        try:
            if platform.system().lower() == 'linux':
                result = subprocess.run(['ip', 'a'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"{self.text_color}Network Interfaces:{RESET}")
                print(result.stdout)
            else:
                print(f"{self.error_color}Error getting network interfaces:{RESET}")
                print(result.stderr)
        except Exception as e:
            print(f"{self.error_color}Error showing network interfaces: {e}{RESET}")
    
    def show_netstat(self):
        """Show network statistics"""
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            else:
                result = subprocess.run(['netstat', '-tulnp'], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"{self.text_color}Network Statistics:{RESET}")
                print(result.stdout)
            else:
                print(f"{self.error_color}Error getting network statistics:{RESET}")
                print(result.stderr)
        except Exception as e:
            print(f"{self.error_color}Error showing network statistics: {e}{RESET}")
    
    def ping_ip(self, ip):
        """Ping an IP address"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            count = '4'  # Number of ping packets
            command = ['ping', param, count, ip]
            
            print(f"{self.text_color}Pinging {ip}...{RESET}")
            output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if output.returncode == 0:
                print(f"{self.success_color}Ping successful to {ip}{RESET}")
                print(output.stdout)
            else:
                print(f"{self.error_color}Ping failed to {ip}{RESET}")
                print(output.stderr)
        except Exception as e:
            print(f"{self.error_color}Error pinging {ip}: {e}{RESET}")
    
    def scan_ip(self, ip):
        """Perform a basic port scan on an IP address"""
        try:
            print(f"{self.text_color}Scanning common ports on {ip}...{RESET}")
            
            common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                    service = socket.getservbyport(port) if port <= 1024 else "unknown"
                    print(f"{self.success_color}Port {port} ({service}) is open{RESET}")
                sock.close()
            
            if not open_ports:
                print(f"{self.warning_color}No open ports found on {ip}{RESET}")
            
            return open_ports
        except Exception as e:
            print(f"{self.error_color}Error scanning {ip}: {e}{RESET}")
            return []
    
    def trace_route(self, ip):
        """Perform a traceroute to an IP address"""
        try:
            param = '-d' if platform.system().lower() == 'windows' else ''
            command = ['tracert', param, ip] if platform.system().lower() == 'windows' else ['traceroute', ip]
            
            print(f"{self.text_color}Tracing route to {ip}...{RESET}")
            subprocess.run(command)
        except Exception as e:
            print(f"{self.error_color}Error performing traceroute to {ip}: {e}{RESET}")
    
    def start_monitoring(self, ip=None):
        """Start monitoring network traffic for threats"""
        global monitoring, traffic_thread
        
        if monitoring:
            print(f"{self.warning_color}Monitoring is already running{RESET}")
            return
        
        if ip:
            monitored_ips.add(ip)
            if ip not in self.config["monitored_ips"]:
                self.config["monitored_ips"].append(ip)
                self.save_config()
        
        if not monitored_ips:
            print(f"{self.error_color}No IPs to monitor. Add IPs first.{RESET}")
            return
        
        print(f"{self.text_color}Starting monitoring on: {', '.join(monitored_ips)}{RESET}")
        
        monitoring = True
        stop_event.clear()
        
        # Start packet capture in a separate thread
        self.sniffer = threading.Thread(target=self.packet_capture)
        self.sniffer.daemon = True
        self.sniffer.start()
        
        # Start threat analysis in a separate thread
        traffic_thread = threading.Thread(target=self.analyze_traffic)
        traffic_thread.daemon = True
        traffic_thread.start()
        
        print(f"{self.success_color}Monitoring started successfully{RESET}")
    
    def stop_monitoring(self):
        """Stop monitoring network traffic"""
        global monitoring, traffic_thread
        
        if not monitoring:
            print(f"{self.warning_color}Monitoring is not running{RESET}")
            return
        
        monitoring = False
        stop_event.set()
        
        if self.sniffer and self.sniffer.is_alive():
            self.sniffer.join(timeout=2)
        
        if traffic_thread and traffic_thread.is_alive():
            traffic_thread.join(timeout=2)
        
        print(f"{self.success_color}Monitoring stopped{RESET}")
    
    def packet_capture(self):
        """Capture network packets using scapy"""
        try:
            print(f"{self.text_color}Starting packet capture...{RESET}")
            
            # Filter to only capture traffic to/from monitored IPs
            bpf_filter = " or ".join([f"host {ip}" for ip in monitored_ips])
            
            sniff(prn=self.process_packet, filter=bpf_filter, store=0, stop_filter=lambda x: stop_event.is_set())
        except Exception as e:
            print(f"{self.error_color}Packet capture error: {e}{RESET}")
    
    def process_packet(self, packet):
        """Process captured packets"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Only process packets involving monitored IPs
                if src_ip in monitored_ips or dst_ip in monitored_ips:
                    current_time = time.time()
                    minute = int(current_time // 60)
                    
                    # Count packets by source IP
                    if src_ip in monitored_ips:
                        packet_counts[src_ip]['outgoing'][minute] += 1
                    else:
                        packet_counts[dst_ip]['incoming'][minute] += 1
                    
                    # Detect port scans
                    if TCP in packet:
                        port = packet[TCP].dport
                        port_scan_counts[src_ip][minute] += 1
                    
                    # Detect HTTP floods
                    if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].dport == 443):
                        http_request_counts[src_ip][minute] += 1
        except Exception as e:
            print(f"{self.error_color}Packet processing error: {e}{RESET}")
    
    def analyze_traffic(self):
        """Analyze network traffic for threats"""
        while not stop_event.is_set():
            try:
                current_time = time.time()
                current_minute = int(current_time // 60)
                
                for ip in list(monitored_ips):
                    # Check for DoS attacks (incoming packets)
                    incoming_packets = sum(packet_counts[ip]['incoming'].values())
                    if incoming_packets > self.config["thresholds"]["dos_attack"]:
                        if current_time - self.last_alert_time.get(f"dos_{ip}", 0) > self.config["alert_cooldown"]:
                            self.detect_threat(ip, "DoS Attack", f"High incoming packet rate: {incoming_packets} packets/minute")
                            self.last_alert_time[f"dos_{ip}"] = current_time
                    
                    # Check for port scans (outgoing packets)
                    outgoing_scans = sum(port_scan_counts[ip].values())
                    if outgoing_scans > self.config["thresholds"]["port_scan"]:
                        if current_time - self.last_alert_time.get(f"portscan_{ip}", 0) > self.config["alert_cooldown"]:
                            self.detect_threat(ip, "Port Scan", f"High port scan activity: {outgoing_scans} ports scanned/minute")
                            self.last_alert_time[f"portscan_{ip}"] = current_time
                    
                    # Check for HTTP floods
                    http_requests = sum(http_request_counts[ip].values())
                    if http_requests > self.config["thresholds"]["http_flood"]:
                        if current_time - self.last_alert_time.get(f"httpflood_{ip}", 0) > self.config["alert_cooldown"]:
                            self.detect_threat(ip, "HTTP Flood", f"High HTTP request rate: {http_requests} requests/minute")
                            self.last_alert_time[f"httpflood_{ip}"] = current_time
                
                # Clean up old data (older than 2 minutes)
                old_minute = current_minute - 2
                for ip in list(packet_counts.keys()):
                    for direction in ['incoming', 'outgoing']:
                        for minute in list(packet_counts[ip][direction].keys()):
                            if minute < old_minute:
                                del packet_counts[ip][direction][minute]
                
                for ip in list(port_scan_counts.keys()):
                    for minute in list(port_scan_counts[ip].keys()):
                        if minute < old_minute:
                            del port_scan_counts[ip][minute]
                
                for ip in list(http_request_counts.keys()):
                    for minute in list(http_request_counts[ip].keys()):
                        if minute < old_minute:
                            del http_request_counts[ip][minute]
                
                time.sleep(5)  # Check every 5 seconds
            except Exception as e:
                print(f"{self.error_color}Traffic analysis error: {e}{RESET}")
                time.sleep(10)
    
    def detect_threat(self, ip, threat_type, description):
        """Handle detected threats"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = {
            "timestamp": timestamp,
            "ip": ip,
            "type": threat_type,
            "description": description
        }
        
        self.threats_detected[ip].append(alert)
        print(f"{self.warning_color}ALERT: {threat_type} detected from {ip} - {description}{RESET}")
        
        # Send Telegram alert if configured
        if self.config["telegram_token"] and self.config["telegram_chat_id"]:
            self.send_telegram_alert(alert)
    
    def add_ip(self, ip):
        """Add an IP to the monitoring list"""
        if not self.validate_ip(ip):
            print(f"{self.error_color}Invalid IP address format{RESET}")
            return
        
        if ip in monitored_ips:
            print(f"{self.warning_color}IP {ip} is already being monitored{RESET}")
            return
        
        monitored_ips.add(ip)
        if ip not in self.config["monitored_ips"]:
            self.config["monitored_ips"].append(ip)
            self.save_config()
        
        print(f"{self.success_color}Added {ip} to monitoring list{RESET}")
    
    def remove_ip(self, ip):
        """Remove an IP from the monitoring list"""
        if ip in monitored_ips:
            monitored_ips.remove(ip)
            if ip in self.config["monitored_ips"]:
                self.config["monitored_ips"].remove(ip)
                self.save_config()
            print(f"{self.success_color}Removed {ip} from monitoring list{RESET}")
        else:
            print(f"{self.warning_color}IP {ip} is not being monitored{RESET}")
    
    def view_status(self):
        """View current monitoring status"""
        table = PrettyTable()
        table.field_names = [f"{self.highlight_color}IP Address{RESET}", f"{self.highlight_color}Status{RESET}", f"{self.highlight_color}Threats Detected{RESET}"]
        table.align = "l"
        
        for ip in monitored_ips:
            status = "Active" if monitoring else "Inactive"
            threat_count = len(self.threats_detected.get(ip, []))
            table.add_row([ip, status, threat_count])
        
        print(f"\n{self.text_color}{BOLD}Monitoring Status:{RESET}")
        print(table)
        
        if self.threats_detected:
            print(f"\n{self.text_color}{BOLD}Recent Threats:{RESET}")
            threat_table = PrettyTable()
            threat_table.field_names = [
                f"{self.highlight_color}Timestamp{RESET}", 
                f"{self.highlight_color}IP{RESET}", 
                f"{self.highlight_color}Type{RESET}", 
                f"{self.highlight_color}Description{RESET}"
            ]
            threat_table.align = "l"
            
            for ip, threats in self.threats_detected.items():
                for threat in threats[-3:]:  # Show last 3 threats per IP
                    threat_table.add_row([
                        threat["timestamp"],
                        threat["ip"],
                        threat["type"],
                        threat["description"]
                    ])
            
            print(threat_table)
    
    def generate_traffic(self, ip, traffic_type, duration):
        """Generate test traffic for simulation"""
        try:
            duration = int(duration)
            if duration <= 0:
                print(f"{self.error_color}Duration must be positive{RESET}")
                return
            
            print(f"{self.text_color}Generating {traffic_type} traffic to {ip} for {duration} seconds...{RESET}")
            
            if traffic_type.lower() == "portscan":
                self.simulate_port_scan(ip, duration)
            elif traffic_type.lower() == "dos":
                self.simulate_dos_attack(ip, duration)
            elif traffic_type.lower() in ["httpflood", "httpsflood"]:
                self.simulate_http_flood(ip, duration, traffic_type.lower() == "httpsflood")
            else:
                print(f"{self.error_color}Unknown traffic type: {traffic_type}{RESET}")
                return
            
            print(f"{self.success_color}Traffic generation completed{RESET}")
        except ValueError:
            print(f"{self.error_color}Invalid duration format{RESET}")
        except Exception as e:
            print(f"{self.error_color}Error generating traffic: {e}{RESET}")
    
    def simulate_port_scan(self, ip, duration):
        """Simulate a port scan"""
        ports_to_scan = range(1, 1025)  # Scan common ports
        end_time = time.time() + duration
        
        while time.time() < end_time:
            for port in ports_to_scan:
                if time.time() >= end_time:
                    break
                
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    result = sock.connect_ex((ip, port))
                    sock.close()
                    time.sleep(0.01)  # Small delay between scans
                except:
                    pass
    
    def simulate_dos_attack(self, ip, duration):
        """Simulate a DoS attack"""
        end_time = time.time() + duration
        
        while time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect((ip, 80))  # Try to connect to port 80
                sock.close()
            except:
                pass
    
    def simulate_http_flood(self, ip, duration, https=False):
        """Simulate an HTTP/HTTPS flood"""
        protocol = "https" if https else "http"
        url = f"{protocol}://{ip}"
        end_time = time.time() + duration
        
        while time.time() < end_time:
            try:
                requests.get(url, timeout=1)
            except:
                pass
    
    def config_telegram(self, param, value):
        """Configure Telegram settings"""
        if param == "token":
            self.config["telegram_token"] = value
            self.save_config()
            print(f"{self.success_color}Telegram token configured{RESET}")
        elif param == "chat_id":
            self.config["telegram_chat_id"] = value
            self.save_config()
            print(f"{self.success_color}Telegram chat ID configured{RESET}")
        else:
            print(f"{self.error_color}Unknown Telegram parameter: {param}{RESET}")
    
    def test_telegram(self):
        """Test Telegram notification"""
        if not self.config["telegram_token"] or not self.config["telegram_chat_id"]:
            print(f"{self.error_color}Telegram token or chat ID not configured{RESET}")
            return
        
        test_message = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip": "127.0.0.1",
            "type": "Test Alert",
            "description": "This is a test notification from CyberGuard"
        }
        
        if self.send_telegram_alert(test_message):
            print(f"{self.success_color}Telegram test notification sent successfully{RESET}")
        else:
            print(f"{self.error_color}Failed to send Telegram test notification{RESET}")
    
    def send_telegram_alert(self, alert):
        """Send alert to Telegram"""
        try:
            token = self.config["telegram_token"]
            chat_id = self.config["telegram_chat_id"]
            
            message = (
                f"🚨 *Accurate Cyber Defense Alert* 🚨\n"
                f"*Timestamp:* {alert['timestamp']}\n"
                f"*IP Address:* `{alert['ip']}`\n"
                f"*Threat Type:* {alert['type']}\n"
                f"*Description:* {alert['description']}"
            )
            
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            params = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(url, json=params)
            return response.status_code == 200
        except Exception as e:
            print(f"{self.error_color}Error sending Telegram alert: {e}{RESET}")
            return False
    
    def export_to_telegram(self):
        """Export current alerts to Telegram"""
        if not self.config["telegram_token"] or not self.config["telegram_chat_id"]:
            print(f"{self.error_color}Telegram token or chat ID not configured{RESET}")
            return
        
        if not self.threats_detected:
            print(f"{self.warning_color}No threats to export{RESET}")
            return
        
        message = "📊 *Accurate Cyber Defense Threat Report* 📊\n\n"
        for ip, threats in self.threats_detected.items():
            message += f"*IP Address:* `{ip}`\n"
            message += f"*Threat Count:* {len(threats)}\n\n"
            
            for threat in threats[-5:]:  # Last 5 threats per IP
                message += (
                    f"⏰ *Time:* {threat['timestamp']}\n"
                    f"🔍 *Type:* {threat['type']}\n"
                    f"📝 *Details:* {threat['description']}\n\n"
                )
        
        try:
            token = self.config["telegram_token"]
            chat_id = self.config["telegram_chat_id"]
            
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            params = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            
            response = requests.post(url, json=params)
            if response.status_code == 200:
                print(f"{self.success_color}Threat report sent to Telegram{RESET}")
            else:
                print(f"{self.error_color}Failed to send threat report to Telegram{RESET}")
        except Exception as e:
            print(f"{self.error_color}Error exporting to Telegram: {e}{RESET}")
    
    def validate_ip(self, ip):
        """Validate an IP address"""
        pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(pattern, ip) is not None
    
    def run(self):
        """Main command loop"""
        self.clear_screen()
        
        while self.running:
            try:
                command = input(f"{self.prompt_color}AccurateBot>{RESET}").strip()
                
                if not command:
                    continue
                
                self.command_history.append(command)
                
                # Parse command
                parts = command.lower().split()
                cmd = parts[0]
                
                if cmd == "help":
                    self.display_help()
                elif cmd == "clear":
                    self.clear_screen()
                elif cmd == "exit":
                    self.stop_monitoring()
                    self.running = False
                elif cmd == "stop":
                    self.stop_monitoring()
                    self.running = False
                elif cmd == "ping" and len(parts) > 1:
                    self.ping_ip(parts[1])
                elif cmd == "scan" and len(parts) > 1:
                    self.scan_ip(parts[1])
                elif cmd == "tracert" and len(parts) > 1:
                    self.trace_route(parts[1])
                elif cmd == "ip" and len(parts) > 1 and parts[1] == "a":
                    self.show_network_interfaces()
                elif cmd == "ifconfig":
                    self.show_network_interfaces()
                elif cmd == "netstat":
                    self.show_netstat()
                elif cmd == "start" and len(parts) > 2 and parts[1] == "monitoring":
                    self.start_monitoring(parts[2])
                elif cmd == "add" and len(parts) > 2 and parts[1] == "ip":
                    self.add_ip(parts[2])
                elif cmd == "remove" and len(parts) > 2 and parts[1] == "ip":
                    self.remove_ip(parts[2])
                elif cmd == "view":
                    self.view_status()
                elif cmd == "generate" and len(parts) > 4 and parts[1] == "traffic":
                    self.generate_traffic(parts[2], parts[3], parts[4])
                elif cmd == "test" and len(parts) > 1 and parts[1] == "telegram":
                    self.test_telegram()
                elif cmd == "export" and len(parts) > 2 and parts[1] == "to" and parts[2] == "telegram":
                    self.export_to_telegram()
                elif cmd == "config_telegram" and len(parts) > 3:
                    self.config_telegram(parts[1], parts[2])
                else:
                    print(f"{self.error_color}Unknown command: {command}{RESET}")
                    print(f"{self.text_color}Type 'help' for available commands{RESET}")
            except KeyboardInterrupt:
                print("\nType 'exit' or 'stop' to exit or 'help' for commands")
            except Exception as e:
                print(f"{self.error_color}Error processing command: {e}{RESET}")

if __name__ == "__main__":
    tool = Accuratecyberdefense()
    tool.run()