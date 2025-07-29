# utils/diagnostics.py
import subprocess
import platform
import socket
from config.theme import BOLD, GREEN, RED, YELLOW, RESET

def _run_command(command, title):
    """Helper function to run a system command and print its output."""
    print(f"{BOLD}Running: {title}...{RESET}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=30)
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"{YELLOW}{result.stderr}{RESET}")
    except FileNotFoundError:
        print(f"{RED}Error: Command '{command[0]}' not found. Is it installed and in your PATH?{RESET}")
    except Exception as e:
        print(f"{RED}An error occurred: {e}{RESET}")

def ping_ip(ip):
    """Pings a given IP address."""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '4', ip]
    _run_command(command, f"Ping {ip}")

def scan_ip(ip):
    """Performs a basic port scan on common ports."""
    print(f"{BOLD}Scanning common ports on {ip}...{RESET}")
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080, 8443]
    open_ports = []
    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
                try:
                    service = socket.getservbyport(port, 'tcp')
                except OSError:
                    service = "unknown"
                print(f"  {GREEN}Port {port:<5} ({service}) is open{RESET}")
    if not open_ports:
        print(f"{YELLOW}No common ports seem to be open.{RESET}")

def trace_route(ip):
    """Traces the route to a given IP address."""
    command = ['tracert', ip] if platform.system().lower() == 'windows' else ['traceroute', ip]
    _run_command(command, f"Traceroute to {ip}")

def show_netstat():
    """Shows network statistics."""
    if platform.system().lower() == 'windows':
        command = ['netstat', '-an']
    else:
        command = ['netstat', '-tulnp'] # Requires sudo
    _run_command(command, "Network Statistics (netstat)")

def show_network_interfaces():
    """Shows network interface configurations."""
    if platform.system().lower() == 'linux':
        command = ['ip', 'a']
    elif platform.system().lower() == 'darwin': # macOS
        command = ['ifconfig']
    elif platform.system().lower() == 'windows':
        command = ['ipconfig', '/all']
    else:
        command = ['ifconfig'] # Fallback
    _run_command(command, "Network Interfaces")