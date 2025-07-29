# utils/simulation.py
import time
import socket
import requests
from config.theme import BOLD, RED, GREEN, YELLOW, RESET

def generate_traffic(ip, traffic_type, duration_str):
    """Main function to start a traffic simulation."""
    try:
        duration = int(duration_str)
        if duration <= 0:
            print(f"{RED}Duration must be a positive integer.{RESET}")
            return
    except ValueError:
        print(f"{RED}Invalid duration. Please provide an integer in seconds.{RESET}")
        return

    print(f"{BOLD}Starting simulation: {traffic_type} to {ip} for {duration} seconds... (Press CTRL+C to stop early){RESET}")
    
    if traffic_type.lower() == "portscan":
        _simulate_port_scan(ip, duration)
    elif traffic_type.lower() == "dos":
        _simulate_dos_attack(ip, duration)
    elif traffic_type.lower() == "httpflood":
        _simulate_http_flood(ip, duration)
    else:
        print(f"{RED}Unknown traffic type. Valid types are: portscan, dos, httpflood.{RESET}")
        return

    print(f"{GREEN}Traffic generation finished.{RESET}")

def _simulate_port_scan(ip, duration):
    """Simulates a port scan by attempting to connect to a range of ports."""
    end_time = time.time() + duration
    port = 1
    try:
        while time.time() < end_time:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.05)
                s.connect_ex((ip, port))
            port = (port % 1024) + 1
            time.sleep(0.01)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Port scan simulation stopped by user.{RESET}")

def _simulate_dos_attack(ip, duration):
    """Simulates a DoS attack by sending rapid connection attempts."""
    end_time = time.time() + duration
    target_port = 80 # A common target
    try:
        while time.time() < end_time:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.01)
                    s.connect((ip, target_port))
            except Exception:
                pass
    except KeyboardInterrupt:
        print(f"\n{YELLOW}DoS simulation stopped by user.{RESET}")


def _simulate_http_flood(ip, duration):
    """Simulates an HTTP flood using the requests library."""
    url = f"http://{ip}"
    end_time = time.time() + duration
    headers = {'User-Agent': 'AccurateCyberBot-Sim/1.0', 'Connection': 'close'}
    try:
        while time.time() < end_time:
            try:
                requests.get(url, headers=headers, timeout=0.5)
            except requests.exceptions.RequestException:
                pass
    except KeyboardInterrupt:
        print(f"\n{YELLOW}HTTP flood simulation stopped by user.{RESET}")