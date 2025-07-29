# core/monitor.py
import threading
import time
from config.theme import BOLD, LIGHT_PURPLE, PURPLE # CHANGED: Updated import path
from config.settings import config
from core.alerter import Alerter
from core.rules import PortScanRule, DosAttackRule 
from collections import namedtuple
import random

# --- MOCK PACKET CAPTURE (for demonstration) ---
Packet = namedtuple('Packet', ['src', 'dst', 'sport', 'dport'])
def mock_packet_capture():
    time.sleep(0.01)
    ip = f"192.168.1.{random.randint(10, 200)}"
    if random.randint(1, 10) == 1:
        ip = "10.0.0.5"
    return Packet(ip, "192.168.1.100", random.randint(10000, 65000), random.choice([22, 80, 443, 3389, random.randint(1, 65535)]))
# --- END MOCK ---

class NetworkMonitor:
    def __init__(self, alerter): # <-- 1. Add 'alerter' as a parameter
        self.is_running = False
        self._stop_event = threading.Event()
        self._monitor_thread = None
        self.alerter = alerter # <-- 2. Use the alerter that was passed in
        self.rules = self._load_rules()

    def _load_rules(self):
        # (Content of this method is unchanged)
        loaded_rules = []
        rule_config = config.get("rules", {})
        print(f"{PURPLE}Loading detection rules...{PURPLE}")
        if rule_config.get("port_scan.enabled"):
            rule = PortScanRule(self.alerter, rule_config.get("port_scan.threshold"), rule_config.get("port_scan.time_window"))
            loaded_rules.append(rule)
            print(f"  - {BOLD}{rule.name} rule enabled.{BOLD}")
        if rule_config.get("dos_attack.enabled"):
            rule = DosAttackRule(self.alerter, rule_config.get("dos_attack.threshold"), rule_config.get("dos_attack.time_window"))
            loaded_rules.append(rule)
            print(f"  - {BOLD}{rule.name} rule enabled.{BOLD}")
        return loaded_rules

    def _packet_processor(self):
        # (Content of this method is unchanged)
        print(f"\n{BOLD}{LIGHT_PURPLE}Network monitoring started. Press CTRL+C to stop.{BOLD}\n")
        while not self._stop_event.is_set():
            try:
                packet = mock_packet_capture()
                ip_src = packet.src
                for rule in self.rules:
                    rule.process_packet(packet, ip_src)
            except Exception as e:
                print(f"Error during packet processing: {e}")

    def start(self):
        # (Content of this method is unchanged)
        if self.is_running:
            print("Monitor is already running.")
            return
        self.is_running = True
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._packet_processor)
        self._monitor_thread.start()

    def stop(self):
        # (Content of this method is unchanged)
        if not self.is_running:
            return
        print(f"\n{BOLD}{LIGHT_PURPLE}Stopping network monitor...{BOLD}")
        self._stop_event.set()
        self._monitor_thread.join()
        self.is_running = False
        print(f"{BOLD}{PURPLE}Monitoring stopped.{BOLD}")