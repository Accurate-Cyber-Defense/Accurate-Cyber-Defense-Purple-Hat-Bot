# core/rules.py
import time
from collections import defaultdict, deque
from abc import ABC, abstractmethod
from scapy.all import IP, TCP

class DetectionRule(ABC):
    """Abstract Base Class for all detection rules."""
    def __init__(self, alerter, threshold):
        self.alerter = alerter
        self.threshold = threshold

    @property
    @abstractmethod
    def name(self):
        """The name of the rule, e.g., 'Port Scan'."""
        pass

    @abstractmethod
    def process_packet(self, packet):
        """Process a single packet and check if the rule is triggered."""
        pass

class PortScanRule(DetectionRule):
    """Detects when a single source IP scans multiple unique ports in a short time."""
    def __init__(self, alerter, threshold):
        super().__init__(alerter, threshold)
        # {ip: deque([(timestamp, port), ...])}
        self.scan_tracker = defaultdict(lambda: deque(maxlen=self.threshold * 2))

    @property
    def name(self):
        return "Port Scan"

    def process_packet(self, packet):
        if not packet.haslayer(TCP):
            return

        ip_src = packet[IP].src
        dst_port = packet[TCP].dport
        current_time = time.time()

        # Add current scan attempt
        self.scan_tracker[ip_src].append((current_time, dst_port))
        
        # Check for scans within a 60-second window
        first_scan_time = self.scan_tracker[ip_src][0][0]
        if (current_time - first_scan_time) <= 60:
            unique_ports = len(set(p for t, p in self.scan_tracker[ip_src]))
            if unique_ports >= self.threshold:
                message = f"Potential {self.name} detected from {ip_src}. Scanned {unique_ports} ports in under a minute."
                self.alerter.trigger_alert(ip_src, self.name, message)
                self.scan_tracker.pop(ip_src) # Reset after alerting


class DosAttackRule(DetectionRule):
    """Detects a high volume of packets from a single source IP per second."""
    def __init__(self, alerter, threshold):
        super().__init__(alerter, threshold)
        # {ip: [timestamp1, timestamp2, ...]}
        self.packet_timestamps = defaultdict(lambda: deque(maxlen=self.threshold * 2))

    @property
    def name(self):
        return "DoS Attack"

    def process_packet(self, packet):
        ip_src = packet[IP].src
        current_time = time.time()

        # Add packet timestamp
        self.packet_timestamps[ip_src].append(current_time)
        
        # Remove timestamps older than 1 second
        while self.packet_timestamps[ip_src] and self.packet_timestamps[ip_src][0] < current_time - 1:
            self.packet_timestamps[ip_src].popleft()

        # Check if count exceeds threshold
        packet_count = len(self.packet_timestamps[ip_src])
        if packet_count >= self.threshold:
            message = f"Potential {self.name} detected from {ip_src}. Received {packet_count} packets in the last second."
            self.alerter.trigger_alert(ip_src, self.name, message)
            self.packet_timestamps.pop(ip_src)


class HttpFloodRule(DetectionRule):
    """Detects a high volume of TCP packets to web ports (80, 443)."""
    def __init__(self, alerter, threshold):
        super().__init__(alerter, threshold)
        # {ip: [timestamp1, ...]}
        self.request_timestamps = defaultdict(lambda: deque(maxlen=self.threshold * 2))

    @property
    def name(self):
        return "HTTP Flood"

    def process_packet(self, packet):
        if not packet.haslayer(TCP) or packet[TCP].dport not in [80, 443]:
            return
        
        ip_src = packet[IP].src
        current_time = time.time()
        
        self.request_timestamps[ip_src].append(current_time)

        while self.request_timestamps[ip_src] and self.request_timestamps[ip_src][0] < current_time - 1:
            self.request_timestamps[ip_src].popleft()
            
        request_count = len(self.request_timestamps[ip_src])
        if request_count >= self.threshold:
            message = f"Potential {self.name} on port {packet[TCP].dport} from {ip_src}. {request_count} requests/sec."
            self.alerter.trigger_alert(ip_src, self.name, message)
            self.request_timestamps.pop(ip_src)