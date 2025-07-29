# core/alerter.py
import time
from collections import defaultdict
from config.settings import config
from config.theme import YELLOW, BOLD, PURPLE, RED # CHANGED: Updated import path

class Alerter:
    def __init__(self):
        self.cooldown = config.get("alert_cooldown_seconds", 300)
        self.telegram_enabled = config.get("telegram.enabled", False)
        self.telegram_token = config.get("telegram.token")
        self.telegram_chat_id = config.get("telegram.chat_id")
        self._alerts_sent = defaultdict(float)

    def is_on_cooldown(self, rule_name, target_ip):
        """Check if an alert for a specific rule and IP is on cooldown."""
        key = f"{rule_name}:{target_ip}"
        last_alert_time = self._alerts_sent.get(key, 0)
        return (time.time() - last_alert_time) < self.cooldown

    def trigger_alert(self, rule_name, target_ip, message):
        """Triggers an alert if not on cooldown."""
        if self.is_on_cooldown(rule_name, target_ip):
            return

        print(f"{BOLD}{RED}[ALERT] {message}{BOLD}")
        
        if self.telegram_enabled:
            self.send_telegram_alert(message)
            
        key = f"{rule_name}:{target_ip}"
        self._alerts_sent[key] = time.time()

    def send_telegram_alert(self, message):
        """Sends a message via the Telegram Bot API."""
        if not self.telegram_token or not self.telegram_chat_id:
            print(f"{YELLOW}Warning: Telegram is enabled, but token or chat_id is missing.{YELLOW}")
            return
        
        print(f"{PURPLE}--> Sending alert to Telegram...{PURPLE}")
        # Placeholder for API call logic