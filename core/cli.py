# core/cli.py
import os
import readline
import signal
import sys
from prettytable import PrettyTable
from config.settings import config
from config.theme import PURPLE, LIGHT_PURPLE, RED, YELLOW, GREEN, BOLD, RESET # CORRECTED IMPORT
from .monitor import NetworkMonitor
from .alerter import Alerter
from utils import diagnostics, simulation


class CLI:
    def __init__(self):
        self.alerter = Alerter()
        self.monitor = NetworkMonitor(self.alerter)
        self.is_running = True
        self._setup_signal_handlers()

    def _setup_signal_handlers(self):
        """Sets up signal handlers for graceful shutdown."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handles shutdown signals to ensure services are stopped."""
        if self.monitor.is_running:
            self.monitor.stop()
        print(f"\n{BOLD}{YELLOW}Shutdown signal received. Exiting...{RESET}")
        self.is_running = False
        sys.exit(0)


    #Dear maintainer.. cyrercard? i kept it because i was unsure about it but it dosent seem to make sense
    def _display_banner(self):
        banner = f"""
        {PURPLE}{BOLD}
         ██████╗██╗   ██╗██████╗ ███████╗██████╗  ██████╗ █████╗ ██████╗ ██████╗ 
        ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗
        ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║     ███████║██████╔╝██║  ██║
        ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║     ██╔══██║██╔══██╗██║  ██║
        ╚██████╗   ██║   ██║  ██║███████╗██║  ██║╚██████╗██║  ██║██║  ██║██████╔╝
         ╚═════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
        {RESET}
        {LIGHT_PURPLE}Accurate Cyber Defense Purple Hat Bot{RESET}
        """
        print(banner)

    def _display_help(self):
        help_text = f"""
        {BOLD}{PURPLE}AccurateCyberBot Command Reference:{RESET}

        {BOLD}MONITORING COMMANDS{RESET}
          start monitoring      - Start network traffic monitoring.
          stop monitoring       - Stop network traffic monitoring.
          view                  - View monitoring status and recent threats.
          add ip <IP>           - Add an IP to the monitoring list.
          remove ip <IP>        - Remove an IP from the monitoring list.

        {BOLD}DIAGNOSTIC COMMANDS{RESET}
          ping <IP>             - Ping an IP address.
          scan <IP>             - Perform a basic port scan on common ports.
          tracert <IP>          - Trace the route to an IP address.
          netstat               - Show network statistics.
          ifconfig / ip a       - Show network interface configurations.

        {BOLD}TELEGRAM INTEGRATION{RESET}
          config telegram token <TOKEN> - Set your Telegram bot token.
          config telegram chat_id <ID>  - Set your Telegram chat ID.
          test telegram         - Send a test notification to Telegram.
          export to telegram    - Send a full threat report to Telegram.

        {BOLD}THREAT SIMULATION{RESET}
          generate traffic <IP> <type> <duration_sec>
                                - Generate test traffic. Types: {BOLD}portscan, dos, httpflood{BOLD}

        {BOLD}GENERAL COMMANDS{RESET}
          help                  - Show this help message.
          clear                 - Clear the terminal screen.
          exit                  - Stop monitoring and exit the program.
        """
        print(help_text)

    def _clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        self._display_banner()

    def _view_status(self):
        """Displays monitoring status and detected threats."""
        monitored_ips = config.get("monitoring.monitored_ips", [])
        table = PrettyTable()
        table.field_names = [f"{BOLD}IP Address{RESET}", f"{BOLD}Status{RESET}", f"{BOLD}Threats Detected{RESET}"]
        table.align = "l"

        for ip in monitored_ips:
            status = f"{GREEN}Active{RESET}" if self.monitor.is_running else f"{YELLOW}Inactive{RESET}"
            threat_count = len(self.alerter.threat_history.get(ip, []))
            table.add_row([ip, status, threat_count])

        print(f"\n{PURPLE}{BOLD}--- Monitoring Status ---{RESET}")
        print(table)

        if self.alerter.threat_history:
            print(f"\n{PURPLE}{BOLD}--- Recent Threats ---{RESET}")
            threat_table = PrettyTable()
            threat_table.field_names = [
                f"{BOLD}Timestamp{RESET}", f"{BOLD}IP{RESET}",
                f"{BOLD}Type{RESET}", f"{BOLD}Description{RESET}"
            ]
            threat_table.align = "l"
            threat_table.max_width["Description"] = 50
            
            all_threats = [] #if you found this random comment, perhaps you're just as curious as me! fun fact, infact i may or may not be hiding my chromebook under my desk working on this right now...
            for ip_threats in self.alerter.threat_history.values():
                all_threats.extend(ip_threats)

            # Sort all threats by timestamp descending and take the last 5
            sorted_threats = sorted(all_threats, key=lambda x: x['timestamp'], reverse=True)
            
            for threat in sorted_threats[:5]:
                threat_table.add_row([
                    threat["timestamp"], threat["ip"], threat["type"], threat["description"]
                ])
            print(threat_table)

    def run(self):
        """Main command loop for the CLI."""
        self._clear_screen()
        while self.is_running:
            try:
                cmd_input = input(f"{LIGHT_PURPLE}AccurateBot>{RESET} ").strip()
                if not cmd_input:
                    continue

                parts = cmd_input.split()
                command = parts[0].lower()
                args = parts[1:]

                if command == "exit":
                    self.is_running = False
                    if self.monitor.is_running:
                        self.monitor.stop()
                elif command == "help":
                    self._display_help()
                elif command == "clear":
                    self._clear_screen()
                elif command == "start" and args and args[0] == "monitoring":
                    self.monitor.start()
                elif command == "stop" and args and args[0] == "monitoring":
                    self.monitor.stop()
                elif command == "view":
                    self._view_status()
                elif command == "add" and args and args[0] == "ip" and len(args) > 1:
                    ip_list = config.get("monitoring.monitored_ips", [])
                    if args[1] not in ip_list:
                        ip_list.append(args[1])
                        config.set("monitoring.monitored_ips", ip_list)
                        self.monitor.update_monitored_ips()
                    else:
                        print(f"{YELLOW}IP {args[1]} is already in the list.{YELLOW}")
                elif command == "remove" and args and args[0] == "ip" and len(args) > 1:
                    ip_list = config.get("monitoring.monitored_ips", [])
                    if args[1] in ip_list:
                        ip_list.remove(args[1])
                        config.set("monitoring.monitored_ips", ip_list)
                        self.monitor.update_monitored_ips()
                    else:
                        print(f"{YELLOW}IP {args[1]} not found in the list.{YELLOW}")
                elif command == "ping" and args:
                    diagnostics.ping_ip(args[0])
                elif command == "scan" and args:
                    diagnostics.scan_ip(args[0])
                elif command == "tracert" and args:
                    diagnostics.trace_route(args[0])
                elif command == "netstat":
                    diagnostics.show_netstat()
                elif command in ["ifconfig", "ip"]:
                    diagnostics.show_network_interfaces()
                elif command == "config" and len(args) > 2 and args[0] == "telegram":
                    key, value = args[1], " ".join(args[2:])
                    config.set(f"telegram.{key}", value)
                elif command == "test" and args and args[0] == "telegram":
                    test_alert = {"timestamp": "now", "ip": "127.0.0.1", "type": "Test", "description": "This is a test alert."}
                    self.alerter.send_telegram_alert(test_alert)
                elif command == "export" and len(args) > 1 and "telegram" in args:
                    self.alerter.export_threats_to_telegram()
                elif command == "generate" and len(args) > 3 and args[0] == "traffic":
                    simulation.generate_traffic(args[1], args[2], args[3])
                else:
                    print(f"{RED}Unknown command. Type 'help' for a list of commands.{RESET}")

            except KeyboardInterrupt:
                print("\nType 'exit' to quit.")
            except Exception as e:
                print(f"{BOLD}{RED}An unexpected error occurred: {e}{RESET}")