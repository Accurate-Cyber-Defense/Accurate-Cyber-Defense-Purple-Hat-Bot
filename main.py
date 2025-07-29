#!/usr/bin/env python3
# main.py
"""
:3
Accurate Cyber Defense Purple Bot 
Version: 19.1, Unstable, Revision 2
Author: Ian Carter Kulani
Description: Real-time network threat detection system with Telegram integration
"""
import os
import sys
from core.cli import CLI
from config.theme import RED, YELLOW

def check_root():
    """Checks for root privileges on non-Windows systems."""
    if sys.platform != "win32" and os.geteuid() != 0:
        print(f"{RED}Error: This script requires root privileges to capture network packets.")
        print(f"{YELLOW}Please run it with 'sudo': sudo python3 main.py{YELLOW}")
        sys.exit(1)

def main():
    """Main function to initialize and run the application."""
    check_root()
    try:
        app = CLI()
        app.run()
    except Exception as e:
        print(f"\nA critical error occurred: {e}")
        print("The application will now exit.")
        sys.exit(1)

if __name__ == "__main__":
    main()