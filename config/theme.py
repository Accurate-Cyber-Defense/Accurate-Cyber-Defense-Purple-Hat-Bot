# config/theme.py
from colorama import Fore, Style, init

# Initialize colorama to work on all platforms
init(autoreset=True)

# Application theme colors
PURPLE = Fore.MAGENTA
LIGHT_PURPLE = Fore.LIGHTMAGENTA_EX
DARK_PURPLE = Fore.BLUE
RED = Fore.RED
YELLOW = Fore.YELLOW
GREEN = Fore.GREEN  # <-- ADDED
BOLD = Style.BRIGHT
RESET = Style.RESET_ALL # <-- ADDED