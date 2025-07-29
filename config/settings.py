# config/settings.py
import json
import os
from .theme import RED, YELLOW, BOLD # CHANGED: Relative import

class Config:
    def __init__(self):
        # CHANGED: This logic now robustly finds the config file
        # It constructs an absolute path to the config file relative to this script's location.
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.path = os.path.join(base_dir, "accuratecyberbot_config.json")
        self.settings = self._load()

    def _load(self):
        """Loads the configuration from the JSON file."""
        if not os.path.exists(self.path):
            print(f"{BOLD}{RED}Error: Configuration file '{self.path}' not found.{BOLD}")
            print(f"{YELLOW}Please ensure it exists in the 'config' directory.")
            exit(1)
        
        try:
            with open(self.path, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print(f"{BOLD}{RED}Error: Could not decode JSON from '{self.path}'. Check for syntax errors.{BOLD}")
            exit(1)

    def get(self, key, default=None):
        """A simple getter to access nested configuration keys."""
        keys = key.split('.')
        value = self.settings
        for k in keys:
            if not isinstance(value, dict) or k not in value:
                return default
            value = value[k]
        return value

# Create a single instance to be imported by other modules
config = Config()