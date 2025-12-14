import os
import json
from datetime import datetime


class MissionConfig:
    def __init__(self):
        self.load_config()

    def load_config(self):
        self.network = {
            "host": "0.0.0.0",
            "port": 9999,
            "server_ip": "localhost",
            "max_connections": 10,
            "timeout": 30,
            "heartbeat_interval": 60,
        }

        self.security = {
            "encryption_enabled": True,
            "session_timeout": 3600,
            "max_failed_attempts": 3,
            "auto_cleanup": True,
            "secure_delete_passes": 3,
        }

        self.operations = {
            "max_message_history": 1000,
            "auto_backup": True,
            "backup_interval": 300,
            "log_retention_days": 7,
            "emergency_wipe_enabled": True,
        }

        self.ui = {
            "timestamp_format": "%H:%M:%S",
            "date_format": "%Y-%m-%d",
            "timezone": "UTC",
            "theme": "dark",
            "max_display_messages": 100,
        }

        self.agents = {
            "default_clearance": "operative",
            "clearance_levels": ["operative", "field_agent", "command", "admin"],
            "require_auth": True,
            "session_keys": True,
        }

        self.protocols = {
            "version": "1.0",
            "compression": True,
            "checksum_verification": True,
            "message_acknowledgment": True,
        }

    def get_network_config(self):
        return self.network

    def get_security_config(self):
        return self.security

    def get_operations_config(self):
        return self.operations

    def get_ui_config(self):
        return self.ui

    def get_agents_config(self):
        return self.agents

    def get_protocols_config(self):
        return self.protocols

    def update_config(self, section: str, key: str, value):
        if hasattr(self, section):
            getattr(self, section)[key] = value
            return True
        return False

    def save_config(self, filepath: str = "../Data/mission_config.json"):
        config_data = {
            "network": self.network,
            "security": self.security,
            "operations": self.operations,
            "ui": self.ui,
            "agents": self.agents,
            "protocols": self.protocols,
            "last_updated": datetime.now().isoformat(),
        }

        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w") as f:
            json.dump(config_data, f, indent=2)

    def load_from_file(self, filepath: str = "../Data/mission_config.json"):
        if os.path.exists(filepath):
            try:
                with open(filepath, "r") as f:
                    config_data = json.load(f)

                for section, values in config_data.items():
                    if hasattr(self, section) and isinstance(values, dict):
                        getattr(self, section).update(values)
                return True
            except Exception as e:
                print(f"Error loading config: {e}")
        return False


config = MissionConfig()

HOST = config.network["host"]
PORT = config.network["port"]
SERVER_IP = config.network["server_ip"]
MAX_CONNECTIONS = config.network["max_connections"]
TIMEOUT = config.network["timeout"]

ENCRYPTION_ENABLED = config.security["encryption_enabled"]
SESSION_TIMEOUT = config.security["session_timeout"]
MAX_FAILED_ATTEMPTS = config.security["max_failed_attempts"]

MAX_MESSAGE_DISPLAY = config.ui["max_display_messages"]
TIMESTAMP_FORMAT = config.ui["timestamp_format"]

# Enhanced Color Scheme for Better UI
YOUR_MESSAGE_COLOR = "bright_green"
THEIR_MESSAGE_COLOR = "bright_cyan"
SYSTEM_MESSAGE_COLOR = "bright_yellow"
ERROR_MESSAGE_COLOR = "bright_red"
TIMESTAMP_COLOR = "dim white"

# Additional color definitions for enhanced UI
CLEARANCE_COLORS = {
    "admin": "bright_magenta",
    "field_agent": "bright_blue",
    "operative": "bright_yellow",
}

PRIORITY_COLORS = {"normal": "white", "high": "yellow", "critical": "red"}

STATUS_COLORS = {"online": "bright_green", "offline": "bright_red", "idle": "yellow"}

UI_ACCENT_COLORS = {
    "primary": "bright_blue",
    "secondary": "bright_cyan",
    "success": "bright_green",
    "warning": "bright_yellow",
    "error": "bright_red",
    "info": "bright_white",
}

# Dual-layer encryption indicators
DUAL_LAYER_ENCRYPTION = True
ENCRYPTION_LAYERS = {
    "level_1": "AES-256 (Fernet)",
    "level_2": "XOR Obfuscation",
    "level_3": "Base64 Encoding",
    "total": "Triple-Layer Protection",
}
