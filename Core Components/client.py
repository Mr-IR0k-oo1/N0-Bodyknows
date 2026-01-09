"""
Operative Terminal - Secure Communication Client
N0-Bodyknows Operations Network
"""

import socket
import threading
import sys
import os
import argparse
import base64
import json
import re
import getpass
from datetime import datetime
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text
from rich.markdown import Markdown
from rich.table import Table

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
from crypto_utils import CryptoEngine
from history_manager import SessionHistoryManager


class OperativeTerminal:
    """Operative Terminal client for secure communications"""

    def __init__(self, server_ip: str, agent_id: str):
        self.console = Console()
        self.crypto = CryptoEngine()
        self.messages = []
        self.running = False
        self.socket = None
        self.agent_id = agent_id
        self.clearance = None
        self.session_key = None
        self.screen_lock = threading.Lock()
        self.server_ip = server_ip
        self.connected_agents = []
        self.typing_agents = set()
        self.history_manager = SessionHistoryManager("../Data/sessions/client")
        self.load_history()

    def add_message(
        self, sender: str, message: str, color: str, priority: str = "normal"
    ):
        """Add a message to the display"""
        message_data = {
            "time": datetime.now(),
            "sender": sender,
            "message": message,
            "color": color,
            "priority": priority,
        }
        self.messages.append(message_data)

        # Add to history manager
        message_copy = message_data.copy()
        message_copy["time"] = message_copy["time"].isoformat()
        self.history_manager.add_message(message_copy)

        # Keep only last N messages in memory
        if len(self.messages) > config.MAX_MESSAGE_DISPLAY:
            self.messages.pop(0)

        # Redraw screen
        self.draw_screen()

    def draw_screen(self):
        """Draw the entire screen"""
        with self.screen_lock:
            # Clear screen
            os.system("clear" if os.name != "nt" else "cls")

            # Enhanced ASCII Art Logo for Client
            logo_lines = [
                "┌─────────────────────────────────────────────────────────────────────────┐",
                "│                                                                         │",
                "│                    ╔═══════════════════════════╗                        │",
                "│                    ║   N0-BODYKNOWS NETWORK    ║                        │",
                "│                    ║  OPERATIVE TERMINAL v2.0  ║                        │",
                "│                    ║  SECURE FIELD COMMS       ║                        │",
                "│                    ╚═══════════════════════════╝                        │",
                "|                                                                         |",
                "└─────────────────────────────────────────────────────────────────────────┘",
            ]
            for line in logo_lines:
                self.console.print(line, style="bold bright_green", justify="center")

            # Enhanced separator with pattern
            self.console.print(
                "[bold blue]╠" + "═" * (self.console.size.width - 2) + "╣[/bold blue]"
            )

            # Enhanced Agent Status Panel
            agent_table = Table(show_header=False, box=None, padding=(0, 1))
            agent_table.add_column("📋 Field", style="bold cyan", width=15)
            agent_table.add_column("💎 Value", style="bold green", width=25)

            # Add clearance level indicator
            clearance_icon = ""
            clearance_color = "white"
            if self.clearance == "admin":
                clearance_icon = "👑 "
                clearance_color = "bright_magenta"
            elif self.clearance == "field_agent":
                clearance_icon = "🎯 "
                clearance_color = "bright_blue"
            elif self.clearance == "operative":
                clearance_icon = "⚡ "
                clearance_color = "bright_yellow"

            agent_table.add_row(
                "👤 Agent ID:", f"[bold white]{self.agent_id}[/bold white]"
            )
            agent_table.add_row(
                "🔐 Clearance:",
                f"[{clearance_color}]{clearance_icon}{self.clearance or 'Unknown'}[/{clearance_color}]",
            )
            agent_table.add_row(
                "📡 Status:",
                "[bold green]🟢 CONNECTED[/bold green]"
                if self.running
                else "[bold red]🔴 DISCONNECTED[/bold red]",
            )
            agent_table.add_row(
                "🌐 Server:", f"[bold cyan]{self.server_ip}:{config.PORT}[/bold cyan]"
            )

            agent_panel = Panel(
                agent_table,
                title="[bold bright_blue]🔰 AGENT STATUS[/bold bright_blue]",
                border_style="bright_blue",
                padding=(1, 2),
            )
            self.console.print(agent_panel)

            # Separator
            self.console.print("[dim]─" * self.console.size.width + "[/dim]")

            # Enhanced Message Display
            messages_group = Group()
            now = datetime.now()

            for i, msg in enumerate(self.messages[-15:]):  # Show last 15 messages
                delta = now - msg["time"]
                if delta.seconds < 60:
                    time_str = f"{delta.seconds}s ago"
                elif delta.seconds < 3600:
                    time_str = f"{delta.seconds // 60}m ago"
                elif delta.days == 0:
                    time_str = msg["time"].strftime("%H:%M:%S")
                else:
                    time_str = msg["time"].strftime("%m/%d %H:%M")

                # Create enhanced message container
                message_container = Table(show_header=False, box=None, padding=(0, 1))
                message_container.add_column("Time", style="dim white", width=10)
                message_container.add_column("Sender", style="bold", width=18)
                message_container.add_column("Message", style="white")

                # Enhanced sender styling
                sender_style = "bold bright_cyan"
                sender_icon = ""

                if msg["sender"] == "YOU":
                    sender_style = "bold bright_green"
                    sender_icon = "📤 "
                elif msg["sender"] == "SYSTEM":
                    sender_style = "bold yellow"
                    sender_icon = "⚙️ "
                elif msg["sender"].startswith("Secure to "):
                    sender_style = "bold bright_magenta"
                    sender_icon = "🔒 "
                elif msg["priority"] == "critical":
                    sender_style = "bold red"
                    sender_icon = "🔴 "
                elif msg["priority"] == "high":
                    sender_style = "bold yellow"
                    sender_icon = "🟡 "

                # Format message content
                content = msg["message"]
                if "**" in content or "*" in content or "`" in content:
                    # Handle markdown-like formatting
                    content = (
                        content.replace("**", "[bold]")
                        .replace("*", "[italic]")
                        .replace("`", "[dim white]")
                    )

                message_container.add_row(
                    f"[dim]{time_str}[/dim]",
                    f"{sender_icon}[{sender_style}]{msg['sender']}[/{sender_style}]",
                    f"[{msg['color']}]{content}[/{msg['color']}]",
                )

                messages_group.renderables.append(message_container)

            # Enhanced Display Panel
            panel = Panel(
                messages_group,
                title="[bold bright_green]🔐 SECURE COMMUNICATIONS[/bold bright_green]",
                border_style="bright_green",
                height=18,
                padding=(1, 2),
            )
            self.console.print(panel)

            # Enhanced Connected Agents Panel
            if self.connected_agents:
                agents_table = Table(show_header=True, box=None, padding=(0, 1))
                agents_table.add_column("👤 Agent ID", style="bold cyan", width=20)
                agents_table.add_column("📊 Status", style="bold green", width=15)
                agents_table.add_column("🔐 Clearance", style="bold yellow", width=15)

                for agent in self.connected_agents:
                    if agent != self.agent_id:
                        # Simulate getting clearance info (in real implementation, this would come from server)
                        clearance = "field_agent" if agent == "alpha" else "operative"
                        clearance_icon = "🎯 " if clearance == "field_agent" else "⚡ "

                        agents_table.add_row(
                            f"[bold cyan]{agent}[/bold cyan]",
                            "[bold green]🟢 Online[/bold green]",
                            f"[bold yellow]{clearance_icon}{clearance}[/bold yellow]",
                        )

                if agents_table.row_count > 0:
                    agents_panel = Panel(
                        agents_table,
                        title="[bold bright_cyan]👥 CONNECTED AGENTS[/bold bright_cyan]",
                        border_style="bright_cyan",
                        padding=(1, 2),
                    )
                    self.console.print(agents_panel)

            # Enhanced separator with pattern
            self.console.print(
                "[bold blue]╠" + "═" * (self.console.size.width - 2) + "╣[/bold blue]"
            )

            # Enhanced Input Prompt
            self.console.print(
                "[bold bright_green]💬 MESSAGE:[/bold bright_green] ", end=""
            )

    def load_history(self):
        """Load message history from session files"""
        try:
            # Load all sessions
            sessions = self.history_manager.get_session_list()

            # Load messages from all sessions
            for session in sessions:
                session_messages = self.history_manager.load_session(
                    session["session_id"]
                )
                for msg in session_messages:
                    self.messages.append(
                        {
                            "time": datetime.fromisoformat(msg["time"]),
                            "sender": msg["sender"],
                            "message": msg["message"],
                            "color": msg["color"],
                            "priority": msg.get("priority", "normal"),
                        }
                    )
        except Exception as e:
            pass

    def save_history(self):
        """Save message history to session files"""
        try:
            # Add new messages to current session
            new_messages = self.messages[-100:]  # Get recent messages

            for msg in new_messages:
                # Convert datetime to string for JSON serialization
                msg_copy = msg.copy()
                msg_copy["time"] = msg_copy["time"].isoformat()
                self.history_manager.add_message(msg_copy)

            # Save the current session
            self.history_manager.save_current_session()

            # Clean up old sessions (keep last 10)
            self.history_manager.cleanup_old_sessions(max_sessions=10)
        except Exception as e:
            pass

    def authenticate_with_server(self):
        """Authenticate with the Command Center"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self.console.print(
                Panel(
                    f"[yellow]Establishing secure connection to {self.server_ip}:{config.PORT}...[/yellow]",
                    title="⚡ N0-BODYKNOWS NETWORK",
                    border_style="green",
                )
            )

            self.socket.connect((self.server_ip, config.PORT))

            # Get password securely
            password = getpass.getpass(
                f"[cyan]Enter password for agent {self.agent_id}: [/cyan]"
            )

            # Send authentication data
            auth_data = {"agent_id": self.agent_id, "password": password}
            auth_data_json = json.dumps(auth_data)
            message_length = len(auth_data_json).to_bytes(4, 'big')
            self.socket.send(message_length + auth_data_json.encode("utf-8"))

            # Receive authentication response
            message_length_bytes = self.socket.recv(4)
            if not message_length_bytes:
                self.console.print(
                    f"[red]Authentication failed: No response from server[/red]"
                )
                self.socket.close()
                return False
            message_length = int.from_bytes(message_length_bytes, 'big')

            response_data = b""
            while len(response_data) < message_length:
                chunk = self.socket.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            
            response_data = response_data.decode('utf-8')
            response = json.loads(response_data)

            if response["status"] == "success":
                self.clearance = response["clearance"]
                self.session_key = response["session_key"]

                self.add_message(
                    "SYSTEM",
                    f"Authenticated as {self.agent_id} ({self.clearance}) - Connected to Command Center",
                    config.SYSTEM_MESSAGE_COLOR,
                    "high",
                )
                self.running = True
                return True
            else:
                self.console.print(
                    f"[red]Authentication failed: {response.get('message', 'Unknown error')}[/red]"
                )
                self.socket.close()
                return False

        except Exception as e:
            self.console.print(f"[red]Connection failed: {e}[/red]")
            self.console.print(
                f"[yellow]Verify Command Center is running and network is accessible.[/yellow]"
            )
            return False

    def receive_messages(self):
        """Thread function to receive messages"""
        while self.running:
            try:
                # Receive message length
                message_length_bytes = self.socket.recv(4)
                if not message_length_bytes:
                    self.add_message(
                        "SYSTEM",
                        "Command Center disconnected",
                        config.ERROR_MESSAGE_COLOR,
                        "critical",
                    )
                    self.running = False
                    break
                message_length = int.from_bytes(message_length_bytes, 'big')

                # Receive the full message
                encrypted_data = b""
                while len(encrypted_data) < message_length:
                    chunk = self.socket.recv(4096)
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                encrypted_data = encrypted_data.decode('utf-8')

                if not encrypted_data:
                    self.add_message(
                        "SYSTEM",
                        "Command Center disconnected",
                        config.ERROR_MESSAGE_COLOR,
                        "critical",
                    )
                    self.running = False
                    break

                # Decrypt message
                try:
                    message_data = json.loads(encrypted_data)
                    message = self.crypto.decrypt_message(message_data)
                except:
                    continue

                # Parse message
                if message.startswith("SYSTEM: "):
                    system_msg = message[8:]
                    self.add_message("SYSTEM", system_msg, config.SYSTEM_MESSAGE_COLOR)
                elif message.startswith("COMMAND: "):
                    command_msg = message[9:]
                    self.add_message(
                        "COMMAND", command_msg, config.YOUR_MESSAGE_COLOR, "high"
                    )
                elif message.startswith("SECURE from "):
                    # Parse secure message
                    parts = message[12:].split(": ", 1)
                    if len(parts) == 2:
                        sender, secure_msg = parts
                        self.add_message(
                            sender, secure_msg, config.THEIR_MESSAGE_COLOR, "high"
                        )
                elif message.startswith("SECURE to "):
                    # Confirmation of sent secure message
                    parts = message[10:].split(": ", 1)
                    if len(parts) == 2:
                        target, secure_msg = parts
                        self.add_message(
                            f"Secure to {target}",
                            secure_msg,
                            config.YOUR_MESSAGE_COLOR,
                            "high",
                        )
                else:
                    # Regular message
                    if ": " in message:
                        sender, msg_content = message.split(": ", 1)
                        self.add_message(
                            sender, msg_content, config.THEIR_MESSAGE_COLOR
                        )
                    else:
                        self.add_message("UNKNOWN", message, config.THEIR_MESSAGE_COLOR)

                # Optional: Beep sound
                print("\a", end="", flush=True)

            except Exception as e:
                if self.running:
                    self.add_message(
                        "SYSTEM",
                        f"Error receiving: {str(e)}",
                        config.ERROR_MESSAGE_COLOR,
                    )
                break

    def send_message(self, message):
        """Send a single message"""
        try:
            if message.strip():
                # Encrypt and send
                encrypted = self.crypto.encrypt_message(message)
                encrypted_json = json.dumps(encrypted)
                message_length = len(encrypted_json).to_bytes(4, 'big')
                self.socket.send(message_length + encrypted_json.encode('utf-8'))

                # Add to display
                self.add_message("YOU", message, config.YOUR_MESSAGE_COLOR)

        except Exception as e:
            self.add_message(
                "SYSTEM", f"Error sending: {str(e)}", config.ERROR_MESSAGE_COLOR
            )

    def send_secure_message(self, target_agent_id: str, message: str):
        """Send a secure message to a specific agent"""
        try:
            secure_command = f"/secure {target_agent_id} {message}"
            encrypted = self.crypto.encrypt_message(secure_command)
            encrypted_json = json.dumps(encrypted)
            message_length = len(encrypted_json).to_bytes(4, 'big')
            self.socket.send(message_length + encrypted_json.encode('utf-8'))

            self.add_message(
                f"Secure to {target_agent_id}",
                message,
                config.YOUR_MESSAGE_COLOR,
                "high",
            )
        except Exception as e:
            self.add_message(
                "SYSTEM",
                f"Error sending secure message: {str(e)}",
                config.ERROR_MESSAGE_COLOR,
            )

    def send_priority_message(self, priority: str, message: str):
        """Send a priority message"""
        try:
            priority_command = f"/priority {priority} {message}"
            encrypted = self.crypto.encrypt_message(priority_command)
            encrypted_json = json.dumps(encrypted)
            message_length = len(encrypted_json).to_bytes(4, 'big')
            self.socket.send(message_length + encrypted_json.encode('utf-8'))

            self.add_message(
                "YOU",
                f"[{priority.upper()}] {message}",
                config.YOUR_MESSAGE_COLOR,
                priority,
            )
        except Exception as e:
            self.add_message(
                "SYSTEM",
                f"Error sending priority message: {str(e)}",
                config.ERROR_MESSAGE_COLOR,
            )

    def search_messages(self, keyword):
        """Search messages containing keyword"""
        matches = []
        for msg in self.messages:
            if (
                keyword.lower() in msg["message"].lower()
                or keyword.lower() in msg["sender"].lower()
            ):
                matches.append(msg)
        if matches:
            self.add_message(
                "SYSTEM",
                f"Search results for '{keyword}':",
                config.SYSTEM_MESSAGE_COLOR,
            )
            for match in matches[-10:]:  # Show last 10 matches
                # Highlight keyword in message
                highlighted_message = re.sub(
                    f"({re.escape(keyword)})",
                    r"[bold red]\1[/bold red]",
                    match["message"],
                    flags=re.IGNORECASE,
                )
                self.add_message(
                    f"[{match['time'].strftime('%H:%M:%S')}] {match['sender']}",
                    highlighted_message,
                    match["color"],
                )
        else:
            self.add_message(
                "SYSTEM",
                f"No messages found for '{keyword}'",
                config.SYSTEM_MESSAGE_COLOR,
            )

    def run(self):
        """Main run loop"""
        if not self.authenticate_with_server():
            return

        # Start receiver thread
        receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        receive_thread.start()

        # Initial screen draw
        self.add_message(
            "SYSTEM",
            "Operative Terminal active! Type messages and press Enter. Type /quit to exit.",
            config.SYSTEM_MESSAGE_COLOR,
        )

        # Main input loop
        while self.running:
            try:
                message = input()

                if message.lower() == "/quit":
                    self.running = False
                    break
                elif message.startswith("/secure "):
                    # Secure message: /secure agent_id message
                    parts = message[8:].split(" ", 1)
                    if len(parts) == 2:
                        target_agent_id, secure_message = parts
                        self.send_secure_message(target_agent_id, secure_message)
                    else:
                        self.add_message(
                            "SYSTEM",
                            "Usage: /secure <agent_id> <message>",
                            config.ERROR_MESSAGE_COLOR,
                        )
                elif message.startswith("/priority "):
                    # Priority message: /priority high|critical message
                    parts = message[10:].split(" ", 1)
                    if len(parts) == 2:
                        priority, priority_message = parts
                        if priority in ["high", "critical"]:
                            self.send_priority_message(priority, priority_message)
                        else:
                            self.add_message(
                                "SYSTEM",
                                "Invalid priority. Use: high, critical",
                                config.ERROR_MESSAGE_COLOR,
                            )
                    else:
                        self.add_message(
                            "SYSTEM",
                            "Usage: /priority <high|critical> <message>",
                            config.ERROR_MESSAGE_COLOR,
                        )
                elif message.startswith("/search "):
                    keyword = message[8:]
                    self.search_messages(keyword)
                elif message.lower() == "/clear":
                    self.messages = []
                    self.draw_screen()
                elif message.lower() == "/help":
                    help_panel = Panel(
                        """[bold bright_cyan]🔹 Available Commands:[/bold bright_cyan]

[bold green]/help[/bold green] - Show this help menu
[bold green]/quit[/bold green] - Exit Operative Terminal  
[bold green]/clear[/bold green] - Clear message history
[bold green]/search[/bold green] <keyword> - Search messages
[bold green]/secure[/bold green] <agent_id> <message> - Send 🔒 secure message
[bold green]/priority[/bold green] <high|critical> <message> - Send 🚨 priority message
[bold green]/status[/bold green] - Show connection status

[bold yellow]💡 Tips:[/bold yellow]
• Use [bold cyan]/secure[/bold cyan] for private encrypted messages
• Use [bold red]/priority critical[/bold red] for urgent communications
• Messages are automatically encrypted end-to-end
• Your clearance level determines available features""",
                        title="[bold bright_blue]❓ HELP & COMMANDS[/bold bright_blue]",
                        border_style="bright_blue",
                        padding=(1, 2),
                    )
                    self.console.print(help_panel)
                elif message.lower() == "/status":
                    status_info = f"""
Connection Status:
- Agent ID: {self.agent_id}
- Clearance: {self.clearance}
- Server: {self.server_ip}:{config.PORT}
- Status: {"Connected" if self.running else "Disconnected"}
- Session: {"Active" if self.session_key else "None"}
"""
                    self.add_message(
                        "SYSTEM", status_info.strip(), config.SYSTEM_MESSAGE_COLOR
                    )
                else:
                    self.send_message(message)

            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                if self.running:
                    self.add_message(
                        "SYSTEM", f"Input error: {str(e)}", config.ERROR_MESSAGE_COLOR
                    )

        # Cleanup
        self.cleanup()

    def cleanup(self):
        """Clean up resources"""
        self.save_history()
        self.running = False
        if self.socket:
            self.socket.close()
        self.console.print("\n[yellow]Operative Terminal disconnected.[/yellow]")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="N0-BODYKNOWS Operative Terminal")
    parser.add_argument(
        "--host",
        type=str,
        default=config.SERVER_IP,
        help=f"Command Center IP address (default: {config.SERVER_IP})",
    )
    parser.add_argument(
        "--agent-id", type=str, required=True, help="Your agent ID for authentication"
    )
    args = parser.parse_args()

    terminal = OperativeTerminal(server_ip=args.host, agent_id=args.agent_id)
    try:
        terminal.run()
    except KeyboardInterrupt:
        terminal.cleanup()
        print("\nOperative Terminal stopped by user.")


if __name__ == "__main__":
    main()
