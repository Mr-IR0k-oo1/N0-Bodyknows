"""
Command Center - Secure Communication Server
N0-Bodyknows Operations Network
"""

import socket
import threading
import sys
import os
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text
from rich.markdown import Markdown
from rich.table import Table

import sys
import os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config
from history_manager import SessionHistoryManager
from crypto_utils import CryptoEngine


class CommandCenter:
    """Command Center server for secure communications"""

    def __init__(self):
        self.console = Console()
        self.crypto = CryptoEngine()
        self.messages = []
        self.running = False
        self.clients = []  # list of {'socket': socket, 'agent_id': str, 'clearance': str, 'last_seen': datetime}
        self.offline_messages = defaultdict(list)
        self.server_socket = None
        self.agent_id = "COMMAND"
        self.screen_lock = threading.Lock()
        self.sessions = {}  # agent_id: {'session_key': str, 'expires': datetime}
        self.history_manager = SessionHistoryManager("../Data/sessions/server")
        self.load_history()
        self.load_agent_database()

    def load_agent_database(self):
        """Load agent credentials and clearances"""
        self.agent_db = {}
        db_file = "../Data/agent_database.json"
        if os.path.exists(db_file):
            try:
                with open(db_file, "r") as f:
                    self.agent_db = json.load(f)
            except:
                pass
        else:
            # Create default agent database
            self.agent_db = {
                "admin": {
                    "password_hash": self.crypto.hash_password("admin123"),
                    "clearance": "admin",
                    "active": True,
                },
                "alpha": {
                    "password_hash": self.crypto.hash_password("alpha123"),
                    "clearance": "field_agent",
                    "active": True,
                },
                "bravo": {
                    "password_hash": self.crypto.hash_password("bravo123"),
                    "clearance": "operative",
                    "active": True,
                },
            }
            self.save_agent_database()

    def save_agent_database(self):
        """Save agent database"""
        db_file = "../Data/agent_database.json"
        os.makedirs(os.path.dirname(db_file), exist_ok=True)
        with open(db_file, "w") as f:
            json.dump(self.agent_db, f, indent=2)

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

            # Enhanced ASCII Art Logo
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
                self.console.print(line, style="bold bright_cyan", justify="center")

            # Enhanced separator with pattern
            self.console.print(
                "[bold blue]╠" + "═" * (self.console.size.width - 2) + "╣[/bold blue]"
            )

            # Enhanced Status Panel with better styling
            status_table = Table(show_header=False, box=None, padding=(0, 1))
            status_table.add_column("Metric", style="bold cyan", width=20)
            status_table.add_column("Value", style="bold green", width=15)

            active_agents = len(
                [c for c in self.clients if self.is_session_valid(c["agent_id"])]
            )
            total_connections = len(self.clients)

            # Add status indicators with colors
            status_table.add_row(
                "🔌 Active Agents:", f"[bold green]{active_agents}[/bold green]"
            )
            status_table.add_row(
                "🌐 Total Connections:",
                f"[bold yellow]{total_connections}[/bold yellow]",
            )
            status_table.add_row(
                "⚡ Server Status:",
                "[bold green]● ONLINE[/bold green]"
                if self.running
                else "[bold red]● OFFLINE[/bold red]",
            )
            status_table.add_row(
                "⏱️  Uptime:", f"[bold white]{self.get_uptime()}[/bold white]"
            )

            status_panel = Panel(
                status_table,
                title="[bold blue]📊 SYSTEM STATUS[/bold blue]",
                border_style="bright_blue",
                padding=(1, 2),
            )
            self.console.print(status_panel)

            # Enhanced Message Display
            messages_group = Group()
            now = datetime.now()

            # Create enhanced message formatting
            for i, msg in enumerate(self.messages[-20:]):  # Show last 20 messages
                delta = now - msg["time"]
                if delta.seconds < 60:
                    time_str = f"{delta.seconds}s ago"
                elif delta.seconds < 3600:
                    time_str = f"{delta.seconds // 60}m ago"
                elif delta.days == 0:
                    time_str = msg["time"].strftime("%H:%M:%S")
                else:
                    time_str = msg["time"].strftime("%m/%d %H:%M")

                # Create message container with better styling
                message_container = Table(show_header=False, box=None, padding=(0, 1))
                message_container.add_column("Time", style="dim white", width=12)
                message_container.add_column("Sender", style="bold", width=15)
                message_container.add_column("Content", style="white")

                # Enhanced sender styling based on type
                sender_style = "bold bright_cyan"
                sender_prefix = ""

                if msg["sender"] == "SYSTEM":
                    sender_style = "bold yellow"
                    sender_prefix = "⚙️ "
                elif msg["sender"] == "COMMAND":
                    sender_style = "bold bright_magenta"
                    sender_prefix = "📢 "
                elif msg["priority"] == "critical":
                    sender_style = "bold red"
                    sender_prefix = "🔴 "
                elif msg["priority"] == "high":
                    sender_style = "bold yellow"
                    sender_prefix = "🟡 "

                # Format message content with better styling
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
                    f"{sender_prefix}[{sender_style}]{msg['sender']}[/{sender_style}]",
                    f"[{msg['color']}]{content}[/{msg['color']}]",
                )

                messages_group.renderables.append(message_container)

            # Enhanced Display Panel
            panel = Panel(
                messages_group,
                title="[bold bright_blue]📡 COMMUNICATIONS LOG[/bold bright_blue]",
                border_style="bright_blue",
                height=20,
                padding=(1, 2),
            )
            self.console.print(panel)

            # Enhanced Active Agents Panel
            if self.clients:
                agents_table = Table(show_header=True, box=None, padding=(0, 1))
                agents_table.add_column("👤 Agent ID", style="bold cyan", width=15)
                agents_table.add_column("🔐 Clearance", style="bold green", width=12)
                agents_table.add_column("📊 Status", style="bold yellow", width=10)
                agents_table.add_column("⏰ Last Seen", style="dim white", width=12)

                for client in self.clients:
                    is_valid = self.is_session_valid(client["agent_id"])
                    status = "🟢 Active" if is_valid else "🔴 Idle"
                    status_style = "bold green" if is_valid else "bold red"
                    last_seen = client.get("last_seen", datetime.now()).strftime(
                        "%H:%M:%S"
                    )

                    # Add clearance level indicators
                    clearance_icon = ""
                    if client["clearance"] == "admin":
                        clearance_icon = "👑 "
                    elif client["clearance"] == "field_agent":
                        clearance_icon = "🎯 "
                    elif client["clearance"] == "operative":
                        clearance_icon = "⚡ "

                    agents_table.add_row(
                        f"[bold cyan]{client['agent_id']}[/bold cyan]",
                        f"[bold green]{clearance_icon}{client['clearance']}[/bold green]",
                        f"[{status_style}]{status}[/{status_style}]",
                        f"[dim white]{last_seen}[/dim white]",
                    )

                agents_panel = Panel(
                    agents_table,
                    title="[bold bright_green]👥 ACTIVE AGENTS[/bold bright_green]",
                    border_style="bright_green",
                    padding=(1, 2),
                )
                self.console.print(agents_panel)

            # Enhanced separator with pattern
            self.console.print(
                "[bold blue]╠" + "═" * (self.console.size.width - 2) + "╣[/bold blue]"
            )

            # Enhanced Input Prompt
            self.console.print(
                "[bold bright_green]🎯 COMMAND:[/bold bright_green] ", end=""
            )

    def get_uptime(self):
        """Calculate server uptime"""
        if hasattr(self, "start_time"):
            uptime = datetime.now() - self.start_time
            hours, remainder = divmod(uptime.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            return f"{uptime.days}d {hours}h {minutes}m"
        return "00:00:00"

    def is_session_valid(self, agent_id: str) -> bool:
        """Check if agent session is still valid"""
        if agent_id in self.sessions:
            session = self.sessions[agent_id]
            return datetime.now() < session["expires"]
        return False

    def create_session(self, agent_id: str) -> str:
        """Create a new session for an agent"""
        session_key = self.crypto.generate_session_key()
        expires = datetime.now() + timedelta(seconds=config.SESSION_TIMEOUT)
        self.sessions[agent_id] = {"session_key": session_key, "expires": expires}
        return session_key

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

    def start_server(self):
        """Start the server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((config.HOST, config.PORT))
            self.server_socket.listen(config.MAX_CONNECTIONS)
            self.start_time = datetime.now()

            self.console.print(
                Panel(
                    f"[green]Command Center started on {config.HOST}:{config.PORT}[/green]\n"
                    f"[yellow]Awaiting agent connections...[/yellow]",
                    title="⚡ N0-BODYKNOWS NETWORK",
                    border_style="cyan",
                )
            )

            self.running = True
            return True

        except Exception as e:
            self.console.print(f"[red]Error starting Command Center: {e}[/red]")
            return False

    def authenticate_agent(self, agent_id: str, password: str) -> dict:
        """Authenticate an agent"""
        if agent_id in self.agent_db:
            agent_data = self.agent_db[agent_id]
            if agent_data["active"] and self.crypto.verify_password(
                password, agent_data["password_hash"]
            ):
                return {
                    "authenticated": True,
                    "clearance": agent_data["clearance"],
                    "session_key": self.create_session(agent_id),
                }
        return {"authenticated": False}

    def accept_connections(self):
        """Thread to accept new agent connections"""
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()

                # Receive message length
                message_length_bytes = client_socket.recv(4)
                if not message_length_bytes:
                    client_socket.close()
                    continue
                message_length = int.from_bytes(message_length_bytes, 'big')

                # Receive the full message
                auth_data = b""
                while len(auth_data) < message_length:
                    chunk = client_socket.recv(4096)
                    if not chunk:
                        break
                    auth_data += chunk
                
                auth_data = auth_data.decode('utf-8')


                if not auth_data:
                    client_socket.close()
                    continue

                try:
                    auth_info = json.loads(auth_data)
                    agent_id = auth_info["agent_id"]
                    password = auth_info["password"]

                    auth_result = self.authenticate_agent(agent_id, password)

                    if auth_result["authenticated"]:
                        client_info = {
                            "socket": client_socket,
                            "agent_id": agent_id,
                            "clearance": auth_result["clearance"],
                            "address": address,
                            "last_seen": datetime.now(),
                        }
                        self.clients.append(client_info)

                        # Send authentication success
                        response = {
                            "status": "success",
                            "session_key": auth_result["session_key"],
                            "clearance": auth_result["clearance"],
                        }
                        response_json = json.dumps(response)
                        message_length = len(response_json).to_bytes(4, 'big')
                        client_socket.send(message_length + response_json.encode("utf-8"))

                        self.add_message(
                            "SYSTEM",
                            f"Agent {agent_id} ({auth_result['clearance']}) connected from {address[0]}:{address[1]}",
                            config.SYSTEM_MESSAGE_COLOR,
                            "high",
                        )

                        # Send offline messages
                        if agent_id in self.offline_messages:
                            for msg in self.offline_messages[agent_id]:
                                try:
                                    encrypted = self.crypto.encrypt_message(msg)
                                    encrypted_json = json.dumps(encrypted)
                                    message_length = len(encrypted_json).to_bytes(4, 'big')
                                    client_socket.send(message_length + encrypted_json.encode("utf-8"))
                                except:
                                    pass
                            del self.offline_messages[agent_id]

                        # Start thread for this agent
                        client_thread = threading.Thread(
                            target=self.handle_agent, args=(client_info,), daemon=True
                        )
                        client_info["thread"] = client_thread
                        client_thread.start()
                    else:
                        # Send authentication failure
                        response = {
                            "status": "failed",
                            "message": "Invalid credentials",
                        }
                        response_json = json.dumps(response)
                        message_length = len(response_json).to_bytes(4, 'big')
                        client_socket.send(message_length + response_json.encode("utf-8"))
                        client_socket.close()

                except json.JSONDecodeError:
                    client_socket.close()
                    continue

            except Exception as e:
                if self.running:
                    self.console.print(f"[red]Error accepting connection: {e}[/red]")
                break

    def broadcast_message(
        self, message, sender_agent_id, exclude_socket=None, priority="normal"
    ):
        """Broadcast message to all agents except sender"""
        for client in self.clients:
            # Check if this client is the sender by comparing sockets or agent IDs
            is_sender = False
            if exclude_socket is not None:
                try:
                    # Try comparing socket file descriptors (more reliable)
                    is_sender = client["socket"].fileno() == exclude_socket.fileno()
                except:
                    # Fallback to agent ID comparison
                    is_sender = client["agent_id"] == sender_agent_id

            if not is_sender and self.is_session_valid(client["agent_id"]):
                try:
                    encrypted = self.crypto.encrypt_message(message)
                    encrypted_json = json.dumps(encrypted)
                    message_length = len(encrypted_json).to_bytes(4, 'big')
                    client["socket"].send(message_length + encrypted_json.encode('utf-8'))
                    print(
                        f"DEBUG: Broadcast to {client['agent_id']}: {message}"
                    )  # Debug line
                except Exception as e:
                    print(
                        f"DEBUG: Error broadcasting to {client['agent_id']}: {e}"
                    )  # Debug line
                    pass

    def send_secure_message(
        self, sender_agent_id, target_agent_id, message, sender_socket
    ):
        """Send a secure message to a specific agent"""
        target_client = None
        for client in self.clients:
            if client["agent_id"] == target_agent_id:
                target_client = client
                break

        if target_client and self.is_session_valid(target_agent_id):
            # Send to target: SECURE from sender: message
            secure_msg = f"SECURE from {sender_agent_id}: {message}"
            try:
                encrypted = self.crypto.encrypt_message(secure_msg)
                encrypted_json = json.dumps(encrypted)
                message_length = len(encrypted_json).to_bytes(4, 'big')
                target_client["socket"].send(message_length + encrypted_json.encode('utf-8'))
            except:
                pass

            # Send to sender: SECURE to target: message
            confirm_msg = f"SECURE to {target_agent_id}: {message}"
            try:
                encrypted = self.crypto.encrypt_message(confirm_msg)
                encrypted_json = json.dumps(encrypted)
                message_length = len(encrypted_json).to_bytes(4, 'big')
                sender_socket.send(message_length + encrypted_json.encode('utf-8'))
            except:
                pass

            # Add to server display
            self.add_message(
                sender_agent_id,
                f"[Secure to {target_agent_id}] {message}",
                config.THEIR_MESSAGE_COLOR,
                "high",
            )
        else:
            # Agent offline, queue message
            offline_msg = f"SECURE from {sender_agent_id}: {message}"
            self.offline_messages[target_agent_id].append(offline_msg)

            # Confirm to sender
            confirm_msg = f"Message queued for offline agent '{target_agent_id}'."
            try:
                encrypted = self.crypto.encrypt_message(f"SYSTEM: {confirm_msg}")
                encrypted_json = json.dumps(encrypted)
                message_length = len(encrypted_json).to_bytes(4, 'big')
                sender_socket.send(message_length + encrypted_json.encode('utf-8'))
            except:
                pass

    def handle_agent(self, agent_info):
        """Handle messages from a specific agent"""
        agent_socket = agent_info["socket"]
        agent_id = agent_info["agent_id"]

        while self.running:
            try:
                # Receive message length
                message_length_bytes = agent_socket.recv(4)
                if not message_length_bytes:
                    # Agent disconnected
                    self.clients.remove(agent_info)
                    self.add_message(
                        "SYSTEM",
                        f"Agent {agent_id} disconnected",
                        config.ERROR_MESSAGE_COLOR,
                        "high",
                    )
                    agent_socket.close()
                    break
                message_length = int.from_bytes(message_length_bytes, 'big')

                # Receive the full message
                encrypted_data = b""
                while len(encrypted_data) < message_length:
                    chunk = agent_socket.recv(4096)
                    if not chunk:
                        break
                    encrypted_data += chunk
                
                encrypted_data = encrypted_data.decode('utf-8')

                if not encrypted_data:
                    # Agent disconnected
                    self.clients.remove(agent_info)
                    self.add_message(
                        "SYSTEM",
                        f"Agent {agent_id} disconnected",
                        config.ERROR_MESSAGE_COLOR,
                        "high",
                    )
                    agent_socket.close()
                    break

                # Decrypt message
                try:
                    message_data = json.loads(encrypted_data)
                    message = self.crypto.decrypt_message(message_data)
                    print(
                        f"DEBUG: Received message from {agent_id}: {message}"
                    )  # Debug line
                except Exception as e:
                    print(
                        f"DEBUG: Error decrypting message from {agent_id}: {e}"
                    )  # Debug line
                    continue

                if message.startswith("/secure "):
                    # Secure message: /secure agent_id message
                    parts = message[8:].split(" ", 1)
                    if len(parts) == 2:
                        target_agent_id, secure_message = parts
                        self.send_secure_message(
                            agent_id, target_agent_id, secure_message, agent_socket
                        )
                    else:
                        # Invalid format
                        error_msg = "Invalid secure message format. Use /secure agent_id message"
                        try:
                            encrypted = self.crypto.encrypt_message(
                                f"SYSTEM: {error_msg}"
                            )
                            encrypted_json = json.dumps(encrypted)
                            message_length = len(encrypted_json).to_bytes(4, 'big')
                            agent_socket.send(message_length + encrypted_json.encode('utf-8'))
                        except:
                            pass
                elif message.startswith("/priority "):
                    # Priority message: /priority high|critical message
                    parts = message[10:].split(" ", 1)
                    if len(parts) == 2:
                        priority, priority_message = parts
                        if priority in ["high", "critical"]:
                            self.add_message(
                                agent_id,
                                priority_message,
                                config.THEIR_MESSAGE_COLOR,
                                priority,
                            )
                            self.broadcast_message(
                                f"{agent_id}: {priority_message}",
                                agent_id,
                                priority=priority,
                            )
                        else:
                            # Invalid priority
                            error_msg = "Invalid priority level. Use: high, critical"
                            try:
                                encrypted = self.crypto.encrypt_message(
                                    f"SYSTEM: {error_msg}"
                                )
                                encrypted_json = json.dumps(encrypted)
                                message_length = len(encrypted_json).to_bytes(4, 'big')
                                agent_socket.send(message_length + encrypted_json.encode('utf-8'))
                            except:
                                pass
                else:
                    # Regular message
                    self.add_message(agent_id, message, config.THEIR_MESSAGE_COLOR)
                    self.broadcast_message(
                        f"{agent_id}: {message}", agent_id, exclude_socket=agent_socket
                    )

                # Update last seen
                agent_info["last_seen"] = datetime.now()

            except Exception as e:
                if self.running:
                    if agent_info in self.clients:
                        self.clients.remove(agent_info)
                    self.add_message(
                        "SYSTEM",
                        f"Agent {agent_id} disconnected due to error: {str(e)}",
                        config.ERROR_MESSAGE_COLOR,
                        "high",
                    )
                    agent_socket.close()
                break

    def send_command(self, message):
        """Send a command to all agents"""
        try:
            if message.strip():
                # Add to display
                self.add_message("COMMAND", message, config.YOUR_MESSAGE_COLOR, "high")

                # Broadcast to all agents
                self.broadcast_message(
                    f"COMMAND: {message}", "COMMAND", priority="high"
                )

        except Exception as e:
            self.add_message(
                "SYSTEM",
                f"Error sending command: {str(e)}",
                config.ERROR_MESSAGE_COLOR,
                "critical",
            )

    def run(self):
        """Main run loop"""
        if not self.start_server():
            return

        # Start accept connections thread
        accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
        accept_thread.start()

        # Initial screen draw
        self.add_message(
            "SYSTEM",
            "Command Center operational! Type commands and press Enter. Type /quit to exit.",
            config.SYSTEM_MESSAGE_COLOR,
            "normal",
        )

        # Main input loop
        while self.running:
            try:
                command = input()

                if command.lower() == "/quit":
                    self.running = False
                    break
                elif command.lower() == "/clear":
                    self.messages = []
                    self.draw_screen()
                elif command.lower() == "/help":
                    help_panel = Panel(
                        """[bold bright_cyan]🔹 Command Center Commands:[/bold bright_cyan]

[bold green]/help[/bold green] - Show this help menu
[bold green]/quit[/bold green] - Exit Command Center
[bold green]/clear[/bold green] - Clear message history
[bold green]/agents[/bold green] - List all agents in database
[bold green]/status[/bold green] - Show detailed system status
[bold green]/wipe[/bold green] <agent_id> - Emergency wipe agent session

[bold yellow]💡 Admin Features:[/bold yellow]
• Monitor all agent communications
• Send priority commands to all agents
• Manage agent sessions and clearances
• Emergency session termination capabilities

[bold red]🚨 Emergency Commands:[/bold red]
• Use /wipe only in emergency situations
• All agent actions are logged and monitored""",
                        title="[bold bright_blue]❓ COMMAND CENTER HELP[/bold bright_blue]",
                        border_style="bright_blue",
                        padding=(1, 2),
                    )
                    self.console.print(help_panel)
                elif command.lower() == "/agents":
                    agents_list = []
                    for agent_id, data in self.agent_db.items():
                        status = (
                            "Online"
                            if any(c["agent_id"] == agent_id for c in self.clients)
                            else "Offline"
                        )
                        agents_list.append(
                            f"{agent_id} ({data['clearance']}) - {status}"
                        )

                    if agents_list:
                        self.add_message(
                            "SYSTEM",
                            "Active Agents:\n" + "\n".join(agents_list),
                            config.SYSTEM_MESSAGE_COLOR,
                        )
                    else:
                        self.add_message(
                            "SYSTEM",
                            "No agents in database",
                            config.SYSTEM_MESSAGE_COLOR,
                        )
                elif command.lower() == "/status":
                    status_info = f"""
System Status:
- Server: {"Online" if self.running else "Offline"}
- Active Connections: {len(self.clients)}
- Total Agents: {len(self.agent_db)}
- Active Sessions: {len([s for s in self.sessions.values() if datetime.now() < s["expires"]])}
- Uptime: {self.get_uptime()}
"""
                    self.add_message(
                        "SYSTEM", status_info.strip(), config.SYSTEM_MESSAGE_COLOR
                    )
                elif command.startswith("/wipe "):
                    agent_id = command[6:].strip()
                    if agent_id in self.sessions:
                        del self.sessions[agent_id]
                        self.add_message(
                            "SYSTEM",
                            f"Emergency wipe completed for agent {agent_id}",
                            config.SYSTEM_MESSAGE_COLOR,
                            "critical",
                        )
                    else:
                        self.add_message(
                            "SYSTEM",
                            f"No active session found for agent {agent_id}",
                            config.ERROR_MESSAGE_COLOR,
                        )
                else:
                    self.send_command(command)

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
        for client in self.clients:
            try:
                client["socket"].close()
            except:
                pass
        if self.server_socket:
            self.server_socket.close()
        self.console.print("\n[yellow]Command Center shut down.[/yellow]")


def main():
    """Main entry point"""
    command_center = CommandCenter()
    try:
        command_center.run()
    except KeyboardInterrupt:
        command_center.cleanup()
        print("\nCommand Center stopped by user.")


if __name__ == "__main__":
    main()
