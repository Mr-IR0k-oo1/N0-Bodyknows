#!/usr/bin/env python3

"""
Operative Terminal - Secure Communication Client
N0-Bodyknows Operations Network

Modified version that accepts password as command-line argument to avoid getpass issues
"""

import socket
import threading
import sys
import os
import argparse
import base64
import json
import re
from datetime import datetime
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text
from rich.markdown import Markdown
from rich.table import Table

# Add Core Components to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'Core Components'))

import config
from crypto_utils import CryptoEngine
from history_manager import SessionHistoryManager


class OperativeTerminal:
    """Operative Terminal client for secure communications"""

    def __init__(self, server_ip: str, agent_id: str, password: str = None):
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
        self.password = password
        self.history_manager = SessionHistoryManager("../Data/sessions/client")
        self.load_history()
    
    def add_message(self, sender: str, message: str, color: str, priority: str = "normal"):
        """Add a message to the display"""
        message_data = {
            'time': datetime.now(),
            'sender': sender,
            'message': message,
            'color': color,
            'priority': priority
        }
        self.messages.append(message_data)
        
        # Add to history manager
        message_copy = message_data.copy()
        message_copy['time'] = message_copy['time'].isoformat()
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
            os.system('clear' if os.name != 'nt' else 'cls')

            # Print logo
            logo_lines = [
                "╔══════════════════════════════════════════════════════════════╗",
                "║                    N0-BODYKNOWS NETWORK                     ║",
                "║                 OPERATIVE TERMINAL v1.0                    ║",
                "║               SECURE FIELD COMMUNICATIONS                  ║",
                "╚══════════════════════════════════════════════════════════════╝"
            ]
            for line in logo_lines:
                self.console.print(line, style="bold bright_green", justify="center")

            # Agent info panel
            agent_table = Table(show_header=False, box=None, padding=0)
            agent_table.add_column("Field", style="cyan")
            agent_table.add_column("Value", style="green")
            
            agent_table.add_row("Agent ID:", self.agent_id)
            agent_table.add_row("Clearance:", self.clearance or "Unknown")
            agent_table.add_row("Status:", "[green]CONNECTED[/green]" if self.running else "[red]DISCONNECTED[/red]")
            agent_table.add_row("Server:", f"{self.server_ip}:{config.PORT}")
            
            agent_panel = Panel(agent_table, title="Agent Status", border_style="blue")
            self.console.print(agent_panel)

            # Separator
            self.console.print("[dim]─" * self.console.size.width + "[/dim]")

            # Create message display
            messages_group = Group()
            now = datetime.now()
            for msg in self.messages[-15:]:  # Show last 15 messages
                delta = now - msg['time']
                if delta.seconds < 60:
                    time_str = f"{delta.seconds}s ago"
                elif delta.seconds < 3600:
                    time_str = f"{delta.seconds // 60}m ago"
                elif delta.days == 0:
                    time_str = msg['time'].strftime('%H:%M')
                else:
                    time_str = msg['time'].strftime('%m/%d %H:%M')
                
                header = Text()
                header.append(f"[{time_str}] ", style=config.TIMESTAMP_COLOR)
                
                # Priority indicator
                if msg['priority'] == "critical":
                    header.append("🔴 ", style="red")
                elif msg['priority'] == "high":
                    header.append("🟡 ", style="yellow")
                
                header.append(f"{msg['sender']}: ", style="bold cyan")
                
                if '**' in msg['message'] or '*' in msg['message'] or '`' in msg['message']:
                    md = Markdown(msg['message'], inline_code_theme="monokai")
                    messages_group.renderables.append(Group(header, md))
                else:
                    header.append(msg['message'], style=msg['color'])
                    messages_group.renderables.append(header)

            # Display panel
            panel = Panel(
                messages_group,
                title="Secure Communications",
                border_style="green",
                height=18,
                padding=(1, 2)
            )
            self.console.print(panel)

            # Connected agents panel
            if self.connected_agents:
                agents_table = Table(show_header=True, box=None)
                agents_table.add_column("Agent ID", style="cyan")
                agents_table.add_column("Status", style="green")
                
                for agent in self.connected_agents:
                    if agent != self.agent_id:
                        status = "Online"
                        agents_table.add_row(agent, status)
                
                if agents_table.row_count > 0:
                    agents_panel = Panel(agents_table, title="Connected Agents", border_style="green")
                    self.console.print(agents_panel)

            # Separator
            self.console.print("[dim]─" * self.console.size.width + "[/dim]")

            # Input prompt
            self.console.print("[bold green]MESSAGE:[/bold green] ", end="")

    def load_history(self):
        """Load message history from session files"""
        try:
            # Load all sessions
            sessions = self.history_manager.get_session_list()
            
            # Load messages from all sessions
            for session in sessions:
                session_messages = self.history_manager.load_session(session['session_id'])
                for msg in session_messages:
                    self.messages.append({
                        'time': datetime.fromisoformat(msg['time']),
                        'sender': msg['sender'],
                        'message': msg['message'],
                        'color': msg['color'],
                        'priority': msg.get('priority', 'normal')
                    })
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
                msg_copy['time'] = msg_copy['time'].isoformat()
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

            self.console.print(Panel(
                f"[yellow]Establishing secure connection to {self.server_ip}:{config.PORT}...[/yellow]",
                title="⚡ N0-BODYKNOWS NETWORK",
                border_style="green"
            ))

            self.socket.connect((self.server_ip, config.PORT))

            # Use provided password or prompt for it
            if self.password is None:
                import getpass
                password = getpass.getpass(f"[cyan]Enter password for agent {self.agent_id}: [/cyan]")
            else:
                password = self.password
                self.console.print(f"[yellow]Using provided password for agent {self.agent_id}[/yellow]")

            # Send authentication data
            auth_data = {
                'agent_id': self.agent_id,
                'password': password
            }
            self.socket.send(json.dumps(auth_data).encode('utf-8'))

            # Receive authentication response
            response_data = self.socket.recv(1024).decode('utf-8')
            response = json.loads(response_data)

            if response['status'] == 'success':
                self.clearance = response['clearance']
                self.session_key = response['session_key']
                
                self.add_message(
                    "SYSTEM",
                    f"Authenticated as {self.agent_id} ({self.clearance}) - Connected to Command Center",
                    config.SYSTEM_MESSAGE_COLOR,
                    "high"
                )
                self.running = True
                return True
            else:
                self.console.print(f"[red]Authentication failed: {response.get('message', 'Unknown error')}[/red]")
                self.socket.close()
                return False

        except Exception as e:
            self.console.print(f"[red]Connection failed: {e}[/red]")
            self.console.print(f"[yellow]Verify Command Center is running and network is accessible.[/yellow]")
            return False
    
    def receive_messages(self):
        """Thread function to receive messages"""
        while self.running:
            try:
                # Receive encrypted message
                encrypted_data = self.socket.recv(4096).decode('utf-8')

                if not encrypted_data:
                    self.add_message(
                        "SYSTEM",
                        "Command Center disconnected",
                        config.ERROR_MESSAGE_COLOR,
                        "critical"
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
                    self.add_message("COMMAND", command_msg, config.YOUR_MESSAGE_COLOR, "high")
                elif message.startswith("SECURE from "):
                    # Parse secure message
                    parts = message[12:].split(": ", 1)
                    if len(parts) == 2:
                        sender, secure_msg = parts
                        self.add_message(sender, secure_msg, config.THEIR_MESSAGE_COLOR, "high")
                elif message.startswith("SECURE to "):
                    # Confirmation of sent secure message
                    parts = message[10:].split(": ", 1)
                    if len(parts) == 2:
                        target, secure_msg = parts
                        self.add_message(f"Secure to {target}", secure_msg, config.YOUR_MESSAGE_COLOR, "high")
                else:
                    # Regular message
                    if ": " in message:
                        sender, msg_content = message.split(": ", 1)
                        self.add_message(sender, msg_content, config.THEIR_MESSAGE_COLOR)
                    else:
                        self.add_message("UNKNOWN", message, config.THEIR_MESSAGE_COLOR)

                # Optional: Beep sound
                print('\a', end='', flush=True)

            except Exception as e:
                if self.running:
                    self.add_message(
                        "SYSTEM",
                        f"Error receiving: {str(e)}",
                        config.ERROR_MESSAGE_COLOR
                    )
                break
    
    def send_message(self, message):
        """Send a single message"""
        try:
            if message.strip():
                # Encrypt and send
                encrypted = self.crypto.encrypt_message(message)
                self.socket.send(json.dumps(encrypted).encode('utf-8'))

                # Add to display
                self.add_message("YOU", message, config.YOUR_MESSAGE_COLOR)

        except Exception as e:
            self.add_message(
                "SYSTEM",
                f"Error sending: {str(e)}",
                config.ERROR_MESSAGE_COLOR
            )

    def send_secure_message(self, target_agent_id: str, message: str):
        """Send a secure message to a specific agent"""
        try:
            secure_command = f"/secure {target_agent_id} {message}"
            encrypted = self.crypto.encrypt_message(secure_command)
            self.socket.send(json.dumps(encrypted).encode('utf-8'))
            
            self.add_message(f"Secure to {target_agent_id}", message, config.YOUR_MESSAGE_COLOR, "high")
        except Exception as e:
            self.add_message(
                "SYSTEM",
                f"Error sending secure message: {str(e)}",
                config.ERROR_MESSAGE_COLOR
            )

    def send_priority_message(self, priority: str, message: str):
        """Send a priority message"""
        try:
            priority_command = f"/priority {priority} {message}"
            encrypted = self.crypto.encrypt_message(priority_command)
            self.socket.send(json.dumps(encrypted).encode('utf-8'))
            
            self.add_message("YOU", f"[{priority.upper()}] {message}", config.YOUR_MESSAGE_COLOR, priority)
        except Exception as e:
            self.add_message(
                "SYSTEM",
                f"Error sending priority message: {str(e)}",
                config.ERROR_MESSAGE_COLOR
            )

    def search_messages(self, keyword):
        """Search messages containing keyword"""
        matches = []
        for msg in self.messages:
            if keyword.lower() in msg['message'].lower() or keyword.lower() in msg['sender'].lower():
                matches.append(msg)
        if matches:
            self.add_message("SYSTEM", f"Search results for '{keyword}':", config.SYSTEM_MESSAGE_COLOR)
            for match in matches[-10:]:  # Show last 10 matches
                # Highlight keyword in message
                highlighted_message = re.sub(f'({re.escape(keyword)})', r'[bold red]\1[/bold red]', match['message'], flags=re.IGNORECASE)
                self.add_message(f"[{match['time'].strftime('%H:%M:%S')}] {match['sender']}", highlighted_message, match['color'])
        else:
            self.add_message("SYSTEM", f"No messages found for '{keyword}'", config.SYSTEM_MESSAGE_COLOR)
    
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
            config.SYSTEM_MESSAGE_COLOR
        )

        # Main input loop
        while self.running:
            try:
                message = input()

                if message.lower() == '/quit':
                    self.running = False
                    break
                elif message.startswith('/secure '):
                    # Secure message: /secure agent_id message
                    parts = message[8:].split(' ', 1)
                    if len(parts) == 2:
                        target_agent_id, secure_message = parts
                        self.send_secure_message(target_agent_id, secure_message)
                    else:
                        self.add_message("SYSTEM", "Usage: /secure <agent_id> <message>", config.ERROR_MESSAGE_COLOR)
                elif message.startswith('/priority '):
                    # Priority message: /priority high|critical message
                    parts = message[10:].split(' ', 1)
                    if len(parts) == 2:
                        priority, priority_message = parts
                        if priority in ['high', 'critical']:
                            self.send_priority_message(priority, priority_message)
                        else:
                            self.add_message("SYSTEM", "Invalid priority. Use: high, critical", config.ERROR_MESSAGE_COLOR)
                    else:
                        self.add_message("SYSTEM", "Usage: /priority <high|critical> <message>", config.ERROR_MESSAGE_COLOR)
                elif message.startswith('/search '):
                    keyword = message[8:]
                    self.search_messages(keyword)
                elif message.lower() == '/clear':
                    self.messages = []
                    self.draw_screen()
                elif message.lower() == '/help':
                    help_text = """
Available commands:
/help - Show this help
/quit - Exit Operative Terminal
/clear - Clear message history
/search <keyword> - Search messages
/secure <agent_id> <message> - Send secure message
/priority <high|critical> <message> - Send priority message
/status - Show connection status
"""
                    self.add_message("SYSTEM", help_text.strip(), config.SYSTEM_MESSAGE_COLOR)
                elif message.lower() == '/status':
                    status_info = f"""
Connection Status:
- Agent ID: {self.agent_id}
- Clearance: {self.clearance}
- Server: {self.server_ip}:{config.PORT}
- Status: {'Connected' if self.running else 'Disconnected'}
- Session: {'Active' if self.session_key else 'None'}
"""
                    self.add_message("SYSTEM", status_info.strip(), config.SYSTEM_MESSAGE_COLOR)
                else:
                    self.send_message(message)

            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                if self.running:
                    self.add_message(
                        "SYSTEM",
                        f"Input error: {str(e)}",
                        config.ERROR_MESSAGE_COLOR
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
        help=f"Command Center IP address (default: {config.SERVER_IP})"
    )
    parser.add_argument(
        "--agent-id",
        type=str,
        required=True,
        help="Your agent ID for authentication"
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Your password for authentication (optional, will prompt if not provided)"
    )
    args = parser.parse_args()

    terminal = OperativeTerminal(server_ip=args.host, agent_id=args.agent_id, password=args.password)
    try:
        terminal.run()
    except KeyboardInterrupt:
        terminal.cleanup()
        print("\nOperative Terminal stopped by user.")


if __name__ == "__main__":
    main()