"""
Key Generator - Cryptographic Key Management
N0-BODYKNOWS Operations Network
"""

import os
import json
import secrets
import hashlib
import argparse
from datetime import datetime, timedelta
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Core Components'))
from crypto_utils import CryptoEngine


class KeyGenerator:
    """Cryptographic key generation and management utility"""

    def __init__(self):
        self.console = Console()
        self.crypto = CryptoEngine()
        self.key_vault_path = "../Data/key_vault"
        self.agent_db_path = "../Data/agent_database.json"
    
    def generate_agent_credentials(self, agent_id: str, clearance: str = "operative") -> dict:
        """Generate new agent credentials"""
        # Generate random password
        password = secrets.token_urlsafe(16)
        
        # Hash password
        password_hash = self.crypto.hash_password(password)
        
        # Generate agent key pair
        keypair = self.crypto.create_agent_keypair(agent_id)
        
        credentials = {
            'agent_id': agent_id,
            'password': password,
            'password_hash': password_hash,
            'clearance': clearance,
            'key_file': keypair['key_file'],
            'public_key': keypair['public_key'],
            'created': datetime.now().isoformat(),
            'active': True
        }
        
        return credentials
    
    def add_agent_to_database(self, credentials: dict):
        """Add agent credentials to database"""
        # Load existing database
        agent_db = {}
        if os.path.exists(self.agent_db_path):
            try:
                with open(self.agent_db_path, 'r') as f:
                    agent_db = json.load(f)
            except:
                pass
        
        # Add new agent
        agent_db[credentials['agent_id']] = {
            'password_hash': credentials['password_hash'],
            'clearance': credentials['clearance'],
            'active': credentials['active'],
            'created': credentials['created']
        }
        
        # Save database
        os.makedirs(os.path.dirname(self.agent_db_path), exist_ok=True)
        with open(self.agent_db_path, 'w') as f:
            json.dump(agent_db, f, indent=2)
        
        return True
    
    def generate_session_token(self, agent_id: str, expires_hours: int = 24) -> dict:
        """Generate a session token for an agent"""
        token = secrets.token_urlsafe(32)
        expires = datetime.now() + timedelta(hours=expires_hours)
        
        session_data = {
            'token': token,
            'agent_id': agent_id,
            'expires': expires.isoformat(),
            'created': datetime.now().isoformat()
        }
        
        # Save session token
        session_file = os.path.join(self.key_vault_path, f"session_{agent_id}.json")
        os.makedirs(os.path.dirname(session_file), exist_ok=True)
        with open(session_file, 'w') as f:
            json.dump(session_data, f, indent=2)
        
        return session_data
    
    def generate_one_time_pad(self, length: int = 1024) -> dict:
        """Generate a one-time pad for ultra-secure communication"""
        pad_data = secrets.token_bytes(length)
        pad_id = secrets.token_urlsafe(16)
        
        pad_info = {
            'pad_id': pad_id,
            'pad_data': pad_data.hex(),
            'length': length,
            'created': datetime.now().isoformat(),
            'used': False
        }
        
        # Save one-time pad
        pad_file = os.path.join(self.key_vault_path, f"otp_{pad_id}.json")
        os.makedirs(os.path.dirname(pad_file), exist_ok=True)
        with open(pad_file, 'w') as f:
            json.dump(pad_info, f, indent=2)
        
        return pad_info
    
    def list_agents(self):
        """List all agents in the database"""
        if not os.path.exists(self.agent_db_path):
            self.console.print("[red]No agent database found.[/red]")
            return
        
        try:
            with open(self.agent_db_path, 'r') as f:
                agent_db = json.load(f)
            
            table = Table(title="Agent Database", show_header=True)
            table.add_column("Agent ID", style="cyan")
            table.add_column("Clearance", style="green")
            table.add_column("Status", style="yellow")
            table.add_column("Created", style="dim")
            
            for agent_id, data in agent_db.items():
                status = "Active" if data.get('active', True) else "Inactive"
                created = data.get('created', 'Unknown')
                if created != 'Unknown':
                    created = datetime.fromisoformat(created).strftime('%Y-%m-%d')
                
                table.add_row(agent_id, data.get('clearance', 'Unknown'), status, created)
            
            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"[red]Error reading agent database: {e}[/red]")
    
    def revoke_agent(self, agent_id: str):
        """Revoke agent credentials"""
        if not os.path.exists(self.agent_db_path):
            self.console.print("[red]No agent database found.[/red]")
            return False
        
        try:
            with open(self.agent_db_path, 'r') as f:
                agent_db = json.load(f)
            
            if agent_id in agent_db:
                agent_db[agent_id]['active'] = False
                
                with open(self.agent_db_path, 'w') as f:
                    json.dump(agent_db, f, indent=2)
                
                # Remove agent key file
                key_file = os.path.join(self.key_vault_path, f"{agent_id}.key")
                if os.path.exists(key_file):
                    self.crypto.secure_delete(key_file)
                
                self.console.print(f"[green]Agent {agent_id} credentials revoked.[/green]")
                return True
            else:
                self.console.print(f"[red]Agent {agent_id} not found.[/red]")
                return False
                
        except Exception as e:
            self.console.print(f"[red]Error revoking agent: {e}[/red]")
            return False
    
    def create_agent(self, agent_id: str, clearance: str = "operative"):
        """Create a new agent with credentials"""
        # Validate clearance level
        valid_clearances = ['operative', 'field_agent', 'command', 'admin']
        if clearance not in valid_clearances:
            self.console.print(f"[red]Invalid clearance level. Valid levels: {', '.join(valid_clearances)}[/red]")
            return None
        
        # Generate credentials
        credentials = self.generate_agent_credentials(agent_id, clearance)
        
        # Add to database
        if self.add_agent_to_database(credentials):
            # Display credentials
            self.console.print(Panel(
                f"[green]Agent Created Successfully![/green]\n\n"
                f"[cyan]Agent ID:[/cyan] {credentials['agent_id']}\n"
                f"[cyan]Password:[/cyan] {credentials['password']}\n"
                f"[cyan]Clearance:[/cyan] {credentials['clearance']}\n"
                f"[cyan]Key File:[/cyan] {credentials['key_file']}\n"
                f"[yellow]⚠️  Store password securely - it will not be shown again![/yellow]",
                title="🔑 New Agent Credentials",
                border_style="green"
            ))
            
            return credentials
        else:
            self.console.print("[red]Failed to create agent.[/red]")
            return None
    
    def generate_master_key(self):
        """Generate a new master encryption key"""
        master_key = self.crypto.master_key
        
        self.console.print(Panel(
            f"[green]Master Key Generated[/green]\n\n"
            f"[cyan]Key Location:[/cyan] {self.key_vault_path}/master.key\n"
            f"[yellow]⚠️  Backup this key securely - losing it will make all encrypted data unrecoverable![/yellow]",
            title="🔐 Master Encryption Key",
            border_style="blue"
        ))
    
    def cleanup_expired_sessions(self):
        """Clean up expired session tokens"""
        if not os.path.exists(self.key_vault_path):
            return
        
        cleaned = 0
        for filename in os.listdir(self.key_vault_path):
            if filename.startswith('session_') and filename.endswith('.json'):
                session_file = os.path.join(self.key_vault_path, filename)
                try:
                    with open(session_file, 'r') as f:
                        session_data = json.load(f)
                    
                    expires = datetime.fromisoformat(session_data['expires'])
                    if datetime.now() > expires:
                        os.remove(session_file)
                        cleaned += 1
                except:
                    pass
        
        if cleaned > 0:
            self.console.print(f"[green]Cleaned up {cleaned} expired sessions.[/green]")
        else:
            self.console.print("[dim]No expired sessions found.[/dim]")
    
    def show_key_vault_status(self):
        """Show key vault status and statistics"""
        if not os.path.exists(self.key_vault_path):
            self.console.print("[red]Key vault not found.[/red]")
            return
        
        # Count different types of keys
        master_keys = 0
        agent_keys = 0
        session_tokens = 0
        otp_pads = 0
        
        for filename in os.listdir(self.key_vault_path):
            if filename == 'master.key':
                master_keys += 1
            elif filename.endswith('.key'):
                agent_keys += 1
            elif filename.startswith('session_'):
                session_tokens += 1
            elif filename.startswith('otp_'):
                otp_pads += 1
        
        table = Table(title="Key Vault Status", show_header=True)
        table.add_column("Key Type", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Status", style="yellow")
        
        table.add_row("Master Key", str(master_keys), "✅ Active" if master_keys > 0 else "❌ Missing")
        table.add_row("Agent Keys", str(agent_keys), "📝 Stored")
        table.add_row("Session Tokens", str(session_tokens), "🔄 Active")
        table.add_row("One-Time Pads", str(otp_pads), "🔒 Available")
        
        self.console.print(table)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="N0-BODYKNOWS Key Generator")
    parser.add_argument("--create-agent", type=str, help="Create new agent with specified ID")
    parser.add_argument("--clearance", type=str, default="operative", 
                       choices=["operative", "field_agent", "command", "admin"],
                       help="Agent clearance level")
    parser.add_argument("--list-agents", action="store_true", help="List all agents")
    parser.add_argument("--revoke-agent", type=str, help="Revoke agent credentials")
    parser.add_argument("--generate-master", action="store_true", help="Generate master key")
    parser.add_argument("--generate-session", type=str, help="Generate session token for agent")
    parser.add_argument("--generate-otp", action="store_true", help="Generate one-time pad")
    parser.add_argument("--cleanup-sessions", action="store_true", help="Clean up expired sessions")
    parser.add_argument("--status", action="store_true", help="Show key vault status")
    
    args = parser.parse_args()
    
    key_gen = KeyGenerator()
    
    if args.generate_master:
        key_gen.generate_master_key()
    elif args.create_agent:
        key_gen.create_agent(args.create_agent, args.clearance)
    elif args.list_agents:
        key_gen.list_agents()
    elif args.revoke_agent:
        key_gen.revoke_agent(args.revoke_agent)
    elif args.generate_session:
        session = key_gen.generate_session_token(args.generate_session)
        key_gen.console.print(Panel(
            f"[green]Session Token Generated[/green]\n\n"
            f"[cyan]Agent:[/cyan] {session['agent_id']}\n"
            f"[cyan]Token:[/cyan] {session['token']}\n"
            f"[cyan]Expires:[/cyan] {session['expires']}\n",
            title="🎫 Session Token",
            border_style="green"
        ))
    elif args.generate_otp:
        otp = key_gen.generate_one_time_pad()
        key_gen.console.print(Panel(
            f"[green]One-Time Pad Generated[/green]\n\n"
            f"[cyan]Pad ID:[/cyan] {otp['pad_id']}\n"
            f"[cyan]Length:[/cyan] {otp['length']} bytes\n"
            f"[cyan]Created:[/cyan] {otp['created']}\n",
            title="🔐 One-Time Pad",
            border_style="blue"
        ))
    elif args.cleanup_sessions:
        key_gen.cleanup_expired_sessions()
    elif args.status:
        key_gen.show_key_vault_status()
    else:
        # Show interactive menu
        key_gen.console.print(Panel(
            "[bold cyan]N0-BODYKNOWS Key Generator[/bold cyan]\n\n"
            "Use --help to see available commands\n"
            "Example: python key_generator.py --create-agent alpha --clearance field_agent",
            title="🔑 Key Management Utility",
            border_style="cyan"
        ))


if __name__ == "__main__":
    main()