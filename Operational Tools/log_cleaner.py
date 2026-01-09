"""
Log Cleaner - Evidence Removal Utility
N0-BODYKNOWS Operations Network
"""

import os
import json
import shutil
import argparse
import tempfile
from datetime import datetime, timedelta
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Core Components'))
from crypto_utils import CryptoEngine


class LogCleaner:
    """Evidence removal and log cleaning utility"""

    def __init__(self):
        self.console = Console()
        self.crypto = CryptoEngine()
        self.data_stores_path = "../Data"
        self.temp_dir = tempfile.gettempdir()
    
    def secure_delete_file(self, file_path: str, passes: int = 3):
        """Securely delete a file with multiple passes"""
        if not os.path.exists(file_path):
            return False
        
        try:
            file_size = os.path.getsize(file_path)
            
            with open(file_path, 'wb') as f:
                for pass_num in range(passes):
                    f.seek(0)
                    # Use different patterns for each pass
                    if pass_num == 0:
                        # Pass 1: All zeros
                        f.write(b'\x00' * file_size)
                    elif pass_num == 1:
                        # Pass 2: All ones
                        f.write(b'\xFF' * file_size)
                    else:
                        # Pass 3: Random data
                        f.write(os.urandom(file_size))
                    
                    f.flush()
                    os.fsync(f.fileno())
            
            os.remove(file_path)
            return True
        except Exception as e:
            self.console.print(f"[red]Error deleting {file_path}: {e}[/red]")
            return False
    
    def clean_chat_history(self, agent_id: str = None, days_old: int = 7):
        """Clean chat history files"""
        cleaned_files = []
        
        # Clean server history
        server_history = os.path.join(self.data_stores_path, "server_history.json")
        if os.path.exists(server_history):
            if self._clean_history_file(server_history, agent_id, days_old):
                cleaned_files.append(server_history)
        
        # Clean chat history
        chat_history = os.path.join(self.data_stores_path, "chat_history.json")
        if os.path.exists(chat_history):
            if self._clean_history_file(chat_history, agent_id, days_old):
                cleaned_files.append(chat_history)
        
        return cleaned_files
    
    def _clean_history_file(self, file_path: str, agent_id: str = None, days_old: int = 7):
        """Clean individual history file"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            original_count = len(data)
            cutoff_date = datetime.now() - timedelta(days=days_old)
            
            # Filter messages
            filtered_data = []
            for msg in data:
                msg_date = datetime.fromisoformat(msg['time'])
                
                # Remove if older than cutoff date
                if msg_date < cutoff_date:
                    continue
                
                # Remove if specific agent ID is specified
                if agent_id and msg['sender'] == agent_id:
                    continue
                
                filtered_data.append(msg)
            
            # Write back filtered data
            with open(file_path, 'w') as f:
                json.dump(filtered_data, f, indent=2)
            
            removed_count = original_count - len(filtered_data)
            if removed_count > 0:
                self.console.print(f"[green]Cleaned {removed_count} messages from {file_path}[/green]")
                return True
            
        except Exception as e:
            self.console.print(f"[red]Error cleaning {file_path}: {e}[/red]")
        
        return False
    
    def wipe_agent_traces(self, agent_id: str):
        """Completely wipe all traces of an agent"""
        wiped_files = []
        
        # Remove agent key file
        key_file = os.path.join(self.data_stores_path, "key_vault", f"{agent_id}.key")
        if os.path.exists(key_file):
            if self.secure_delete_file(key_file):
                wiped_files.append(key_file)
        
        # Remove session files
        session_file = os.path.join(self.data_stores_path, "key_vault", f"session_{agent_id}.json")
        if os.path.exists(session_file):
            if self.secure_delete_file(session_file):
                wiped_files.append(session_file)
        
        # Remove from agent database
        agent_db_file = os.path.join(self.data_stores_path, "agent_database.json")
        if os.path.exists(agent_db_file):
            try:
                with open(agent_db_file, 'r') as f:
                    agent_db = json.load(f)
                
                if agent_id in agent_db:
                    del agent_db[agent_id]
                    
                    with open(agent_db_file, 'w') as f:
                        json.dump(agent_db, f, indent=2)
                    
                    wiped_files.append(agent_db_file)
            except Exception as e:
                self.console.print(f"[red]Error updating agent database: {e}[/red]")
        
        # Clean from chat histories
        history_files = self.clean_chat_history(agent_id, days_old=0)
        wiped_files.extend(history_files)
        
        return wiped_files
    
    def clean_temp_files(self):
        """Clean temporary files and caches"""
        cleaned_files = []
        
        # Clean system temp directory
        temp_patterns = [
            "nobodyknows_*",
            "chat_*",
            "server_*",
            "agent_*",
            "session_*"
        ]
        
        for pattern in temp_patterns:
            for filename in os.listdir(self.temp_dir):
                if filename.startswith(pattern.replace("*", "")):
                    file_path = os.path.join(self.temp_dir, filename)
                    try:
                        if os.path.isfile(file_path):
                            if self.secure_delete_file(file_path):
                                cleaned_files.append(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                            cleaned_files.append(file_path)
                    except:
                        pass
        
        return cleaned_files
    
    def clean_logs(self, log_dir: str = "logs"):
        """Clean application logs"""
        cleaned_files = []
        
        if not os.path.exists(log_dir):
            return cleaned_files
        
        for filename in os.listdir(log_dir):
            if filename.endswith('.log') or filename.endswith('.out'):
                file_path = os.path.join(log_dir, filename)
                if self.secure_delete_file(file_path):
                    cleaned_files.append(file_path)
        
        return cleaned_files
    
    def emergency_wipe(self, confirm: bool = False):
        """Emergency wipe of all sensitive data"""
        if not confirm:
            self.console.print("[red]Emergency wipe requires confirmation. Use --confirm flag.[/red]")
            return []
        
        wiped_files = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            # Wipe key vault
            task1 = progress.add_task("Wiping key vault...", total=None)
            key_vault_path = os.path.join(self.data_stores_path, "key_vault")
            if os.path.exists(key_vault_path):
                for filename in os.listdir(key_vault_path):
                    file_path = os.path.join(key_vault_path, filename)
                    if self.secure_delete_file(file_path):
                        wiped_files.append(file_path)
            progress.update(task1, completed=True)
            
            # Wipe agent database
            task2 = progress.add_task("Wiping agent database...", total=None)
            agent_db_file = os.path.join(self.data_stores_path, "agent_database.json")
            if os.path.exists(agent_db_file):
                if self.secure_delete_file(agent_db_file):
                    wiped_files.append(agent_db_file)
            progress.update(task2, completed=True)
            
            # Wipe chat histories
            task3 = progress.add_task("Wiping chat histories...", total=None)
            history_files = ["server_history.json", "chat_history.json"]
            for history_file in history_files:
                file_path = os.path.join(self.data_stores_path, history_file)
                if os.path.exists(file_path):
                    if self.secure_delete_file(file_path):
                        wiped_files.append(file_path)
            progress.update(task3, completed=True)
            
            # Wipe configuration
            task4 = progress.add_task("Wiping configuration...", total=None)
            config_file = os.path.join(self.data_stores_path, "mission_config.json")
            if os.path.exists(config_file):
                if self.secure_delete_file(config_file):
                    wiped_files.append(config_file)
            progress.update(task4, completed=True)
        
        return wiped_files
    
    def analyze_data_stores(self):
        """Analyze data stores for sensitive information"""
        analysis = {
            'total_files': 0,
            'sensitive_files': 0,
            'size_mb': 0,
            'oldest_file': None,
            'newest_file': None
        }
        
        if not os.path.exists(self.data_stores_path):
            return analysis
        
        oldest_time = datetime.now()
        newest_time = datetime.min
        
        for root, dirs, files in os.walk(self.data_stores_path):
            for file in files:
                file_path = os.path.join(root, file)
                analysis['total_files'] += 1
                
                # Check file size
                try:
                    file_size = os.path.getsize(file_path)
                    analysis['size_mb'] += file_size / (1024 * 1024)
                except:
                    pass
                
                # Check modification time
                try:
                    mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    if mod_time < oldest_time:
                        oldest_time = mod_time
                        analysis['oldest_file'] = file_path
                    if mod_time > newest_time:
                        newest_time = mod_time
                        analysis['newest_file'] = file_path
                except:
                    pass
                
                # Check if file contains sensitive data
                sensitive_patterns = ['password', 'key', 'token', 'secret', 'credential']
                if any(pattern in file.lower() for pattern in sensitive_patterns):
                    analysis['sensitive_files'] += 1
        
        return analysis
    
    def show_analysis(self):
        """Show data stores analysis"""
        analysis = self.analyze_data_stores()
        
        table = Table(title="Data Analysis", show_header=True)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Total Files", str(analysis['total_files']))
        table.add_row("Sensitive Files", str(analysis['sensitive_files']))
        table.add_row("Total Size", f"{analysis['size_mb']:.2f} MB")
        table.add_row("Oldest File", analysis['oldest_file'] or "None")
        table.add_row("Newest File", analysis['newest_file'] or "None")
        
        self.console.print(table)
    
    def generate_cleanup_report(self, cleaned_files: list):
        """Generate a cleanup report"""
        if not cleaned_files:
            self.console.print("[yellow]No files were cleaned.[/yellow]")
            return
        
        table = Table(title="Cleanup Report", show_header=True)
        table.add_column("File Path", style="cyan")
        table.add_column("Status", style="green")
        
        for file_path in cleaned_files:
            table.add_row(file_path, "✅ Cleaned")
        
        self.console.print(table)
        self.console.print(f"[green]Total files cleaned: {len(cleaned_files)}[/green]")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="N0-BODYKNOWS Log Cleaner")
    parser.add_argument("--clean-history", action="store_true", help="Clean chat history")
    parser.add_argument("--agent-id", type=str, help="Specific agent ID to clean")
    parser.add_argument("--days-old", type=int, default=7, help="Clean messages older than N days")
    parser.add_argument("--wipe-agent", type=str, help="Completely wipe agent traces")
    parser.add_argument("--clean-temp", action="store_true", help="Clean temporary files")
    parser.add_argument("--clean-logs", action="store_true", help="Clean application logs")
    parser.add_argument("--emergency-wipe", action="store_true", help="Emergency wipe of all data")
    parser.add_argument("--confirm", action="store_true", help="Confirm destructive operations")
    parser.add_argument("--analyze", action="store_true", help="Analyze data stores")
    
    args = parser.parse_args()
    
    cleaner = LogCleaner()
    
    if args.analyze:
        cleaner.show_analysis()
    elif args.emergency_wipe:
        wiped_files = cleaner.emergency_wipe(args.confirm)
        if wiped_files:
            cleaner.generate_cleanup_report(wiped_files)
    elif args.wipe_agent:
        if not args.confirm:
            cleaner.console.print("[red]Agent wipe requires --confirm flag.[/red]")
            return
        wiped_files = cleaner.wipe_agent_traces(args.wipe_agent)
        cleaner.generate_cleanup_report(wiped_files)
    elif args.clean_history:
        cleaned_files = cleaner.clean_chat_history(args.agent_id, args.days_old)
        cleaner.generate_cleanup_report(cleaned_files)
    elif args.clean_temp:
        cleaned_files = cleaner.clean_temp_files()
        cleaner.generate_cleanup_report(cleaned_files)
    elif args.clean_logs:
        cleaned_files = cleaner.clean_logs()
        cleaner.generate_cleanup_report(cleaned_files)
    else:
        # Show interactive menu
        cleaner.console.print(Panel(
            "[bold cyan]N0-BODYKNOWS Log Cleaner[/bold cyan]\n\n"
            "Use --help to see available commands\n"
            "Example: python log_cleaner.py --clean-history --days-old 30\n"
            "Example: python log_cleaner.py --emergency-wipe --confirm",
            title="🧹 Evidence Removal Utility",
            border_style="red"
        ))


if __name__ == "__main__":
    main()