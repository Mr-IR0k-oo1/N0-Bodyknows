"""
Network Test - Connection Testing Utility
N0-BODYKNOWS Operations Network
"""

import os
import socket
import time
import json
import argparse
import threading
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.layout import Layout
from rich.live import Live

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'Core Components'))
import config


class NetworkTester:
    """Network connection testing and diagnostics utility"""

    def __init__(self):
        self.console = Console()
        self.test_results = []
        self.default_host = config.SERVER_IP
        self.default_port = config.PORT
    
    def test_port_connectivity(self, host: str, port: int, timeout: int = 5) -> dict:
        """Test basic TCP port connectivity"""
        result = {
            'host': host,
            'port': port,
            'test': 'Port Connectivity',
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'response_time': None,
            'error': None
        }
        
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            connection_result = sock.connect_ex((host, port))
            end_time = time.time()
            
            result['response_time'] = round((end_time - start_time) * 1000, 2)  # ms
            
            if connection_result == 0:
                result['success'] = True
                result['status'] = 'Open'
            else:
                result['status'] = 'Closed'
                result['error'] = f'Connection failed with code {connection_result}'
            
            sock.close()
            
        except socket.timeout:
            result['error'] = 'Connection timeout'
            result['status'] = 'Timeout'
        except Exception as e:
            result['error'] = str(e)
            result['status'] = 'Error'
        
        return result
    
    def test_server_response(self, host: str, port: int, timeout: int = 10) -> dict:
        """Test server response and protocol compatibility"""
        result = {
            'host': host,
            'port': port,
            'test': 'Server Response',
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'response_time': None,
            'server_info': None,
            'error': None
        }
        
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            sock.connect((host, port))
            
            # Send test authentication data
            test_auth = {
                'agent_id': 'test_connection',
                'password': 'test_password'
            }
            sock.send(json.dumps(test_auth).encode('utf-8'))
            
            # Receive response
            response = sock.recv(1024).decode('utf-8')
            end_time = time.time()
            
            result['response_time'] = round((end_time - start_time) * 1000, 2)
            
            if response:
                try:
                    response_data = json.loads(response)
                    result['server_info'] = {
                        'responds_to_auth': True,
                        'response_type': response_data.get('status', 'unknown'),
                        'response_length': len(response)
                    }
                    result['success'] = True
                except json.JSONDecodeError:
                    result['server_info'] = {
                        'responds_to_auth': False,
                        'raw_response': response[:100] + '...' if len(response) > 100 else response,
                        'response_length': len(response)
                    }
                    result['success'] = True
            else:
                result['error'] = 'No response from server'
            
            sock.close()
            
        except socket.timeout:
            result['error'] = 'Server response timeout'
        except ConnectionRefusedError:
            result['error'] = 'Connection refused'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def test_bandwidth(self, host: str, port: int, data_size: int = 1024, timeout: int = 10) -> dict:
        """Test network bandwidth by sending data"""
        result = {
            'host': host,
            'port': port,
            'test': 'Bandwidth Test',
            'timestamp': datetime.now().isoformat(),
            'success': False,
            'data_size': data_size,
            'transfer_time': None,
            'bandwidth_kbps': None,
            'error': None
        }
        
        try:
            # Generate test data
            test_data = 'A' * data_size
            
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            sock.connect((host, port))
            
            # Send data
            sock.send(test_data.encode('utf-8'))
            
            end_time = time.time()
            transfer_time = end_time - start_time
            
            result['transfer_time'] = round(transfer_time * 1000, 2)  # ms
            result['bandwidth_kbps'] = round((data_size * 8) / (transfer_time * 1024), 2)  # Kbps
            result['success'] = True
            
            sock.close()
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def test_multiple_ports(self, host: str, ports: list) -> list:
        """Test connectivity to multiple ports"""
        results = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            
            task = progress.add_task(f"Testing {len(ports)} ports on {host}...", total=len(ports))
            
            for port in ports:
                result = self.test_port_connectivity(host, port)
                results.append(result)
                progress.advance(task)
        
        return results
    
    def continuous_monitor(self, host: str, port: int, duration: int = 60, interval: int = 5) -> list:
        """Continuously monitor connection status"""
        results = []
        start_time = time.time()
        
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        
        with Live(layout, refresh_per_second=1) as live:
            while time.time() - start_time < duration:
                result = self.test_port_connectivity(host, port, timeout=2)
                results.append(result)
                
                # Update display
                layout["header"].update(Panel(
                    f"[bold cyan]Network Monitor[/bold cyan]\n"
                    f"Testing {host}:{port} - {len(results)} tests completed",
                    border_style="blue"
                ))
                
                # Create results table
                table = Table(show_header=True)
                table.add_column("Time", style="dim")
                table.add_column("Status", style="green")
                table.add_column("Response Time", style="yellow")
                
                recent_results = results[-10:]  # Show last 10 results
                for res in recent_results:
                    time_str = datetime.fromisoformat(res['timestamp']).strftime('%H:%M:%S')
                    status = "✅ Connected" if res['success'] else "❌ Failed"
                    response_time = f"{res['response_time']}ms" if res['response_time'] else "N/A"
                    
                    table.add_row(time_str, status, response_time)
                
                layout["body"].update(Panel(table, border_style="green"))
                
                # Calculate statistics
                if results:
                    success_rate = sum(1 for r in results if r['success']) / len(results) * 100
                    avg_response = sum(r['response_time'] or 0 for r in results) / len(results)
                    
                    layout["footer"].update(Panel(
                        f"Success Rate: {success_rate:.1f}% | "
                        f"Avg Response: {avg_response:.1f}ms | "
                        f"Time Remaining: {int(duration - (time.time() - start_time))}s",
                        border_style="yellow"
                    ))
                
                time.sleep(interval)
        
        return results
    
    def comprehensive_test(self, host: str, port: int) -> dict:
        """Run comprehensive network tests"""
        comprehensive_result = {
            'host': host,
            'port': port,
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'overall_success': False
        }
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=self.console
        ) as progress:
            
            tasks = {
                'connectivity': progress.add_task("Testing connectivity...", total=1),
                'server_response': progress.add_task("Testing server response...", total=1),
                'bandwidth': progress.add_task("Testing bandwidth...", total=1)
            }
            
            # Test 1: Basic connectivity
            comprehensive_result['tests']['connectivity'] = self.test_port_connectivity(host, port)
            progress.update(tasks['connectivity'], completed=1)
            
            # Test 2: Server response (only if connectivity works)
            if comprehensive_result['tests']['connectivity']['success']:
                comprehensive_result['tests']['server_response'] = self.test_server_response(host, port)
                progress.update(tasks['server_response'], completed=1)
            else:
                comprehensive_result['tests']['server_response'] = {'success': False, 'error': 'Skipped due to connectivity failure'}
                progress.update(tasks['server_response'], completed=1)
            
            # Test 3: Bandwidth (only if connectivity works)
            if comprehensive_result['tests']['connectivity']['success']:
                comprehensive_result['tests']['bandwidth'] = self.test_bandwidth(host, port)
                progress.update(tasks['bandwidth'], completed=1)
            else:
                comprehensive_result['tests']['bandwidth'] = {'success': False, 'error': 'Skipped due to connectivity failure'}
                progress.update(tasks['bandwidth'], completed=1)
        
        # Calculate overall success
        comprehensive_result['overall_success'] = all(
            test.get('success', False) for test in comprehensive_result['tests'].values()
        )
        
        return comprehensive_result
    
    def display_results(self, results):
        """Display test results in a formatted table"""
        if isinstance(results, dict):
            results = [results]
        
        table = Table(title="Network Test Results", show_header=True)
        table.add_column("Test", style="cyan")
        table.add_column("Host:Port", style="green")
        table.add_column("Status", style="yellow")
        table.add_column("Response Time", style="blue")
        table.add_column("Details", style="dim")
        
        for result in results:
            if 'test' in result:
                # Single test result
                status = "✅ Success" if result['success'] else "❌ Failed"
                response_time = f"{result['response_time']}ms" if result['response_time'] else "N/A"
                details = result.get('error') or result.get('status', 'N/A')
                
                table.add_row(
                    result['test'],
                    f"{result['host']}:{result['port']}",
                    status,
                    response_time,
                    details
                )
            elif 'tests' in result:
                # Comprehensive test result
                for test_name, test_result in result['tests'].items():
                    status = "✅ Success" if test_result.get('success', False) else "❌ Failed"
                    response_time = f"{test_result.get('response_time', 'N/A')}ms" if test_result.get('response_time') else "N/A"
                    details = test_result.get('error') or test_result.get('status', 'N/A')
                    
                    table.add_row(
                        test_name.title(),
                        f"{result['host']}:{result['port']}",
                        status,
                        response_time,
                        details
                    )
        
        self.console.print(table)
    
    def save_results(self, results, filename: str = None):
        """Save test results to file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"network_test_results_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.console.print(f"[green]Results saved to {filename}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error saving results: {e}[/red]")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="N0-BODYKNOWS Network Tester")
    parser.add_argument("--host", type=str, default=config.SERVER_IP, help="Target host")
    parser.add_argument("--port", type=int, default=config.PORT, help="Target port")
    parser.add_argument("--test", type=str, choices=["connectivity", "server", "bandwidth", "comprehensive"], 
                       default="comprehensive", help="Type of test to run")
    parser.add_argument("--ports", type=str, help="Comma-separated list of ports for multi-port test")
    parser.add_argument("--monitor", action="store_true", help="Enable continuous monitoring")
    parser.add_argument("--duration", type=int, default=60, help="Monitoring duration in seconds")
    parser.add_argument("--interval", type=int, default=5, help="Monitoring interval in seconds")
    parser.add_argument("--save", type=str, help="Save results to file")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout in seconds")
    
    args = parser.parse_args()
    
    tester = NetworkTester()
    
    if args.monitor:
        results = tester.continuous_monitor(args.host, args.port, args.duration, args.interval)
    elif args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]
        results = tester.test_multiple_ports(args.host, ports)
    else:
        if args.test == "connectivity":
            results = tester.test_port_connectivity(args.host, args.port, args.timeout)
        elif args.test == "server":
            results = tester.test_server_response(args.host, args.port, args.timeout)
        elif args.test == "bandwidth":
            results = tester.test_bandwidth(args.host, args.port, timeout=args.timeout)
        else:  # comprehensive
            results = tester.comprehensive_test(args.host, args.port)
    
    # Display results
    tester.display_results(results)
    
    # Save results if requested
    if args.save:
        tester.save_results(results, args.save)


if __name__ == "__main__":
    main()