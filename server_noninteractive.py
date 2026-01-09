#!/usr/bin/env python3

"""
Non-interactive version of the Command Center server for testing
"""

import socket
import threading
import sys
import os
import json
import time
from datetime import datetime, timedelta
from collections import defaultdict

# Add Core Components to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'Core Components'))

import config
from crypto_utils import CryptoEngine


class NonInteractiveCommandCenter:
    """Command Center server for secure communications - non-interactive version"""

    def __init__(self):
        self.crypto = CryptoEngine()
        self.messages = []
        self.running = False
        self.clients = []  # list of {'socket': socket, 'agent_id': str, 'clearance': str, 'last_seen': datetime}
        self.offline_messages = defaultdict(list)
        self.server_socket = None
        self.agent_id = "COMMAND"
        self.sessions = {}  # agent_id: {'session_key': str, 'expires': datetime}
        self.load_agent_database()

    def load_agent_database(self):
        """Load agent credentials and clearances"""
        self.agent_db = {}
        db_file = "../Data/agent_database.json"
        if os.path.exists(db_file):
            try:
                with open(db_file, 'r') as f:
                    self.agent_db = json.load(f)
            except:
                pass
        else:
            # Create default agent database
            self.agent_db = {
                "admin": {
                    "password_hash": self.crypto.hash_password("admin123"),
                    "clearance": "admin",
                    "active": True
                },
                "alpha": {
                    "password_hash": self.crypto.hash_password("alpha123"),
                    "clearance": "field_agent",
                    "active": True
                },
                "bravo": {
                    "password_hash": self.crypto.hash_password("bravo123"),
                    "clearance": "operative",
                    "active": True
                }
            }
            self.save_agent_database()

    def save_agent_database(self):
        """Save agent database"""
        db_file = "../Data/agent_database.json"
        os.makedirs(os.path.dirname(db_file), exist_ok=True)
        with open(db_file, 'w') as f:
            json.dump(self.agent_db, f, indent=2)

    def is_session_valid(self, agent_id: str) -> bool:
        """Check if agent session is still valid"""
        if agent_id in self.sessions:
            session = self.sessions[agent_id]
            return datetime.now() < session['expires']
        return False

    def create_session(self, agent_id: str) -> str:
        """Create a new session for an agent"""
        session_key = self.crypto.generate_session_key()
        expires = datetime.now() + timedelta(seconds=config.SESSION_TIMEOUT)
        self.sessions[agent_id] = {
            'session_key': session_key,
            'expires': expires
        }
        return session_key

    def authenticate_agent(self, agent_id: str, password: str) -> dict:
        """Authenticate an agent"""
        if agent_id in self.agent_db:
            agent_data = self.agent_db[agent_id]
            if agent_data['active'] and self.crypto.verify_password(password, agent_data['password_hash']):
                return {
                    'authenticated': True,
                    'clearance': agent_data['clearance'],
                    'session_key': self.create_session(agent_id)
                }
        return {'authenticated': False}

    def start_server(self):
        """Start the server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((config.HOST, config.PORT))
            self.server_socket.listen(config.MAX_CONNECTIONS)
            self.start_time = datetime.now()

            print(f"[INFO] Command Center started on {config.HOST}:{config.PORT}")
            print("[INFO] Awaiting agent connections...")

            self.running = True
            return True

        except Exception as e:
            print(f"[ERROR] Error starting Command Center: {e}")
            return False

    def broadcast_message(self, message, sender_agent_id, exclude_socket=None, priority="normal"):
        """Broadcast message to all agents except sender"""
        print(f"[DEBUG] Broadcasting message: {message} from {sender_agent_id}")
        print(f"[DEBUG] Current clients: {[c['agent_id'] for c in self.clients]}")
        
        for client in self.clients:
            # Check if this client is the sender by comparing sockets or agent IDs
            is_sender = False
            if exclude_socket is not None:
                try:
                    # Try comparing socket file descriptors (more reliable)
                    is_sender = (client['socket'].fileno() == exclude_socket.fileno())
                    print(f"[DEBUG] Comparing sockets: {client['socket'].fileno()} vs {exclude_socket.fileno()} -> {is_sender}")
                except:
                    # Fallback to agent ID comparison
                    is_sender = (client['agent_id'] == sender_agent_id)
                    print(f"[DEBUG] Comparing agent IDs: {client['agent_id']} vs {sender_agent_id} -> {is_sender}")
            
            if not is_sender and self.is_session_valid(client['agent_id']):
                try:
                    encrypted = self.crypto.encrypt_message(message)
                    client['socket'].send(json.dumps(encrypted).encode('utf-8'))
                    print(f"[DEBUG] Successfully broadcast to {client['agent_id']}: {message}")
                except Exception as e:
                    print(f"[DEBUG] Error broadcasting to {client['agent_id']}: {e}")
                    pass
            else:
                print(f"[DEBUG] Skipping {client['agent_id']} - is_sender: {is_sender}, session_valid: {self.is_session_valid(client['agent_id'])}")

    def handle_agent(self, agent_info):
        """Handle messages from a specific agent"""
        agent_socket = agent_info['socket']
        agent_id = agent_info['agent_id']
        
        print(f"[INFO] Handling agent {agent_id}")
        
        while self.running:
            try:
                # Receive encrypted message
                encrypted_data = agent_socket.recv(4096).decode('utf-8')

                if not encrypted_data:
                    # Agent disconnected
                    if agent_info in self.clients:
                        self.clients.remove(agent_info)
                    print(f"[INFO] Agent {agent_id} disconnected")
                    agent_socket.close()
                    break

                # Decrypt message
                try:
                    message_data = json.loads(encrypted_data)
                    message = self.crypto.decrypt_message(message_data)
                    print(f"[DEBUG] Received message from {agent_id}: {message}")
                except Exception as e:
                    print(f"[DEBUG] Error decrypting message from {agent_id}: {e}")
                    continue

                # Handle different message types
                if message.startswith('/secure '):
                    print(f"[DEBUG] Handling secure message: {message}")
                elif message.startswith('/priority '):
                    print(f"[DEBUG] Handling priority message: {message}")
                else:
                    # Regular message - broadcast to all other agents
                    print(f"[DEBUG] Broadcasting regular message from {agent_id}: {message}")
                    self.broadcast_message(f"{agent_id}: {message}", agent_id, exclude_socket=agent_socket)

                # Update last seen
                agent_info['last_seen'] = datetime.now()

            except Exception as e:
                if self.running:
                    if agent_info in self.clients:
                        self.clients.remove(agent_info)
                    print(f"[INFO] Agent {agent_id} disconnected due to error: {str(e)}")
                    agent_socket.close()
                break

    def accept_connections(self):
        """Thread to accept new agent connections"""
        print("[INFO] Accepting connections...")
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                print(f"[INFO] New connection from {address}")
                
                # Receive authentication data
                auth_data = client_socket.recv(1024).decode('utf-8')
                if not auth_data:
                    client_socket.close()
                    continue
                
                try:
                    auth_info = json.loads(auth_data)
                    agent_id = auth_info['agent_id']
                    password = auth_info['password']
                    
                    auth_result = self.authenticate_agent(agent_id, password)
                    
                    if auth_result['authenticated']:
                        client_info = {
                            'socket': client_socket, 
                            'agent_id': agent_id, 
                            'clearance': auth_result['clearance'],
                            'address': address,
                            'last_seen': datetime.now()
                        }
                        self.clients.append(client_info)

                        # Send authentication success
                        response = {
                            'status': 'success',
                            'session_key': auth_result['session_key'],
                            'clearance': auth_result['clearance']
                        }
                        client_socket.send(json.dumps(response).encode('utf-8'))
                        print(f"[INFO] Agent {agent_id} authenticated successfully")

                        # Start thread for this agent
                        client_thread = threading.Thread(target=self.handle_agent, args=(client_info,), daemon=True)
                        client_info['thread'] = client_thread
                        client_thread.start()
                    else:
                        # Send authentication failure
                        response = {'status': 'failed', 'message': 'Invalid credentials'}
                        client_socket.send(json.dumps(response).encode('utf-8'))
                        client_socket.close()
                        print(f"[INFO] Authentication failed for agent from {address}")

                except json.JSONDecodeError:
                    client_socket.close()
                    continue

            except Exception as e:
                if self.running:
                    print(f"[ERROR] Error accepting connection: {e}")
                break

    def run(self):
        """Main run loop"""
        if not self.start_server():
            return

        # Start accept connections thread
        accept_thread = threading.Thread(target=self.accept_connections, daemon=True)
        accept_thread.start()

        print("[INFO] Server running. Press Ctrl+C to stop.")

        # Keep the server running
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.running = False

        # Cleanup
        self.cleanup()

    def cleanup(self):
        """Clean up resources"""
        self.running = False
        for client in self.clients:
            try:
                client['socket'].close()
            except:
                pass
        if self.server_socket:
            self.server_socket.close()
        print("[INFO] Command Center shut down.")


def main():
    """Main entry point"""
    command_center = NonInteractiveCommandCenter()
    try:
        command_center.run()
    except KeyboardInterrupt:
        command_center.cleanup()
        print("\nCommand Center stopped by user.")


if __name__ == "__main__":
    main()