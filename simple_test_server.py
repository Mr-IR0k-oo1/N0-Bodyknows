#!/usr/bin/env python3

"""
Very simple test server for debugging broadcast issues
"""

import socket
import threading
import json
import sys
import os

# Add Core Components to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'Core Components'))

from crypto_utils import CryptoEngine

class SimpleTestServer:
    def __init__(self):
        self.crypto = CryptoEngine()
        self.clients = []
        self.running = True
        self.server_socket = None
        
    def start(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('localhost', 9999))
            self.server_socket.listen(5)
            print("✅ Simple test server started on localhost:9999")
            
            # Start connection acceptor
            threading.Thread(target=self.accept_connections, daemon=True).start()
            
            # Keep server running
            while self.running:
                pass
                
        except Exception as e:
            print(f"❌ Server error: {e}")
        finally:
            self.cleanup()
    
    def accept_connections(self):
        print("🔍 Waiting for connections...")
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                print(f"🔌 New connection from {addr}")
                
                # Handle authentication
                auth_data = client_socket.recv(1024).decode('utf-8')
                if not auth_data:
                    client_socket.close()
                    continue
                
                try:
                    auth_info = json.loads(auth_data)
                    agent_id = auth_info['agent_id']
                    password = auth_info['password']
                    
                    # Simple authentication - accept any password for testing
                    response = {
                        'status': 'success',
                        'session_key': 'test_key_123',
                        'clearance': 'test'
                    }
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    print(f"✅ Authenticated {agent_id}")
                    
                    # Add to clients list
                    self.clients.append({
                        'socket': client_socket,
                        'agent_id': agent_id,
                        'addr': addr
                    })
                    
                    # Start message handler
                    threading.Thread(target=self.handle_client, args=(client_socket, agent_id), daemon=True).start()
                    
                except json.JSONDecodeError:
                    client_socket.close()
                    
            except Exception as e:
                if self.running:
                    print(f"❌ Connection error: {e}")
    
    def handle_client(self, client_socket, agent_id):
        print(f"📡 Handling messages from {agent_id}")
        while self.running:
            try:
                data = client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                
                print(f"💬 Received from {agent_id}: {data}")
                
                # Broadcast to all other clients
                self.broadcast_message(data, agent_id, client_socket)
                
            except Exception as e:
                print(f"❌ Error handling {agent_id}: {e}")
                break
        
        # Clean up
        self.clients = [c for c in self.clients if c['socket'] != client_socket]
        client_socket.close()
        print(f"🔌 {agent_id} disconnected")
    
    def broadcast_message(self, message, sender_id, exclude_socket):
        print(f"📢 Broadcasting message from {sender_id}: {message}")
        print(f"👥 Current clients: {[c['agent_id'] for c in self.clients]}")
        
        for client in self.clients:
            if client['socket'] != exclude_socket:
                try:
                    # Compare using fileno for reliability
                    if client['socket'].fileno() != exclude_socket.fileno():
                        client['socket'].send(message.encode('utf-8'))
                        print(f"📤 Sent to {client['agent_id']}: {message}")
                    else:
                        print(f"🚫 Skipping {client['agent_id']} (sender)")
                except Exception as e:
                    print(f"❌ Error sending to {client['agent_id']}: {e}")
    
    def cleanup(self):
        self.running = False
        for client in self.clients:
            try:
                client['socket'].close()
            except:
                pass
        if self.server_socket:
            self.server_socket.close()
        print("🛑 Server stopped")

if __name__ == "__main__":
    server = SimpleTestServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.cleanup()