#!/usr/bin/env python3

"""
Minimal test to identify the broadcast issue
"""

import sys
import json
import socket
import time
import os

# Add Core Components to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'Core Components'))

import config
from crypto_utils import CryptoEngine

def test_encryption():
    """Test if encryption/decryption works correctly"""
    crypto = CryptoEngine()
    
    # Test message
    message = "Hello from alpha!"
    print(f"Original message: {message}")
    
    # Encrypt
    encrypted = crypto.encrypt_message(message)
    print(f"Encrypted: {encrypted}")
    
    # Decrypt
    decrypted = crypto.decrypt_message(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Check if they match
    if decrypted == message:
        print("✅ Encryption/Decryption works correctly")
        return True
    else:
        print("❌ Encryption/Decryption failed")
        return False

def test_socket_comparison():
    """Test socket comparison logic"""
    # Create some mock sockets
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"Socket 1 fileno: {sock1.fileno()}")
    print(f"Socket 2 fileno: {sock2.fileno()}")
    
    # Test comparison
    is_same = sock1.fileno() == sock2.fileno()
    print(f"Are socket filenos equal? {is_same}")
    
    # Test with None
    is_sender = False
    exclude_socket = sock1
    
    if exclude_socket is not None:
        try:
            is_sender = (sock1.fileno() == exclude_socket.fileno())
            print(f"Socket 1 vs exclude_socket (sock1): {is_sender}")
        except:
            print("Exception in socket comparison")
    
    if exclude_socket is not None:
        try:
            is_sender = (sock2.fileno() == exclude_socket.fileno())
            print(f"Socket 2 vs exclude_socket (sock1): {is_sender}")
        except:
            print("Exception in socket comparison")
    
    sock1.close()
    sock2.close()

def test_broadcast_logic():
    """Test the broadcast logic with mock data"""
    # Mock clients
    clients = [
        {'socket': 'socket1', 'agent_id': 'alpha', 'clearance': 'field_agent'},
        {'socket': 'socket2', 'agent_id': 'bravo', 'clearance': 'operative'}
    ]
    
    # Mock sender
    sender_agent_id = 'alpha'
    exclude_socket = 'socket1'  # This would be the alpha's socket
    message = "Hello from alpha!"
    
    print(f"Testing broadcast logic:")
    print(f"Message: {message}")
    print(f"Sender: {sender_agent_id}")
    print(f"Clients: {[c['agent_id'] for c in clients]}")
    
    for client in clients:
        # Check if this client is the sender
        is_sender = False
        if exclude_socket is not None:
            try:
                # In real code, this would compare filenos
                is_sender = (client['socket'] == exclude_socket)
            except:
                # Fallback to agent ID comparison
                is_sender = (client['agent_id'] == sender_agent_id)
        
        print(f"Client {client['agent_id']}: is_sender={is_sender}")
        
        if not is_sender:
            print(f"  -> Would broadcast to {client['agent_id']}")
        else:
            print(f"  -> Would skip {client['agent_id']} (sender)")

if __name__ == "__main__":
    print("=== Testing Encryption ===")
    test_encryption()
    
    print("\n=== Testing Socket Comparison ===")
    test_socket_comparison()
    
    print("\n=== Testing Broadcast Logic ===")
    test_broadcast_logic()