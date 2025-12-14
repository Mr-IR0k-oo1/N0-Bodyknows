#!/usr/bin/env python3

import sys
import json
import socket
import threading
import time
import os
import base64

# Add Core Components to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'Core Components'))

import config

def test_broadcast():
    """Test message broadcasting between two agents"""
    
    # Connect first agent (alpha)
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock1.connect((config.SERVER_IP, config.PORT))
    
    # Authenticate alpha
    auth_data1 = {
        'agent_id': 'alpha',
        'password': 'alpha123'
    }
    sock1.send(json.dumps(auth_data1).encode('utf-8'))
    response1 = json.loads(sock1.recv(1024).decode('utf-8'))
    print(f"Alpha authentication: {response1['status']}")
    
    # Connect second agent (bravo)
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.connect((config.SERVER_IP, config.PORT))
    
    # Authenticate bravo
    auth_data2 = {
        'agent_id': 'bravo',
        'password': 'bravo123'
    }
    sock2.send(json.dumps(auth_data2).encode('utf-8'))
    response2 = json.loads(sock2.recv(1024).decode('utf-8'))
    print(f"Bravo authentication: {response2['status']}")
    
    # Give some time for both agents to be registered
    time.sleep(1)
    
    # Send a message from alpha
    message_data = {
        'encrypted_data': base64.b64encode(b"Hello from alpha!").decode(),
        'type': 'master_encrypted'
    }
    sock1.send(json.dumps(message_data).encode('utf-8'))
    print("Alpha sent: Hello from alpha!")
    
    # Try to receive on bravo
    try:
        sock2.settimeout(5.0)
        response = sock2.recv(4096).decode('utf-8')
        print(f"Bravo received: {response}")
    except socket.timeout:
        print("❌ Bravo did not receive the message (timeout)")
    except Exception as e:
        print(f"❌ Error receiving on bravo: {e}")
    
    # Clean up
    sock1.close()
    sock2.close()

if __name__ == "__main__":
    test_broadcast()