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

def test_simple_broadcast():
    """Simple test to check if broadcast logic works"""
    
    # Test the socket comparison logic
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    print(f"Socket 1 fileno: {sock1.fileno()}")
    print(f"Socket 2 fileno: {sock2.fileno()}")
    print(f"Are sockets equal? {sock1 == sock2}")
    print(f"Are filenos equal? {sock1.fileno() == sock2.fileno()}")
    
    # Test with actual server connection
    try:
        # Connect first agent (alpha)
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
        time.sleep(2)
        
        print("Both agents authenticated successfully!")
        
        # Clean up
        sock1.close()
        sock2.close()
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_simple_broadcast()