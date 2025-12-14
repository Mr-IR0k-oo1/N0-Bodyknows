#!/usr/bin/env python3

import sys
import json
import socket
import os

# Add Core Components to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'Core Components'))

import config

def test_client_fixed():
    try:
        print(f"Connecting to {config.SERVER_IP}:{config.PORT}")
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((config.SERVER_IP, config.PORT))
        
        print("Connected successfully!")
        
        agent_id = "alpha"
        # Use the known correct password instead of getpass
        password = "alpha123"
        
        auth_data = {
            'agent_id': agent_id,
            'password': password
        }
        
        print(f"Sending authentication data for {agent_id}...")
        sock.send(json.dumps(auth_data).encode('utf-8'))
        
        # Receive authentication response
        response_data = sock.recv(1024).decode('utf-8')
        response = json.loads(response_data)
        
        print(f"Server response: {response}")
        
        if response['status'] == 'success':
            print("✅ Authentication successful!")
            print(f"Clearance: {response['clearance']}")
            print(f"Session key: {response['session_key'][:10]}...")
            
            # Now you can send messages
            while True:
                try:
                    message = input("Enter message (or 'quit' to exit): ")
                    if message.lower() == 'quit':
                        break
                    
                    # For now, just send plain text (in real client, this would be encrypted)
                    message_data = {
                        'encrypted_data': base64.b64encode(message.encode()).decode(),
                        'type': 'master_encrypted'
                    }
                    sock.send(json.dumps(message_data).encode('utf-8'))
                    
                except KeyboardInterrupt:
                    break
                    
        else:
            print("❌ Authentication failed!")
            print(f"Reason: {response.get('message', 'Unknown error')}")
            
        sock.close()
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_client_fixed()