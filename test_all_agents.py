#!/usr/bin/env python3

import sys
import json
import socket
import os

# Add Core Components to path
sys.path.append(os.path.join(os.path.dirname(__file__), "Core Components"))

import config


def test_all_agents():
    agents = [("admin", "admin123"), ("alpha", "alpha123"), ("bravo", "bravo123"), ("delta", "3nug-12GZIJUIMzxiFS7tg"), ("charlie", "yS2HdghQSmmApnPla4n0Xw")]

    for agent_id, password in agents:
        try:
            print(f"\n--- Testing {agent_id} ---")
            print(f"Connecting to {config.SERVER_IP}:{config.PORT}")

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((config.SERVER_IP, config.PORT))

            print("✅ Connected successfully!")

            auth_data = {"agent_id": agent_id, "password": password}

            print(f"Sending authentication data for {agent_id}...")
            sock.send(json.dumps(auth_data).encode("utf-8"))

            # Receive authentication response
            response_data = sock.recv(1024).decode("utf-8")
            response = json.loads(response_data)

            print(f"Server response: {response}")

            if response["status"] == "success":
                print("🎉 Authentication successful!")
                print(f"Clearance: {response['clearance']}")
                print(f"Session key: {response['session_key'][:10]}...")
            else:
                print("❌ Authentication failed!")
                print(f"Reason: {response.get('message', 'Unknown error')}")

            sock.close()
            print("✅ Connection closed")

        except Exception as e:
            print(f"❌ Error testing {agent_id}: {e}")


if __name__ == "__main__":
    test_all_agents()
