#!/usr/bin/env python3

import sys
import json
import socket
import os

# Add Core Components to path
sys.path.append(os.path.join(os.path.dirname(__file__), "Core Components"))

import config


def test_bravo_auth():
    try:
        print(f"Connecting to {config.SERVER_IP}:{config.PORT}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((config.SERVER_IP, config.PORT))

        print("✅ Connected successfully!")

        agent_id = "bravo"
        # Use the known correct password
        password = "bravo123"

        auth_data = {"agent_id": agent_id, "password": password}

        print(
            f"Sending authentication data for {agent_id} with password '{password}'..."
        )
        auth_data_json = json.dumps(auth_data)
        message_length = len(auth_data_json).to_bytes(4, "big")
        sock.send(message_length + auth_data_json.encode("utf-8"))

        # Receive authentication response
        message_length_bytes = sock.recv(4)
        if not message_length_bytes:
            print("❌ No response from server")
            sock.close()
            return
        message_length = int.from_bytes(message_length_bytes, "big")

        response_data = b""
        while len(response_data) < message_length:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response_data += chunk

        response = json.loads(response_data.decode("utf-8"))

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
        print(f"❌ Error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    test_bravo_auth()
