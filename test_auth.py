#!/usr/bin/env python3

import sys
import json
import socket
import os

# Add Core Components to path
sys.path.append(os.path.join(os.path.dirname(__file__), "Core Components"))

from crypto_utils import CryptoEngine


def test_authentication():
    try:
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("localhost", 9999))

        # Test with the default password from server.py
        agent_id = "alpha"
        password = "alpha123"

        auth_data = {"agent_id": agent_id, "password": password}

        print(f"Testing authentication for {agent_id} with password '{password}'")
        auth_data_json = json.dumps(auth_data)
        message_length = len(auth_data_json).to_bytes(4, "big")
        sock.send(message_length + auth_data_json.encode("utf-8"))

        # Receive response
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
            print("✅ Authentication successful!")
        else:
            print("❌ Authentication failed!")

        sock.close()

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    test_authentication()
