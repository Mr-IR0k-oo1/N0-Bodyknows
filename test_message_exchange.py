#!/usr/bin/env python3

import sys
import json
import socket
import threading
import time
import os

# Add Core Components to path
sys.path.append(os.path.join(os.path.dirname(__file__), "Core Components"))

import config
from crypto_utils import CryptoEngine


class TestClient:
    def __init__(self, agent_id, password):
        self.agent_id = agent_id
        self.password = password
        self.socket = None
        self.crypto = CryptoEngine()
        self.running = False
        self.messages = []

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((config.SERVER_IP, config.PORT))

            # Authenticate
            auth_data = {"agent_id": self.agent_id, "password": self.password}
            self.socket.send(json.dumps(auth_data).encode("utf-8"))

            # Receive authentication response
            response_data = self.socket.recv(1024).decode("utf-8")
            response = json.loads(response_data)

            if response["status"] == "success":
                print(f"✅ {self.agent_id} authenticated successfully!")
                self.session_key = response["session_key"]
                self.clearance = response["clearance"]
                self.running = True
                return True
            else:
                print(
                    f"❌ {self.agent_id} authentication failed: {response.get('message')}"
                )
                return False

        except Exception as e:
            print(f"❌ {self.agent_id} connection error: {e}")
            return False

    def receive_messages(self):
        while self.running:
            try:
                encrypted_data = self.socket.recv(4096).decode("utf-8")
                if not encrypted_data:
                    break

                message_data = json.loads(encrypted_data)
                message = self.crypto.decrypt_message(message_data)

                timestamp = time.strftime("%H:%M:%S")
                print(f"[{timestamp}] {self.agent_id} received: {message}")
                self.messages.append(message)

            except Exception as e:
                if self.running:
                    print(f"❌ {self.agent_id} receive error: {e}")
                break

    def send_message(self, message):
        try:
            encrypted = self.crypto.encrypt_message(message)
            self.socket.send(json.dumps(encrypted).encode("utf-8"))
            print(f"📤 {self.agent_id} sent: {message}")
        except Exception as e:
            print(f"❌ {self.agent_id} send error: {e}")

    def disconnect(self):
        self.running = False
        if self.socket:
            self.socket.close()
        print(f"🔌 {self.agent_id} disconnected")


def test_message_exchange():
    print("🚀 Testing message exchange between agents...")

    # Create test clients
    alpha_client = TestClient("alpha", "alpha123")
    bravo_client = TestClient("bravo", "bravo123")

    # Connect both clients
    if not alpha_client.connect():
        return False
    if not bravo_client.connect():
        alpha_client.disconnect()
        return False

    # Start receiver threads
    alpha_thread = threading.Thread(target=alpha_client.receive_messages, daemon=True)
    bravo_thread = threading.Thread(target=bravo_client.receive_messages, daemon=True)

    alpha_thread.start()
    bravo_thread.start()

    # Wait for threads to be ready
    time.sleep(1)

    # Test messages
    print("\n📝 Testing message exchange...")

    # Alpha sends a message
    alpha_client.send_message("Hello from Alpha!")
    time.sleep(1)

    # Bravo sends a message
    bravo_client.send_message("Hello from Bravo!")
    time.sleep(1)

    # Alpha sends a secure message to Bravo
    alpha_client.send_message("/secure bravo This is a secure message from Alpha")
    time.sleep(1)

    # Bravo sends a priority message
    bravo_client.send_message(
        "/priority high This is a high priority message from Bravo"
    )
    time.sleep(1)

    # Wait for all messages to be processed
    time.sleep(2)

    # Disconnect clients
    alpha_client.disconnect()
    bravo_client.disconnect()

    print("\n✅ Message exchange test completed!")
    return True


if __name__ == "__main__":
    test_message_exchange()
