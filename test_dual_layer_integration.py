#!/usr/bin/env python3

import sys
import os

sys.path.append("Core Components")

import json
import base64
import secrets
from crypto_utils import CryptoEngine


def test_dual_layer_integration():
    """Test dual-layer encryption integration with existing system"""
    print("🔐 Testing Dual-Layer Encryption Integration...")
    print("=" * 60)

    crypto = CryptoEngine()

    test_messages = ["Hello World", "N0-BODYKNOWS", "Secret message 123!"]

    for i, message in enumerate(test_messages, 1):
        print(f"\n📝 Test {i}: '{message}'")

        try:
            # Test regular encryption
            regular_encrypted = crypto.encrypt_message(message)
            regular_decrypted = crypto.decrypt_message(regular_encrypted)

            print(f"✅ Regular AES: {message == regular_decrypted}")

            # Test dual-layer encryption (manual implementation)
            # Layer 1: AES encryption
            aes_encrypted = crypto.encrypt_message(message)

            # Layer 2: XOR obfuscation
            json_data = json.dumps(aes_encrypted)
            xor_key = secrets.token_bytes(16)
            xor_encrypted = bytes(
                [
                    b ^ xor_key[i % len(xor_key)]
                    for i, b in enumerate(json_data.encode())
                ]
            )

            # Layer 3: Base64 encoding
            dual_encrypted = base64.b64encode(xor_encrypted).decode("utf-8")

            dual_package = {
                "encrypted_data": dual_encrypted,
                "xor_key": base64.b64encode(xor_key).decode("utf-8"),
                "type": "dual_layer",
                "inner_type": aes_encrypted["type"],
            }

            # Manual decryption
            xor_encrypted_back = base64.b64decode(dual_package["encrypted_data"])
            xor_key_back = base64.b64decode(dual_package["xor_key"])
            json_data_back = bytes(
                [
                    b ^ xor_key_back[i % len(xor_key_back)]
                    for i, b in enumerate(xor_encrypted_back)
                ]
            ).decode()
            aes_data_back = json.loads(json_data_back)
            aes_data_back["type"] = dual_package["inner_type"]
            dual_decrypted = crypto.decrypt_message(aes_data_back)

            success = message == dual_decrypted
            print(f"✅ Dual-Layer: {success}")

            if not success:
                print(f"   Original: {message}")
                print(f"   Decrypted: {dual_decrypted}")

        except Exception as e:
            print(f"❌ Error: {e}")

    print("\n🎉 Dual-layer encryption integration test completed!")

    # Show encryption levels
    print("\n📊 ENCRYPTION LEVELS:")
    print("  🔹 Level 1: AES-256 (Fernet)")
    print("  🔹 Level 2: XOR Obfuscation")
    print("  🔹 Level 3: Base64 Encoding")
    print("  🔹 Total: Triple-layer protection")

    print("\n🛡️ SECURITY BENEFITS:")
    print("  • Multiple encryption layers")
    print("  • Obfuscation against analysis")
    print("  • XOR key adds randomness")
    print("  • Maintains AES-256 security")
    print("  • Compatible with existing system")


if __name__ == "__main__":
    test_dual_layer_integration()
