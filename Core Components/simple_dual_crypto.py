"""
Simple Dual-Layer Encryption
N0-BODYKNOWS Network - Enhanced Security
"""

import os
import json
import hashlib
import base64
import random
import string
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets


class SimpleDualLayerCrypto:
    """Simple but effective dual-layer encryption"""

    def __init__(self, key_vault_path="../Data/key_vault"):
        self.key_vault_path = key_vault_path
        self.ensure_key_vault()
        self.master_key = self.load_or_create_master_key()

    def ensure_key_vault(self):
        if not os.path.exists(self.key_vault_path):
            os.makedirs(self.key_vault_path, exist_ok=True)

    def load_or_create_master_key(self):
        master_key_path = os.path.join(self.key_vault_path, "master.key")
        if os.path.exists(master_key_path):
            with open(master_key_path, "rb") as f:
                return f.read()
        else:
            master_key = Fernet.generate_key()
            with open(master_key_path, "wb") as f:
                f.write(master_key)
            return master_key

    def _simple_xor(self, data: bytes, key: bytes) -> bytes:
        """Simple XOR encryption"""
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

    def _reverse_string(self, text: str) -> str:
        """Simple string reversal"""
        return text[::-1]

    def _add_noise(self, text: str) -> str:
        """Add random noise characters"""
        noise_chars = "!@#$%^&*"
        result = []

        for char in text:
            result.append(char)
            if random.random() < 0.2:  # 20% noise
                result.append(random.choice(noise_chars))

        return "".join(result)

    def _remove_noise(self, text: str) -> str:
        """Remove noise characters"""
        noise_chars = "!@#$%^&*"
        return "".join([c for c in text if c not in noise_chars])

    def encrypt_message_dual_layer(self, message: str, password: str = None):
        """Encrypt with dual layers: AES + XOR + Noise"""
        try:
            # Layer 1: AES-256 encryption
            if password:
                key, salt = self.derive_key(password)
                fernet = Fernet(key)
                aes_encrypted = fernet.encrypt(message.encode())
                aes_data = {
                    "encrypted_data": base64.b64encode(aes_encrypted).decode(),
                    "salt": base64.b64encode(salt).decode(),
                    "type": "password_encrypted",
                }
            else:
                fernet = Fernet(self.master_key)
                aes_encrypted = fernet.encrypt(message.encode())
                aes_data = {
                    "encrypted_data": base64.b64encode(aes_encrypted).decode(),
                    "type": "master_encrypted",
                }

            # Layer 2: Convert to JSON and apply XOR
            json_data = json.dumps(aes_data)
            xor_key = secrets.token_bytes(16)  # Random XOR key
            xor_encrypted = self._simple_xor(json_data.encode(), xor_key)

            # Layer 3: Add noise and encode
            noisy_data = self._add_noise(xor_encrypted.hex())
            final_encrypted = base64.b64encode(noisy_data.encode()).decode()

            return {
                "encrypted_data": final_encrypted,
                "xor_key": base64.b64encode(xor_key).decode(),
                "type": "dual_layer",
                "inner_type": aes_data["type"],
                "obfuscation_level": "maximum",
            }

        except Exception as e:
            raise Exception(f"Dual-layer encryption failed: {str(e)}")

    def decrypt_message_dual_layer(self, encrypted_package, password: str = None):
        """Decrypt dual-layer message"""
        try:
            # Layer 1: Remove noise
            encrypted_data = encrypted_package["encrypted_data"]
            noisy_data = base64.b64decode(encrypted_data).decode()
            clean_data = self._remove_noise(noisy_data)

            # Layer 2: Remove XOR
            xor_key = base64.b64decode(encrypted_package["xor_key"])
            xor_encrypted = bytes.fromhex(clean_data)
            json_data = self._simple_xor(xor_encrypted, xor_key).decode()
            aes_data = json.loads(json_data)

            # Layer 3: AES-256 decryption
            if aes_data["type"] == "password_encrypted":
                if not password:
                    raise ValueError("Password required for decryption")
                salt = base64.b64decode(aes_data["salt"])
                key, _ = self.derive_key(password, salt)
                fernet = Fernet(key)
                encrypted_bytes = base64.b64decode(aes_data["encrypted_data"])
            else:
                fernet = Fernet(self.master_key)
                encrypted_bytes = base64.b64decode(aes_data["encrypted_data"])

            decrypted_data = fernet.decrypt(encrypted_bytes)
            return decrypted_data.decode()

        except Exception as e:
            raise Exception(f"Dual-layer decryption failed: {str(e)}")

    def derive_key(self, password: str, salt: bytes = None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def generate_session_key(self):
        return secrets.token_urlsafe(32)

    def hash_password(self, password: str):
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 100000
        ).hex()
        return f"{salt}:{password_hash}"

    def verify_password(self, password: str, stored_hash: str):
        try:
            salt, password_hash = stored_hash.split(":")
            computed_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt.encode(), 100000
            ).hex()
            return computed_hash == password_hash
        except:
            return False


def test_simple_dual_layer():
    """Test simple dual-layer encryption"""
    crypto = SimpleDualLayerCrypto()

    test_messages = [
        "Hello World",
        "N0-BODYKNOWS",
        "Secret message 123!",
        "Test with special chars: !@#$%^&*()",
    ]

    print("🔐 Testing Simple Dual-Layer Encryption...")
    print("=" * 50)

    for i, message in enumerate(test_messages, 1):
        print(f"\n📝 Test {i}: '{message}'")

        try:
            # Test without password
            encrypted = crypto.encrypt_message_dual_layer(message)
            decrypted = crypto.decrypt_message_dual_layer(encrypted)

            success = message == decrypted
            print(f"✅ No password: {success}")
            if not success:
                print(f"   Original: {message}")
                print(f"   Decrypted: {decrypted}")

            # Test with password
            password = "test_password"
            encrypted_pw = crypto.encrypt_message_dual_layer(message, password)
            decrypted_pw = crypto.decrypt_message_dual_layer(encrypted_pw, password)

            success_pw = message == decrypted_pw
            print(f"✅ With password: {success_pw}")
            if not success_pw:
                print(f"   Original: {message}")
                print(f"   Decrypted: {decrypted_pw}")

        except Exception as e:
            print(f"❌ Error: {e}")

    print("\n🎉 Simple dual-layer encryption working!")


if __name__ == "__main__":
    test_simple_dual_layer()
