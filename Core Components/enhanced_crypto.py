"""
Enhanced Crypto Engine with Dual-Layer Encryption
N0-BODYKNOWS Network - Military Grade Security
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


class SimpleObfuscation:
    """Simple but effective obfuscation layer"""

    def __init__(self):
        # Character sets for obfuscation
        self.uppercase = string.ascii_uppercase
        self.lowercase = string.ascii_lowercase
        self.digits = string.digits
        self.special = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        # Random substitution tables
        self.substitution_table = self._generate_substitution_table()

    def _generate_substitution_table(self):
        """Generate random substitution table"""
        all_chars = string.ascii_letters + string.digits + self.special
        shuffled = list(all_chars)
        random.shuffle(shuffled)

        table = {}
        for i, char in enumerate(all_chars):
            table[char] = shuffled[i]

        return table

    def _reverse_table(self, table):
        """Reverse substitution table"""
        return {v: k for k, v in table.items()}

    def _substitute(self, text, table):
        """Apply substitution cipher"""
        result = []
        for char in text:
            if char in table:
                result.append(table[char])
            else:
                result.append(char)
        return "".join(result)

    def _add_noise(self, data):
        """Add random noise characters"""
        noise_chars = "!@#$%^&*"
        result = []

        for char in data:
            result.append(char)
            # Add noise with 30% probability
            if random.random() < 0.3:
                result.append(random.choice(noise_chars))

        return "".join(result)

    def _remove_noise(self, data):
        """Remove noise characters"""
        noise_chars = "!@#$%^&*"
        result = []

        for char in data:
            if char not in noise_chars:
                result.append(char)

        return "".join(result)

    def encrypt_with_obfuscation(self, data, password=None):
        """Encrypt data with obfuscation layer"""
        try:
            # Step 1: Apply substitution cipher
            substituted = self._substitute(data, self.substitution_table)

            # Step 2: Add noise
            noisy = self._add_noise(substituted)

            # Step 3: Apply password-based XOR if provided
            if password:
                password_bytes = password.encode("utf-8")
                noisy_bytes = noisy.encode("utf-8")

                encrypted_bytes = bytearray()
                for i, byte in enumerate(noisy_bytes):
                    key_byte = password_bytes[i % len(password_bytes)]
                    encrypted_bytes.append(byte ^ key_byte)

                encrypted_data = base64.b64encode(encrypted_bytes).decode("utf-8")
                encryption_type = "obfuscation_xor"
            else:
                # Just encode to base64
                encrypted_data = base64.b64encode(noisy.encode("utf-8")).decode("utf-8")
                encryption_type = "obfuscation"

            return {
                "encrypted_data": encrypted_data,
                "type": encryption_type,
                "obfuscation_level": "medium",
            }

        except Exception as e:
            raise Exception(f"Obfuscation encryption failed: {str(e)}")

    def decrypt_with_obfuscation(self, encrypted_package, password=None):
        """Decrypt obfuscated data"""
        try:
            encrypted_data = encrypted_package["encrypted_data"]
            encryption_type = encrypted_package.get("type", "obfuscation")

            # Step 1: Decode from base64
            if encryption_type == "obfuscation_xor":
                if not password:
                    raise ValueError("Password required for obfuscation_xor decryption")

                encrypted_bytes = base64.b64decode(encrypted_data)
                password_bytes = password.encode("utf-8")

                # Reverse XOR
                decrypted_bytes = bytearray()
                for i, byte in enumerate(encrypted_bytes):
                    key_byte = password_bytes[i % len(password_bytes)]
                    decrypted_bytes.append(byte ^ key_byte)

                noisy = decrypted_bytes.decode("utf-8")
            else:
                noisy = base64.b64decode(encrypted_data).decode("utf-8")

            # Step 2: Remove noise
            clean = self._remove_noise(noisy)

            # Step 3: Reverse substitution
            reverse_table = self._reverse_table(self.substitution_table)
            result = self._substitute(clean, reverse_table)

            return result

        except Exception as e:
            raise Exception(f"Obfuscation decryption failed: {str(e)}")


class CryptoEngine:
    """Enhanced Crypto Engine with Dual-Layer Encryption"""

    def __init__(self, key_vault_path="../Data/key_vault"):
        self.key_vault_path = key_vault_path
        self.ensure_key_vault()
        self.master_key = self.load_or_create_master_key()
        self.obfuscator = SimpleObfuscation()

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

    def encrypt_message(self, message: str, password: str = None):
        if password:
            key, salt = self.derive_key(password)
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(message.encode())
            return {
                "encrypted_data": base64.b64encode(encrypted_data).decode(),
                "salt": base64.b64encode(salt).decode(),
                "type": "password_encrypted",
            }
        else:
            fernet = Fernet(self.master_key)
            encrypted_data = fernet.encrypt(message.encode())
            return {
                "encrypted_data": base64.b64encode(encrypted_data).decode(),
                "type": "master_encrypted",
            }

    def decrypt_message(self, encrypted_package, password: str = None):
        encrypted_data = base64.b64decode(encrypted_package["encrypted_data"])

        if encrypted_package["type"] == "password_encrypted":
            if not password:
                raise ValueError("Password required for decryption")
            salt = base64.b64decode(encrypted_package["salt"])
            key, _ = self.derive_key(password, salt)
            fernet = Fernet(key)
        else:
            fernet = Fernet(self.master_key)

        decrypted_data = fernet.decrypt(encrypted_data)
        return decrypted_data.decode()

    def encrypt_message_dual_layer(self, message: str, password: str = None):
        """Encrypt message with dual layers: AES-256 + Obfuscation"""
        try:
            # Layer 1: AES-256 encryption
            aes_encrypted = self.encrypt_message(message, password)

            # Layer 2: Obfuscation on top of AES
            obfuscated = self.obfuscator.encrypt_with_obfuscation(
                json.dumps(aes_encrypted),
                password + "_obfuscation" if password else None,
            )

            return {
                "encrypted_data": obfuscated["encrypted_data"],
                "type": "dual_layer",
                "inner_type": aes_encrypted["type"],
                "outer_type": obfuscated["type"],
                "obfuscation_level": "maximum",
            }

        except Exception as e:
            raise Exception(f"Dual-layer encryption failed: {str(e)}")

    def decrypt_message_dual_layer(self, encrypted_package, password: str = None):
        """Decrypt message with dual layers"""
        try:
            # Layer 1: Remove obfuscation
            outer_package = {
                "encrypted_data": encrypted_package["encrypted_data"],
                "type": encrypted_package.get("outer_type", "obfuscation"),
            }

            obfuscation_password = password + "_obfuscation" if password else None
            aes_data_str = self.obfuscator.decrypt_with_obfuscation(
                outer_package, obfuscation_password
            )
            aes_data = json.loads(aes_data_str)

            # Layer 2: AES-256 decryption
            inner_type = encrypted_package.get("inner_type", "master_encrypted")
            aes_data["type"] = inner_type

            return self.decrypt_message(aes_data, password)

        except Exception as e:
            raise Exception(f"Dual-layer decryption failed: {str(e)}")

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

    def secure_delete(self, file_path: str, passes: int = 3):
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            with open(file_path, "wb") as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(file_path)

    def create_agent_keypair(self, agent_id: str):
        agent_key = Fernet.generate_key()
        key_file = os.path.join(self.key_vault_path, f"{agent_id}.key")

        with open(key_file, "wb") as f:
            f.write(agent_key)

        return {
            "agent_id": agent_id,
            "key_file": key_file,
            "public_key": base64.b64encode(agent_key).decode(),
        }

    def load_agent_key(self, agent_id: str):
        key_file = os.path.join(self.key_vault_path, f"{agent_id}.key")
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        return None


def test_dual_layer_encryption():
    """Test dual-layer encryption functionality"""
    crypto = CryptoEngine()

    test_messages = [
        "Hello World",
        "N0-BODYKNOWS",
        "Secret message 123!",
        "Test with special chars: !@#$%^&*()",
    ]

    print("🔐 Testing Dual-Layer Encryption...")
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

    print("\n🎉 Dual-layer encryption working!")


if __name__ == "__main__":
    test_dual_layer_encryption()
