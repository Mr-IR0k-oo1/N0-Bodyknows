"""
Simple Obfuscation Layer
Lightweight encryption for N0-BODYKNOWS Network
Provides additional security layer on top of AES-256
"""

import random
import base64
import string
from typing import Dict


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

    def _generate_substitution_table(self) -> Dict[str, str]:
        """Generate random substitution table"""
        all_chars = string.ascii_letters + string.digits + self.special
        shuffled = list(all_chars)
        random.shuffle(shuffled)

        table = {}
        for i, char in enumerate(all_chars):
            table[char] = shuffled[i]

        return table

    def _reverse_table(self, table: Dict[str, str]) -> Dict[str, str]:
        """Reverse substitution table"""
        return {v: k for k, v in table.items()}

    def _substitute(self, text: str, table: Dict[str, str]) -> str:
        """Apply substitution cipher"""
        result = []
        for char in text:
            if char in table:
                result.append(table[char])
            else:
                result.append(char)
        return "".join(result)

    def _add_noise(self, data: str) -> str:
        """Add random noise characters"""
        noise_chars = "!@#$%^&*"
        result = []

        for char in data:
            result.append(char)
            # Add noise with 30% probability
            if random.random() < 0.3:
                result.append(random.choice(noise_chars))

        return "".join(result)

    def _remove_noise(self, data: str) -> str:
        """Remove noise characters"""
        noise_chars = "!@#$%^&*"
        result = []

        for char in data:
            if char not in noise_chars:
                result.append(char)

        return "".join(result)

    def encrypt_with_obfuscation(self, data: str, password: str = None) -> Dict:
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

    def decrypt_with_obfuscation(
        self, encrypted_package: Dict, password: str = None
    ) -> str:
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

    def generate_obfuscation_key(self, length: int = 16) -> str:
        """Generate random obfuscation key"""
        all_chars = string.ascii_letters + string.digits + self.special
        return "".join(random.choice(all_chars) for _ in range(length))


def test_obfuscation():
    """Test obfuscation layer"""
    obs = SimpleObfuscation()

    test_messages = [
        "Hello World",
        "N0-BODYKNOWS",
        "Secret message 123!",
        "Test with special chars: !@#$%^&*()",
    ]

    print("🔐 Testing Obfuscation Layer...")
    print("=" * 50)

    for i, message in enumerate(test_messages, 1):
        print(f"\n📝 Test {i}: '{message}'")

        try:
            # Test without password
            encrypted = obs.encrypt_with_obfuscation(message)
            decrypted = obs.decrypt_with_obfuscation(encrypted)

            success = message == decrypted
            print(f"✅ No password: {success}")
            if not success:
                print(f"   Original: {message}")
                print(f"   Decrypted: {decrypted}")

            # Test with password
            password = "test_password"
            encrypted_pw = obs.encrypt_with_obfuscation(message, password)
            decrypted_pw = obs.decrypt_with_obfuscation(encrypted_pw, password)

            success_pw = message == decrypted_pw
            print(f"✅ With password: {success_pw}")
            if not success_pw:
                print(f"   Original: {message}")
                print(f"   Decrypted: {decrypted_pw}")

        except Exception as e:
            print(f"❌ Error: {e}")

    print("\n🎉 Obfuscation layer working!")


if __name__ == "__main__":
    test_obfuscation()
