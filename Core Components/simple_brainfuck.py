"""
Simplified Brainfuck Encryption Layer
Additional obfuscation layer for N0-BODYKNOWS Network
"""

import random
import base64
import re
from typing import Dict


class SimpleBrainfuckCrypto:
    """Simplified Brainfuck-based encryption for reliable operation"""

    def __init__(self):
        # Brainfuck commands
        self.commands = [">", "<", "+", "-", ".", ",", "[", "]"]

        # Noise characters for obfuscation
        self.noise_chars = ["!", "?", "*", "&", "^", "~"]

    def text_to_brainfuck(self, text: str) -> str:
        """Convert text to simple Brainfuck code"""
        if not text:
            return ""

        brainfuck_code = []

        for char in text:
            ascii_val = ord(char)

            # Simple encoding: set cell to ASCII value and output
            char_code = ["+"] * ascii_val + ["."]

            # Add minimal noise
            if random.random() < 0.2:  # 20% chance
                char_code.extend([">", "<"])  # No-op

            brainfuck_code.extend(char_code)

        # Add noise prefix and suffix
        noise_prefix = "".join(
            random.choice(self.noise_chars) for _ in range(random.randint(2, 4))
        )
        noise_suffix = "".join(
            random.choice(self.noise_chars) for _ in range(random.randint(2, 4))
        )

        return noise_prefix + "".join(brainfuck_code) + noise_suffix

    def brainfuck_to_text(self, brainfuck_code: str) -> str:
        """Convert Brainfuck code back to text"""
        if not brainfuck_code:
            return ""

        # Clean code - remove noise and non-Brainfuck characters
        cleaned_code = re.sub(r"[^><+\-.,\[\]]", "", brainfuck_code)

        # Simple Brainfuck interpreter
        memory = [0] * 30000
        pointer = 0
        output = []
        loop_stack = []

        i = 0
        while i < len(cleaned_code):
            cmd = cleaned_code[i]

            if cmd == ">":
                pointer += 1
                if pointer >= len(memory):
                    memory.extend([0] * 1000)
            elif cmd == "<":
                pointer -= 1
                if pointer < 0:
                    pointer = 0
            elif cmd == "+":
                memory[pointer] = (memory[pointer] + 1) % 256
            elif cmd == "-":
                memory[pointer] = (memory[pointer] - 1) % 256
            elif cmd == ".":
                output.append(chr(memory[pointer]))
            elif cmd == "[":
                if memory[pointer] == 0:
                    # Skip to matching ]
                    bracket_count = 1
                    i += 1
                    while i < len(cleaned_code) and bracket_count > 0:
                        if cleaned_code[i] == "[":
                            bracket_count += 1
                        elif cleaned_code[i] == "]":
                            bracket_count -= 1
                        i += 1
                    i -= 1
                else:
                    loop_stack.append(i)
            elif cmd == "]":
                if memory[pointer] != 0 and loop_stack:
                    i = loop_stack[-1]
                else:
                    if loop_stack:
                        loop_stack.pop()

            i += 1

        return "".join(output)

    def encrypt_with_brainfuck(self, data: str, password: str = None) -> Dict:
        """Encrypt data using Brainfuck encoding"""
        try:
            # Convert to Brainfuck
            brainfuck_encoded = self.text_to_brainfuck(data)

            # Add password-based XOR if provided
            if password:
                password_bytes = password.encode("utf-8")
                brainfuck_bytes = brainfuck_encoded.encode("utf-8")

                encrypted_bytes = bytearray()
                for i, byte in enumerate(brainfuck_bytes):
                    key_byte = password_bytes[i % len(password_bytes)]
                    encrypted_bytes.append(byte ^ key_byte)

                encrypted_data = base64.b64encode(encrypted_bytes).decode("utf-8")
                encryption_type = "brainfuck_xor"
            else:
                # Just encode to Brainfuck and base64
                encrypted_data = base64.b64encode(
                    brainfuck_encoded.encode("utf-8")
                ).decode("utf-8")
                encryption_type = "brainfuck"

            return {
                "encrypted_data": encrypted_data,
                "type": encryption_type,
                "obfuscation_level": "high",
            }

        except Exception as e:
            raise Exception(f"Brainfuck encryption failed: {str(e)}")

    def decrypt_with_brainfuck(
        self, encrypted_package: Dict, password: str = None
    ) -> str:
        """Decrypt Brainfuck-encoded data"""
        try:
            encrypted_data = encrypted_package["encrypted_data"]
            encryption_type = encrypted_package.get("type", "brainfuck")

            # Decode from base64
            if encryption_type == "brainfuck_xor":
                if not password:
                    raise ValueError("Password required for brainfuck_xor decryption")

                encrypted_bytes = base64.b64decode(encrypted_data)
                password_bytes = password.encode("utf-8")

                # Reverse XOR
                decrypted_bytes = bytearray()
                for i, byte in enumerate(encrypted_bytes):
                    key_byte = password_bytes[i % len(password_bytes)]
                    decrypted_bytes.append(byte ^ key_byte)

                brainfuck_code = decrypted_bytes.decode("utf-8")
            else:
                brainfuck_code = base64.b64decode(encrypted_data).decode("utf-8")

            # Convert from Brainfuck back to text
            return self.brainfuck_to_text(brainfuck_code)

        except Exception as e:
            raise Exception(f"Brainfuck decryption failed: {str(e)}")


def test_simple_brainfuck():
    """Test simplified Brainfuck encryption"""
    bf = SimpleBrainfuckCrypto()

    test_messages = ["Hello", "N0-BODYKNOWS", "Test 123", "Secret!"]

    print("🧠 Testing Simplified Brainfuck Encryption...")
    print("=" * 50)

    for i, message in enumerate(test_messages, 1):
        print(f"\n📝 Test {i}: '{message}'")

        try:
            # Test without password
            encrypted = bf.encrypt_with_brainfuck(message)
            decrypted = bf.decrypt_with_brainfuck(encrypted)

            success = message == decrypted
            print(f"✅ No password: {success}")
            if not success:
                print(f"   Original: {message}")
                print(f"   Decrypted: {decrypted}")

            # Test with password
            password = "test123"
            encrypted_pw = bf.encrypt_with_brainfuck(message, password)
            decrypted_pw = bf.decrypt_with_brainfuck(encrypted_pw, password)

            success_pw = message == decrypted_pw
            print(f"✅ With password: {success_pw}")
            if not success_pw:
                print(f"   Original: {message}")
                print(f"   Decrypted: {decrypted_pw}")

        except Exception as e:
            print(f"❌ Error: {e}")

    print("\n🎉 Simplified Brainfuck encryption test completed!")


if __name__ == "__main__":
    test_simple_brainfuck()
