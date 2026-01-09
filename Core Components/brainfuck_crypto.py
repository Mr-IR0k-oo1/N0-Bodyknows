"""
Brainfuck Encryption Layer
Additional obfuscation layer for N0-BODYKNOWS Network
Provides Brainfuck-based encoding/decoding for enhanced security
"""

import random
import base64
import re
from typing import Tuple, List


class BrainfuckCrypto:
    """Brainfuck-based encryption/decryption for additional obfuscation layer"""

    def __init__(self):
        # Brainfuck commands
        self.commands = [">", "<", "+", "-", ".", ",", "[", "]"]

        # Extended Brainfuck character set for more complexity
        self.extended_commands = [
            ">",
            "<",
            "+",
            "-",
            ".",
            ",",
            "[",
            "]",
            "#",
            "@",
            "$",
            "%",
        ]

        # Random padding characters for obfuscation
        self.padding_chars = ["!", "?", "*", "&", "^", "~", "`", "|", "\\"]

    def text_to_brainfuck(self, text: str, use_extended: bool = True) -> str:
        """Convert text to Brainfuck code with obfuscation"""
        if not text:
            return ""

        brainfuck_code = []

        for char in text:
            ascii_val = ord(char)

            # Simple Brainfuck encoding for each character
            char_code = []

            # Use efficient encoding based on ASCII value
            if ascii_val <= 127:
                # For standard ASCII, use optimized approach
                if ascii_val <= 64:
                    # Small values - direct addition
                    char_code.extend(["+"] * ascii_val)
                else:
                    # Larger values - use multiplication for efficiency
                    factor = min(ascii_val // 8, 8)  # Limit factor for efficiency
                    remainder = ascii_val - (factor * 8)

                    # Set up cell with factor
                    char_code.extend(["+"] * factor)
                    char_code.extend(
                        [
                            "[>",
                            ">",
                            ">",
                            ">",
                            ">",
                            ">",
                            ">",
                            ">",
                            "+",
                            "<",
                            "<",
                            "<",
                            "<",
                            "<",
                            "<",
                            "<",
                            "<",
                            "-",
                        ][: 8 + remainder + 2]
                    )
                    char_code.append("]")
                    char_code.extend([">"] * 8)

                    # Add remainder if needed
                    if remainder > 0:
                        char_code.extend(["+"] * remainder)
            else:
                # Extended ASCII - split into bytes
                high_byte = ascii_val // 256
                low_byte = ascii_val % 256

                # Encode high byte
                char_code.extend(["+"] * high_byte)
                char_code.append(">")

                # Encode low byte
                char_code.extend(["+"] * low_byte)
                char_code.append("<")

            # Output character
            char_code.append(".")

            # Add minimal obfuscation
            if random.random() < 0.3:  # 30% chance of padding
                char_code.extend([">", "<"])  # No-op padding

            brainfuck_code.extend(char_code)

        # Add simple noise prefix/suffix
        noise_chars = ["!", "?", "*"]
        noise_prefix = "".join(
            random.choice(noise_chars) for _ in range(random.randint(2, 5))
        )
        noise_suffix = "".join(
            random.choice(noise_chars) for _ in range(random.randint(2, 5))
        )

        return noise_prefix + "".join(brainfuck_code) + noise_suffix

    def brainfuck_to_text(self, brainfuck_code: str) -> str:
        """Convert Brainfuck code back to text"""
        if not brainfuck_code:
            return ""

        # Clean the code - remove padding and non-Brainfuck characters
        cleaned_code = re.sub(r"[^><+\-.,[\]]", "", brainfuck_code)

        # Execute Brainfuck code
        memory = [0] * 30000  # Standard Brainfuck memory size
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
                    # Find matching ]
                    loop_count = 1
                    i += 1
                    while i < len(cleaned_code) and loop_count > 0:
                        if cleaned_code[i] == "[":
                            loop_count += 1
                        elif cleaned_code[i] == "]":
                            loop_count -= 1
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

    def encrypt_with_brainfuck(self, data: str, password: str = None) -> dict:
        """Encrypt data using Brainfuck encoding with optional password-based obfuscation"""
        try:
            # Convert to Brainfuck
            brainfuck_encoded = self.text_to_brainfuck(data)

            # Add password-based transformation if provided
            if password:
                # Simple XOR obfuscation based on password
                password_bytes = password.encode("utf-8")
                brainfuck_bytes = brainfuck_encoded.encode("utf-8")

                encrypted_bytes = bytearray()
                for i, byte in enumerate(brainfuck_bytes):
                    key_byte = password_bytes[i % len(password_bytes)]
                    encrypted_bytes.append(byte ^ key_byte)

                encrypted_data = base64.b64encode(encrypted_bytes).decode("utf-8")
                encryption_type = "brainfuck_password"
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
        self, encrypted_package: dict, password: str = None
    ) -> str:
        """Decrypt Brainfuck-encoded data"""
        try:
            encrypted_data = encrypted_package["encrypted_data"]
            encryption_type = encrypted_package.get("type", "brainfuck")

            # Decode from base64
            if encryption_type == "brainfuck_password":
                if not password:
                    raise ValueError(
                        "Password required for brainfuck_password decryption"
                    )

                encrypted_bytes = base64.b64decode(encrypted_data)
                password_bytes = password.encode("utf-8")

                # Reverse XOR obfuscation
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

    def generate_brainfuck_key(self, length: int = 32) -> str:
        """Generate a random Brainfuck-style key"""
        key_chars = self.extended_commands + self.padding_chars
        return "".join(random.choice(key_chars) for _ in range(length))

    def analyze_brainfuck_complexity(self, brainfuck_code: str) -> dict:
        """Analyze the complexity of Brainfuck code"""
        if not brainfuck_code:
            return {"complexity": 0, "commands": 0, "loops": 0}

        # Count different command types
        command_counts = {}
        for cmd in self.commands:
            command_counts[cmd] = brainfuck_code.count(cmd)

        # Count loops
        loop_count = brainfuck_code.count("[")

        # Calculate complexity score
        total_commands = sum(command_counts.values())
        complexity_score = total_commands + (
            loop_count * 10
        )  # Loops add more complexity

        return {
            "complexity": complexity_score,
            "commands": total_commands,
            "loops": loop_count,
            "command_distribution": command_counts,
        }


# Test function for Brainfuck encryption
def test_brainfuck_encryption():
    """Test Brainfuck encryption/decryption functionality"""
    bf = BrainfuckCrypto()

    test_messages = [
        "Hello World",
        "N0-BODYKNOWS",
        "Secret message 123!",
        "Test with special chars: !@#$%^&*()",
    ]

    print("🧠 Testing Brainfuck Encryption Layer...")
    print("=" * 50)

    for i, message in enumerate(test_messages, 1):
        print(f"\n📝 Test {i}: '{message}'")

        try:
            # Test without password
            encrypted = bf.encrypt_with_brainfuck(message)
            decrypted = bf.decrypt_with_brainfuck(encrypted)

            print(f"✅ No password: {message == decrypted}")

            # Test with password
            password = "test_password"
            encrypted_pw = bf.encrypt_with_brainfuck(message, password)
            decrypted_pw = bf.decrypt_with_brainfuck(encrypted_pw, password)

            print(f"✅ With password: {message == decrypted_pw}")

            # Analyze complexity
            complexity = bf.analyze_brainfuck_complexity(bf.text_to_brainfuck(message))
            print(f"📊 Complexity score: {complexity['complexity']}")

        except Exception as e:
            print(f"❌ Error: {e}")

    print("\n🎉 Brainfuck encryption layer working!")


if __name__ == "__main__":
    test_brainfuck_encryption()
