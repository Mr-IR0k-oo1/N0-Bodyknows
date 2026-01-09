import os
import json
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
from obfuscation_crypto import SimpleObfuscation


class CryptoEngine:
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

    def derive_key(self, password: str, salt: bytes = None) -> bytes:
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

    def encrypt_message(self, message: str, password: str = None) -> dict:
        bf_code = self.text_to_brainfuck(message)
        if password:
            key, salt = self.derive_key(password)
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(bf_code.encode())
            return {
                "encrypted_data": base64.b64encode(encrypted_data).decode(),
                "salt": base64.b64encode(salt).decode(),
                "type": "password_encrypted",
            }
        else:
            fernet = Fernet(self.master_key)
            encrypted_data = fernet.encrypt(bf_code.encode())
            return {
                "encrypted_data": base64.b64encode(encrypted_data).decode(),
                "type": "master_encrypted",
            }

    def decrypt_message(self, encrypted_package: dict, password: str = None) -> str:
        encrypted_data = base64.b64decode(encrypted_package["encrypted_data"])

        if encrypted_package["type"] == "password_encrypted":
            if not password:
                raise ValueError("Password required for decryption")
            salt = base64.b64decode(encrypted_package["salt"])
            key, _ = self.derive_key(password, salt)
            fernet = Fernet(key)
        else:
            fernet = Fernet(self.master_key)

        decrypted_bf_code = fernet.decrypt(encrypted_data).decode()
        return self.brainfuck_to_text(decrypted_bf_code)

    def generate_session_key(self) -> str:
        return secrets.token_urlsafe(32)

    def hash_password(self, password: str) -> str:
        salt = secrets.token_hex(16)
        password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 100000
        ).hex()
        return f"{salt}:{password_hash}"

    def verify_password(self, password: str, stored_hash: str) -> bool:
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

    def create_agent_keypair(self, agent_id: str) -> dict:
        agent_key = Fernet.generate_key()
        key_file = os.path.join(self.key_vault_path, f"{agent_id}.key")

        with open(key_file, "wb") as f:
            f.write(agent_key)

        return {
            "agent_id": agent_id,
            "key_file": key_file,
            "public_key": base64.b64encode(agent_key).decode(),
        }

    def brainfuck_to_text(self, bf_code: str) -> str:
        """Executes a Brainfuck program and returns the output."""
        tape = [0] * 30000
        ptr = 0
        output = ""
        i = 0
        while i < len(bf_code):
            command = bf_code[i]
            if command == ">":
                ptr += 1
            elif command == "<":
                ptr -= 1
            elif command == "+":
                tape[ptr] = (tape[ptr] + 1) % 256
            elif command == "-":
                tape[ptr] = (tape[ptr] - 1) % 256
            elif command == ".":
                output += chr(tape[ptr])
            elif command == ",":
                # Not implemented
                pass
            elif command == "[":
                if tape[ptr] == 0:
                    loop_count = 1
                    while loop_count > 0:
                        i += 1
                        if bf_code[i] == "[":
                            loop_count += 1
                        elif bf_code[i] == "]":
                            loop_count -= 1
            elif command == "]":
                if tape[ptr] != 0:
                    loop_count = 1
                    while loop_count > 0:
                        i -= 1
                        if bf_code[i] == "]":
                            loop_count += 1
                        elif bf_code[i] == "[":
                            loop_count -= 1
            i += 1
        return output

    def text_to_brainfuck(self, text: str) -> str:
        """Converts a string to a Brainfuck program."""
        bf_code = ""
        for char in text:
            ascii_val = ord(char)
            num_tens = ascii_val // 10
            num_ones = ascii_val % 10
            bf_code += ">" + ("+" * 10)
            bf_code += "[<" + ("+" * num_tens) + ">-]"
            bf_code += "<" + ("+" * num_ones) + ".[-]"
        return bf_code

    def load_agent_key(self, agent_id: str) -> bytes:
        key_file = os.path.join(self.key_vault_path, f"{agent_id}.key")
        if os.path.exists(key_file):
            with open(key_file, "rb") as f:
                return f.read()
        return None

    def encrypt_message_dual_layer(self, message: str, password: str = None) -> dict:
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

    def decrypt_message_dual_layer(
        self, encrypted_package: dict, password: str = None
    ) -> str:
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
