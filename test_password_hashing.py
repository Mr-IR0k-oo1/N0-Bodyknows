#!/usr/bin/env python3

import sys
import os

sys.path.append("Core Components")

import config
from crypto_utils import CryptoEngine


def test_password_hashing():
    crypto = CryptoEngine()

    print("Testing password hashing and verification:")

    # Test with default passwords
    passwords = ["admin123", "alpha123", "bravo123"]

    for password in passwords:
        # Create hash like server does
        stored_hash = crypto.hash_password(password)
        print(f"\nPassword: {password}")
        print(f"Generated hash: {stored_hash}")

        # Test verification
        verified = crypto.verify_password(password, stored_hash)
        print(f"Verification result: {verified}")

    # Test against existing database hashes
    print("\n" + "=" * 50)
    print("Testing against existing database hashes:")

    existing_hashes = {
        "admin123": "98b27f9b5441110cbaeb0a5d84199135:75f6c242f0139ee45b3d2a4d9cdfa523dd4e4ebaf6a563d8b52bfc5307729e55",
        "alpha123": "db4459959a1160fd8b1546c92ed68b86:342faed844c690167c6dbfa5360c7db527d9c6aaba33374b78b91971f21fcd69",
        "bravo123": "db991b83019391331fd769b9b2738def:1e32effe86918a794a7329d5b6f3c1b66a486ca135786b762857211fb18e6b6b",
    }

    for password, hash_value in existing_hashes.items():
        verified = crypto.verify_password(password, hash_value)
        print(f"Password: {password} -> Verified: {verified}")


if __name__ == "__main__":
    test_password_hashing()
