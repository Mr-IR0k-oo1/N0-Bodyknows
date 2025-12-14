"""
Unit Tests for N0-BODYKNOWS Core Components
Tests cryptographic utilities and core functionality
"""

import unittest
import tempfile
import shutil
import os
import json
import sys

# Add the path to import core components
sys.path.append(os.path.join(os.path.dirname(__file__), 'N0-Bodyknows', 'Core Components'))

try:
    from crypto_utils import CryptoEngine
except ImportError:
    print("❌ Cannot import crypto_utils. Please ensure you're running from the correct directory.")
    sys.exit(1)


class TestCryptoEngine(unittest.TestCase):
    """Test cryptographic engine functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.crypto = CryptoEngine(key_vault_path=os.path.join(self.test_dir, 'test_vault'))
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
        
    def test_password_hashing(self):
        """Test password hashing and verification"""
        password = "test_password_123"
        hashed = self.crypto.hash_password(password)
        
        # Verify hash format
        self.assertIn(':', hashed)
        self.assertEqual(len(hashed.split(':')), 2)
        
        # Test verification
        self.assertTrue(self.crypto.verify_password(password, hashed))
        self.assertFalse(self.crypto.verify_password("wrong_password", hashed))
        
    def test_message_encryption(self):
        """Test message encryption and decryption"""
        message = "This is a secret message"
        encrypted = self.crypto.encrypt_message(message)
        decrypted = self.crypto.decrypt_message(encrypted)
        
        self.assertEqual(message, decrypted)
        self.assertNotEqual(message, encrypted['encrypted_data'])
        
    def test_password_encryption(self):
        """Test password-based encryption"""
        message = "Secret data with password"
        password = "encryption_password"
        
        encrypted = self.crypto.encrypt_message(message, password)
        decrypted = self.crypto.decrypt_message(encrypted, password)
        
        self.assertEqual(message, decrypted)
        
        # Test that wrong password fails
        with self.assertRaises(Exception):
            self.crypto.decrypt_message(encrypted, "wrong_password")
            
    def test_key_derivation(self):
        """Test key derivation from password"""
        password = "test_key_derivation"
        key1, salt1 = self.crypto.derive_key(password)
        key2, salt2 = self.crypto.derive_key(password)
        
        # Same password should generate same key if same salt provided
        key3, _ = self.crypto.derive_key(password, salt1)
        
        self.assertEqual(key1, key3)
        self.assertNotEqual(key1, key2)  # Different salts should produce different keys
        
    def test_agent_keypair_creation(self):
        """Test agent key pair generation"""
        agent_id = "test_agent"
        keypair = self.crypto.create_agent_keypair(agent_id)
        
        self.assertIn('key_file', keypair)
        self.assertIn('public_key', keypair)
        self.assertTrue(os.path.exists(keypair['key_file']))


class TestAuthentication(unittest.TestCase):
    """Test authentication functionality"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.crypto = CryptoEngine(key_vault_path=os.path.join(self.test_dir, 'test_vault'))
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
        
    def test_agent_database_structure(self):
        """Test agent database structure and validation"""
        # Create test agent data
        agent_data = {
            "password_hash": self.crypto.hash_password("test_password"),
            "clearance": "operative",
            "active": True,
            "created": "2024-01-01T00:00:00"
        }
        
        # Verify structure
        self.assertIn('password_hash', agent_data)
        self.assertIn('clearance', agent_data)
        self.assertIn('active', agent_data)
        self.assertIn('created', agent_data)
        
        # Test password verification
        self.assertTrue(self.crypto.verify_password("test_password", agent_data['password_hash']))


class TestMessageHandling(unittest.TestCase):
    """Test message handling and formatting"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.crypto = CryptoEngine(key_vault_path=os.path.join(self.test_dir, 'test_vault'))
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir)
        
    def test_message_structure(self):
        """Test message structure validation"""
        message = {
            "type": "message",
            "sender": "test_agent",
            "recipient": "recipient_agent",
            "content": "Test message content",
            "timestamp": "2024-01-01T12:00:00",
            "priority": "normal"
        }
        
        # Verify required fields
        required_fields = ['type', 'sender', 'recipient', 'content', 'timestamp', 'priority']
        for field in required_fields:
            self.assertIn(field, message)
            
    def test_encrypted_message_structure(self):
        """Test encrypted message structure"""
        original_message = "Secret test message"
        
        # Test master key encryption
        encrypted_master = self.crypto.encrypt_message(original_message)
        self.assertIn('encrypted_data', encrypted_master)
        self.assertIn('type', encrypted_master)
        self.assertEqual(encrypted_master['type'], 'master_encrypted')
        
        # Test password encryption
        encrypted_password = self.crypto.encrypt_message(original_message, "test_password")
        self.assertIn('encrypted_data', encrypted_password)
        self.assertIn('salt', encrypted_password)
        self.assertIn('type', encrypted_password)
        self.assertEqual(encrypted_password['type'], 'password_encrypted')


if __name__ == '__main__':
    print("🧪 Running N0-BODYKNOWS Unit Tests...")
    print("=" * 50)
    
    # Run tests
    unittest.main(verbosity=2)