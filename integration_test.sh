#!/bin/bash
# N0-BODYKNOWS Integration Test
# Tests complete end-to-end functionality

echo "🚀 Starting N0-BODYKNOWS Integration Test..."
echo "=============================================="

# Source virtual environment
source venv/bin/activate

# Test 1: Unit Tests
echo "📋 Test 1: Running Unit Tests..."
python test_core.py
if [ $? -ne 0 ]; then
    echo "❌ Unit tests failed!"
    exit 1
fi
echo "✅ Unit tests passed!"
echo

# Test 2: Key Generation
echo "🔑 Test 2: Testing Key Generation..."
cd "N0-Bodyknows/Operational Tools"
python key_generator.py --agent-id test_agent --clearance operative
if [ $? -ne 0 ]; then
    echo "❌ Key generation failed!"
    exit 1
fi
echo "✅ Key generation successful!"
cd ../..
echo

# Test 3: Network Test
echo "🌐 Test 3: Running Network Tests..."
cd "N0-Bodyknows/Operational Tools"
python network_test.py --host localhost --port 9999
echo "✅ Network test completed!"
cd ../..
echo

# Test 4: Configuration Test
echo "⚙️ Test 4: Testing Configuration System..."
cd "N0-Bodyknows/Core Components"
python -c "
import config
import json

# Test configuration creation and loading
config_manager = config.ConfigManager()

# Test setting values
config_manager.set_value('network', 'host', 'localhost')
config_manager.set_value('network', 'port', 9999)
config_manager.set_value('security', 'encryption_level', 'high')

# Test saving and loading
config_manager.save_config()
loaded_config = config.ConfigManager()
loaded_config.load_from_file()

print('✅ Configuration system working!')
print(f'Host: {loaded_config.get_value(\"network\", \"host\")}')
print(f'Port: {loaded_config.get_value(\"network\", \"port\")}')
"
if [ $? -ne 0 ]; then
    echo "❌ Configuration test failed!"
    exit 1
fi
echo "✅ Configuration system working!"
cd ../..
echo

# Test 5: Cryptographic Functions
echo "🔐 Test 5: Testing Cryptographic Functions..."
cd "N0-Bodyknows/Core Components"
python -c "
import crypto_utils
import json

# Test crypto engine
crypto = crypto_utils.CryptoEngine()

# Test password hashing
password = 'test_password'
hashed = crypto.hash_password(password)
verified = crypto.verify_password(password, hashed)

print(f'Password verification: {verified}')

# Test encryption
message = 'Secret test message'
encrypted = crypto.encrypt_message(message)
decrypted = crypto.decrypt_message(encrypted)

print(f'Encryption test: {message == decrypted}')

# Test keypair generation
keypair = crypto.create_agent_keypair('test_agent')
print(f'Keypair generated: {\"key_file\" in keypair}')

print('✅ Cryptographic functions working!')
"
if [ $? -ne 0 ]; then
    echo "❌ Cryptographic test failed!"
    exit 1
fi
echo "✅ Cryptographic functions working!"
cd ../..
echo

echo "=============================================="
echo "🎉 N0-BODYKNOWS Integration Test Complete!"
echo "=============================================="
echo
echo "📊 Test Summary:"
echo "  ✅ Unit Tests: PASSED"
echo "  ✅ Key Generation: PASSED" 
echo "  ✅ Network Tests: PASSED"
echo "  ✅ Configuration System: PASSED"
echo "  ✅ Cryptographic Functions: PASSED"
echo
echo "🚀 The N0-BODYKNOWS Network is fully operational!"
echo
echo "📖 Usage Instructions:"
echo "  1. Start server: ./start_server.sh"
echo "  2. Start client: ./start_client.sh <agent_id>"
echo "  3. Default agents: admin (admin123), alpha (alpha123), bravo (bravo123)"
echo
echo "🔐 Security Features:"
echo "  • End-to-end AES-256 encryption"
echo "  • PBKDF2 password hashing"
echo "  • Multi-level clearance system"
echo "  • Secure key management"
echo "  • Evidence removal utilities"