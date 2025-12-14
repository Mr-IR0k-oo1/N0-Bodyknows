#!/usr/bin/env python3

import sys
import os
import time
import threading
import subprocess
import signal

# Add Core Components to path
sys.path.append("Core Components")


def test_complete_system():
    print("🚀 Testing Complete N0-BODYKNOWS System...")
    print("=" * 60)

    # Test 1: Server Startup
    print("📋 Test 1: Server Startup")
    try:
        # Start server in background
        server_process = subprocess.Popen(
            ["python", "server.py"],
            cwd="Core Components",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for server to start
        time.sleep(3)

        if server_process.poll() is None:
            print("✅ Server started successfully!")
        else:
            print("❌ Server failed to start")
            return False

    except Exception as e:
        print(f"❌ Server startup error: {e}")
        return False

    # Test 2: Authentication
    print("\n📋 Test 2: Agent Authentication")
    try:
        result = subprocess.run(
            ["python", "test_all_agents.py"], capture_output=True, text=True
        )

        if (
            "🎉 Authentication successful!" in result.stdout
            and result.stdout.count("✅") >= 3
        ):
            print("✅ All agent authentication working!")
        else:
            print("❌ Authentication test failed")
            print(result.stdout)
            return False

    except Exception as e:
        print(f"❌ Authentication test error: {e}")
        return False

    # Test 3: Message Exchange
    print("\n📋 Test 3: Message Exchange")
    try:
        result = subprocess.run(
            ["python", "test_message_exchange.py"], capture_output=True, text=True
        )

        if "✅ Message exchange test completed!" in result.stdout:
            print("✅ Message exchange working!")
        else:
            print("❌ Message exchange test failed")
            print(result.stdout)
            return False

    except Exception as e:
        print(f"❌ Message exchange test error: {e}")
        return False

    # Test 4: Unit Tests
    print("\n📋 Test 4: Unit Tests")
    try:
        result = subprocess.run(
            ["python", "test_core.py"],
            env={**os.environ, "PYTHONPATH": "Core Components"},
            capture_output=True,
            text=True,
        )

        if result.returncode == 0 and "OK" in result.stdout:
            print("✅ All unit tests passing!")
        else:
            print("❌ Unit tests failed")
            print(result.stdout)
            return False

    except Exception as e:
        print(f"❌ Unit tests error: {e}")
        return False

    # Cleanup
    print("\n📋 Test 5: Cleanup")
    try:
        server_process.terminate()
        server_process.wait(timeout=5)
        print("✅ Server stopped cleanly!")
    except:
        server_process.kill()
        print("✅ Server force-stopped!")

    return True


def test_operational_tools():
    print("\n🔧 Testing Operational Tools...")

    # Test key generator
    print("📋 Testing Key Generator...")
    try:
        result = subprocess.run(
            ["python", "key_generator.py", "--list-agents"],
            cwd="Operational Tools",
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            print("✅ Key generator working!")
        else:
            print("❌ Key generator failed")

    except Exception as e:
        print(f"❌ Key generator error: {e}")


def main():
    print("🎯 N0-BODYKNOWS Complete System Test")
    print("=" * 60)

    # Run complete system test
    if test_complete_system():
        print("\n🎉 COMPLETE SYSTEM TEST PASSED!")
        print("=" * 60)

        # Test operational tools
        test_operational_tools()

        print("\n📊 FINAL STATUS:")
        print("  ✅ Server Startup: PASSED")
        print("  ✅ Authentication: PASSED")
        print("  ✅ Message Exchange: PASSED")
        print("  ✅ Unit Tests: PASSED")
        print("  ✅ Operational Tools: TESTED")

        print("\n🚀 The N0-BODYKNOWS Network is FULLY OPERATIONAL!")
        print("\n📖 Usage Instructions:")
        print("  1. Start server: cd 'Core Components' && python server.py")
        print(
            "  2. Start client: cd 'Core Components' && python client.py --agent-id <agent_id>"
        )
        print("  3. Default agents:")
        print("     - admin (admin123) - System administrator")
        print("     - alpha (alpha123) - Field agent")
        print("     - bravo (bravo123) - Special operative")

        print("\n🔐 Security Features:")
        print("  • End-to-end AES-256 encryption")
        print("  • PBKDF2 password hashing (100,000 iterations)")
        print("  • Multi-level clearance system")
        print("  • Secure key management")
        print("  • Session-based authentication")
        print("  • Message history management")

        return True
    else:
        print("\n❌ COMPLETE SYSTEM TEST FAILED!")
        print("=" * 60)
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
