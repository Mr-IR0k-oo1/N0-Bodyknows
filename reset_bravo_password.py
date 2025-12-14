#!/usr/bin/env python3

"""
Reset bravo password to default
"""

import sys
import json
import os

# Add Core Components to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'Core Components'))

from crypto_utils import CryptoEngine

def reset_bravo_password():
    """Reset bravo password to 'bravo123'"""
    
    # Load existing database
    db_file = "Data/agent_database.json"
    if os.path.exists(db_file):
        with open(db_file, 'r') as f:
            agent_db = json.load(f)
    else:
        print("Database file not found")
        return
    
    # Update bravo password
    crypto = CryptoEngine()
    new_password = "bravo123"
    new_hash = crypto.hash_password(new_password)
    
    if "bravo" in agent_db:
        agent_db["bravo"]["password_hash"] = new_hash
        print(f"✅ Updated bravo password to '{new_password}'")
        print(f"New hash: {new_hash}")
    else:
        print("Bravo agent not found in database")
        return
    
    # Save updated database
    with open(db_file, 'w') as f:
        json.dump(agent_db, f, indent=2)
    
    print("✅ Database updated successfully")

if __name__ == "__main__":
    reset_bravo_password()