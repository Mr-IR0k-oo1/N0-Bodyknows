#!/usr/bin/env python3

import sys
import os
import json

sys.path.append("Core Components")

from crypto_utils import CryptoEngine


def fix_agent_database():
    crypto = CryptoEngine()

    # Create correct password hashes for default agents
    default_agents = {
        "admin": {"password": "admin123", "clearance": "admin"},
        "alpha": {"password": "alpha123", "clearance": "field_agent"},
        "bravo": {"password": "bravo123", "clearance": "operative"},
    }

    # Load existing database
    db_file = "Data/agent_database.json"
    agent_db = {}

    if os.path.exists(db_file):
        with open(db_file, "r") as f:
            agent_db = json.load(f)

    # Update password hashes for default agents
    for agent_id, agent_info in default_agents.items():
        password_hash = crypto.hash_password(agent_info["password"])

        if agent_id in agent_db:
            # Update existing agent
            agent_db[agent_id]["password_hash"] = password_hash
            agent_db[agent_id]["clearance"] = agent_info["clearance"]
            agent_db[agent_id]["active"] = True
            print(f"Updated {agent_id} with new password hash")
        else:
            # Create new agent
            agent_db[agent_id] = {
                "password_hash": password_hash,
                "clearance": agent_info["clearance"],
                "active": True,
                "created": "2025-12-13T00:00:00.000000",
            }
            print(f"Created {agent_id} with password hash")

    # Save updated database
    os.makedirs(os.path.dirname(db_file), exist_ok=True)
    with open(db_file, "w") as f:
        json.dump(agent_db, f, indent=2)

    print(f"\nAgent database updated successfully!")

    # Test verification
    print("\nTesting password verification:")
    for agent_id, agent_info in default_agents.items():
        password = agent_info["password"]
        stored_hash = agent_db[agent_id]["password_hash"]
        verified = crypto.verify_password(password, stored_hash)
        print(f"{agent_id}:{password} -> {verified}")


if __name__ == "__main__":
    fix_agent_database()
