#!/bin/bash
# N0-BODYKNOWS Operative Terminal Startup Script

if [ -z "$1" ]; then
    echo "Usage: $0 <agent_id>"
    echo "Available agents: admin, alpha, bravo (and any others you create)"
    exit 1
fi

echo "🔐 Starting N0-BODYKNOWS Operative Terminal for agent: $1"
source venv/bin/activate
cd "Core Components"
python client.py --agent-id "$1"