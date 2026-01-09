# How to Run N0-Bodyknows

## Prerequisites
Ensure dependencies are installed:
```bash
source venv/bin/activate
pip install -r requirements.txt
```
(You have already done this via the provided setup steps).

## 1. Start the Command Center (Server)
Open a terminal and run:
```bash
./start_server.sh
```
This will start the central server. Keep this terminal open.

## 2. Create a New Agent
Since existing agent passwords might be unknown, create a new agent to get a fresh password.
Open a **new** terminal and run:
```bash
# Activate environment first
source venv/bin/activate

# Create a new agent (replace 'myagent' with your desired name)
python "Operational Tools/key_generator.py" --create-agent myagent --clearance field_agent
```
**IMPORTANT:** Note down the password displayed! It will not be shown again.

## 3. Connect as an Agent (Client)
In the same terminal (or a new one), connect to the server:
```bash
./start_client.sh myagent
```
Enter the password you just noted down.

## Useful Commands
- **Client**: `/help` to see available commands, `/secure <agent> <msg>` for encrypted items.
- **Server**: `/agents` to see online agents.
