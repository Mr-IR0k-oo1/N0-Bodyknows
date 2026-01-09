# N0-BODYKNOWS Operations Manual

## Table of Contents
1. [System Overview](#system-overview)
2. [Quick Start Guide](#quick-start-guide)
3. [Command Center Operations](#command-center-operations)
4. [Operative Terminal Usage](#operative-terminal-usage)
5. [Security Protocols](#security-protocols)
6. [Emergency Procedures](#emergency-procedures)
7. [Troubleshooting](#troubleshooting)

## System Overview

The N0-BODYKNOWS Network is a secure communications system designed for covert operations. It consists of:

- **Command Center**: Central server that manages all communications
- **Operative Terminals**: Client applications used by field agents
- **Key Vault**: Secure storage for encryption keys and credentials
- **Operational Tools**: Utilities for key management, evidence removal, and network testing

### Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Operative     │    │   Command       │    │   Operative     │
│   Terminal      │◄──►│   Center       │◄──►│   Terminal      │
│   (Client)      │    │   (Server)     │    │   (Client)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  Key Vault &    │
                    │  Data Stores   │
                    └─────────────────┘
```

## Quick Start Guide

### 1. Initial Setup

1. **Install Dependencies**:
   ```bash
   pip install rich cryptography
   ```

2. **Generate Master Key**:
   ```bash
   cd "N0-Bodyknows/Operational Tools"
   python key_generator.py --generate-master
   ```

3. **Create Agent Accounts**:
   ```bash
   python key_generator.py --create-agent alpha --clearance field_agent
   python key_generator.py --create-agent bravo --clearance operative
   ```

### 2. Start Command Center

```bash
cd "N0-Bodyknows/Core Components"
python server.py
```

The Command Center will start and display:
- System status
- Active connections
- Communications log
- Command interface

### 3. Connect Operative Terminal

```bash
cd "N0-Bodyknows/Core Components"
python client.py --agent-id alpha --host localhost
```

Enter the agent password when prompted (shown during account creation).

## Command Center Operations

### Starting the Server

```bash
python server.py
```

### Available Commands

- `/help` - Display available commands
- `/agents` - List all agents in database
- `/status` - Show system status and statistics
- `/wipe <agent_id>` - Emergency wipe of agent session
- `/clear` - Clear message history
- `/quit` - Shutdown Command Center

### Sending Messages

Type any message and press Enter to broadcast to all connected agents.

### Priority Messages

Use priority levels for urgent communications:
- High priority: `/priority high Emergency situation`
- Critical priority: `/priority critical Immediate action required`

## Operative Terminal Usage

### Connecting to Command Center

```bash
python client.py --agent-id <agent_id> --host <server_ip>
```

### Authentication

1. Enter agent ID when prompted
2. Enter password securely (hidden input)
3. Terminal will display connection status and clearance level

### Available Commands

- `/help` - Show available commands
- `/secure <agent_id> <message>` - Send secure message to specific agent
- `/priority <high|critical> <message>` - Send priority message
- `/search <keyword>` - Search message history
- `/status` - Show connection status
- `/clear` - Clear message history
- `/quit` - Disconnect from Command Center

### Message Types

1. **Regular Messages**: Broadcast to all agents
2. **Secure Messages**: Point-to-point encrypted communication
3. **Priority Messages**: High-priority broadcasts with visual indicators

## Security Protocols

### Encryption

- All communications use AES-256 encryption
- Master key stored in secure key vault
- Session keys generated for each connection
- Password hashing with PBKDF2 (100,000 iterations)

### Authentication

- Agent credentials stored in encrypted database
- Session tokens with configurable timeout
- Failed attempt tracking and lockout protection

### Clearance Levels

1. **Operative**: Basic communication access
2. **Field Agent**: Enhanced privileges and secure messaging
3. **Command**: Administrative functions
4. **Admin**: Full system control

## Emergency Procedures

### Emergency Wipe

To immediately wipe all traces of an agent:

```bash
python log_cleaner.py --wipe-agent <agent_id> --confirm
```

This will:
- Delete agent's encryption keys
- Remove session tokens
- Clean agent from database
- Remove from chat histories

### Complete System Wipe

For emergency situations requiring total data destruction:

```bash
python log_cleaner.py --emergency-wipe --confirm
```

⚠️ **WARNING**: This action is irreversible and will destroy all system data.

### Connection Issues

If connection is compromised:
1. Use `/quit` to disconnect immediately
2. Run emergency wipe procedures
3. Contact command center via alternate channel

## Troubleshooting

### Common Issues

#### Connection Failed

**Symptoms**: "Connection failed" error when connecting to Command Center

**Solutions**:
1. Verify Command Center is running
2. Check network connectivity: `python network_test.py --host <server_ip>`
3. Verify correct IP address and port
4. Check firewall settings

#### Authentication Failed

**Symptoms**: "Authentication failed" error

**Solutions**:
1. Verify correct agent ID and password
2. Check if agent account is active: `python key_generator.py --list-agents`
3. Reset agent credentials if needed

#### Encryption Errors

**Symptoms**: Messages not encrypting/decrypting properly

**Solutions**:
1. Verify master key exists in key vault
2. Check key file permissions
3. Regenerate keys if corrupted: `python key_generator.py --generate-master`

### Network Diagnostics

Run comprehensive network tests:

```bash
python network_test.py --host <server_ip> --port <port> --test comprehensive
```

### Log Analysis

Check system logs for errors:

```bash
python log_cleaner.py --analyze
```

### Performance Issues

For slow connections or high latency:

1. Test bandwidth: `python network_test.py --test bandwidth`
2. Check system resources
3. Reduce message history retention in config

## Advanced Operations

### Custom Configuration

Edit `Data Stores/mission_config.json` to customize:
- Network settings
- Security parameters
- Operational timeouts
- UI preferences

### Session Management

Generate session tokens for automated access:

```bash
python key_generator.py --generate-session <agent_id>
```

### One-Time Pads

For ultra-secure communications:

```bash
python key_generator.py --generate-otp
```

### Backup and Recovery

Regularly backup:
- Key vault contents
- Agent database
- Configuration files
- Message histories (if required)

## Security Best Practices

1. **Password Security**: Use strong, unique passwords for each agent
2. **Key Management**: Regularly rotate encryption keys
3. **Access Control**: Limit Command Center access to authorized personnel
4. **Audit Trails**: Monitor connection logs and message patterns
5. **Emergency Planning**: Establish procedures for rapid data destruction

## Contact and Support

For technical support or security concerns:
- Check system logs for error details
- Run network diagnostics
- Document all unusual activities
- Follow emergency procedures if compromise suspected

---

**CLASSIFICATION**: TOP SECRET // NOFORN // EYES ONLY
**DISTRIBUTION**: Authorized N0-BODYKNOWS personnel only
**VERSION**: 1.0
**LAST UPDATED**: Current operational date