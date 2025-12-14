# N0-BODYKNOWS Network

## 🎯 Mission Statement

N0-BODYKNOWS is a **military-grade secure communication system** designed for covert operations requiring **maximum security, anti-analysis protection, and operational reliability**. Built with defense-in-depth architecture and triple-layer encryption, it provides secure communications for command centers and field operatives.

## 🔐 Security Architecture

### Triple-Layer Encryption System

```
┌─────────────────────────────────────────────────────────────┐
│                    AES-256 Symmetric Encryption             │
├─────────────────────────────────────────────────────────────┤
│                    XOR Obfuscation Layer                    │
├─────────────────────────────────────────────────────────────┤
│                    Base64 Transport Encoding                │
└─────────────────────────────────────────────────────────────┘
```

**Security Features:**

- **Triple-Layer Encryption:** AES-256 + XOR Obfuscation + Base64 Transport Encoding
- **Defense in Depth:** Multiple independent security layers
- **Perfect Forward Secrecy:** Session keys prevent retrospective decryption
- **Zero Trust Architecture:** No implicit trust in network or systems
- **Secure by Default:** All communications encrypted by default
- **Need-to-Know Access Control:** Role-based permissions system
- **Anti-Analysis Protection:** Obfuscated code and encrypted data stores

## 🚀 Quick Start

### 1. Automatic Setup (Recommended)

```bash
chmod +x setup.sh
./setup.sh
```

### 2. Manual Installation

```bash
# Clone the repository
git clone https://github.com/your-repo/n0-bodyknows.git
cd n0-bodyknows

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize the system
cd "Operational Tools"
python key_generator.py --generate-master
python key_generator.py --create-agent admin --clearance admin
python key_generator.py --create-agent alpha --clearance field_agent
python key_generator.py --create-agent bravo --clearance operative
cd ..
```

## 🎮 Usage

### Start the Command Center (Server)

```bash
# Using startup script
./start_server.sh

# Or manually
source venv/bin/activate
cd "Core Components"
python server.py
```

### Connect Operative Terminal (Client)

```bash
# Using startup script
./start_client.sh admin

# Or manually
source venv/bin/activate
cd "Core Components"
python client.py --agent-id admin --host localhost
```

### Default Agent Credentials

| Agent ID | Role | Default Password | Clearance Level |
|----------|------|------------------|-----------------|
| `admin` | System Administrator | `admin123` | Admin |
| `alpha` | Field Agent | `alpha123` | Field Agent |
| `bravo` | Special Operative | `bravo123` | Operative |

## 💬 Client Commands

### Basic Commands

- `/help` - Display enhanced help menu with operational tips
- `/status` - Show connection, encryption, and system status
- `/exit` - Securely disconnect from the network
- `/clear` - Clear the terminal display

### Communication Commands

- `/secure <agent_id> <message>` - Send encrypted direct message
- `/broadcast <message>` - Send message to all connected agents
- `/priority <high|critical> <message>` - Send priority message with visual alerts
- `/file <agent_id> <file_path>` - Secure file transfer (encrypted)

### Security Commands

- `/key-rotate` - Rotate encryption keys for current session
- `/auth-check` - Verify authentication and encryption status
- `/secure-wipe` - Emergency data wipe (client-side)

### Administrative Commands (Admin Only)

- `/agent-list` - List all connected agents
- `/agent-kick <agent_id>` - Disconnect specified agent
- `/system-alert <message>` - Send system-wide alert
- `/log-review` - Access encrypted communication logs

## 🏗️ System Architecture

### Core Components

```
┌───────────────────────────────────────────────────────────────────────────┐
│                            N0-BODYKNOWS NETWORK                           │
─────────────────┬─────────────────┬─────────────────┬──────────────────────┤
│  Command Center │  Operative      │  Operative     │  Key Vault &         │
│  (Server)       │  Terminal       │  Terminal      │  Data Stores         │
│                 │  (Client)       │  (Client)      │                      │
└─────────────────┴─────────────────┴────────────────┴──────────────────────┘
```

### Component Details

**Core Components:**

- `server.py` - Command Center with multi-client management
- `client.py` - Operative Terminal with military-grade UI
- `enhanced_crypto.py` - Triple-layer encryption engine
- `config.py` - System configuration and security settings
- `history_manager.py` - Secure communication logging

**Cryptographic Modules:**

- `brainfuck_crypto.py` - Advanced obfuscation algorithms
- `obfuscation_crypto.py` - Anti-analysis encryption layers
- `simple_brainfuck.py` - Lightweight obfuscation utilities
- `simple_dual_crypto.py` - Dual-layer encryption fallback
- `crypto_utils.py` - Cryptographic utility functions

**Operational Tools:**

- `key_generator.py` - Master key and agent credential management
- `log_cleaner.py` - Secure evidence removal and log sanitization
- `network_test.py` - Network connectivity and security testing

## 🛡️ Security Features

### Encryption Standards

- **AES-256-CBC** - Military-grade symmetric encryption
- **XOR Obfuscation** - Anti-pattern analysis layer
- **Base64 Transport** - Safe data transmission encoding
- **Session Key Rotation** - Automatic key refresh
- **Secure Key Storage** - Encrypted key vault system

### Access Control

- **Role-Based Access:** Admin, Field Agent, Operative roles
- **Clearance Levels:** Admin, Field Agent, Operative tiers
- **Authentication:** Secure password-based authentication
- **Authorization:** Command-level permission system

### Operational Security

- **Secure Wipe:** Emergency data destruction capability
- **Log Encryption:** All communication logs encrypted at rest
- **Network Testing:** Pre-mission connectivity verification
- **Anti-Forensics:** Evidence removal utilities

## 📚 Documentation

### Available Manuals

- **Operations Manual** (`Documentation/op_manual.md`) - Complete system guide
- **Security Procedures** (`Documentation/security.md`) - Security protocols
- **Communication Protocols** (`Documentation/protocols.md`) - Network protocols

### Quick Reference

```bash
# View operations manual
less Documentation/op_manual.md

# Review security procedures
less Documentation/security.md

# Study communication protocols
less Documentation/protocols.md
```

## 🔧 Advanced Configuration

### Custom Agent Creation

```bash
cd "Operational Tools"
python key_generator.py --create-agent <agent_id> --clearance <level>
```

**Clearance Levels:**

- `admin` - Full system access
- `field_agent` - Standard field operations
- `operative` - Limited tactical access

### Key Management

```bash
# Generate new master key
python key_generator.py --generate-master

# Rotate agent keys
python key_generator.py --rotate-keys <agent_id>

# Backup key vault
cp -r Data/key_vault/ backup_location/
```

### Network Configuration

Edit `config.py` to customize:

- Server host and port settings
- Encryption algorithm preferences
- Session timeout values
- Maximum connection limits

## 🧪 Testing & Validation

### Integration Testing

```bash
chmod +x integration_test.sh
./integration_test.sh
```

### Manual Testing

```bash
# Test server connectivity
cd "Operational Tools"
python network_test.py

# Validate encryption
python -c "from Core Components.enhanced_crypto import test_encryption; test_encryption()"
```

## 🎨 User Interface Features

### Military-Grade Design

- **3D-Style Branding:** Professional military aesthetic
- **Rich Panel Layouts:** Organized information display
- **Real-time Indicators:** Visual status cues
- **Priority Alerts:** Color-coded message importance
- **Secure Input:** Password-masked entry fields

### Visual Elements

- **Connection Status:** Green/Red indicators
- **Encryption Status:** Lock icons and security level
- **Message Priority:** High/Critical visual alerts
- **Agent Identification:** Role-based color coding

## 🔄 System Maintenance

### Regular Operations

```bash
# Clean logs and temporary files
cd "Operational Tools"
python log_cleaner.py --dry-run  # Preview changes
python log_cleaner.py --execute  # Execute cleanup

# Backup system data
cp -r Data/ backup_location/

# Restore from backup
cp -r backup_location/Data/ .
```

### Emergency Procedures

```bash
# Secure system shutdown
./start_client.sh admin
/secure-wipe
/exit

# Data recovery
python fix_database.py
```

## 📦 Deployment Options

### Development Setup

```bash
# Install development dependencies
pip install rich cryptography

# Run in development mode
python "Core Components/server.py" --debug
```

### Production Deployment

```bash
# Create production environment
python3 -m venv venv --system-site-packages

# Install only required dependencies
pip install rich cryptography

# Run in production mode
nohup python "Core Components/server.py" > server.log 2>&1 &
```

### Docker Deployment (Future)

```bash
# Build Docker image
# docker build -t n0-bodyknows .

# Run container
# docker run -p 12345:12345 n0-bodyknows
```

## 🤝 Contributing

### Development Guidelines

- Follow existing code style and architecture
- Maintain security-first approach
- Document all changes and additions
- Test thoroughly before submission

### Pull Request Process

1. Fork the repository
2. Create feature branch: `git checkout -b feature/your-feature`
3. Commit changes: `git commit -m "Add your feature"`
4. Push to branch: `git push origin feature/your-feature`
5. Submit pull request with detailed description

## 📜 License

**Unlicensed** - Free to use for any purpose

- No restrictions on usage
- No warranty or liability
- Use at your own risk
- Suitable for personal, educational, and professional use

## 🚨 Disclaimer

**This system is designed for educational and research purposes.** While it implements strong security measures, it should not be relied upon for actual covert operations without professional security audit and certification.

## 📞 Support

For issues, questions, or contributions:

- Review documentation in `Documentation/` directory
- Check existing issues and pull requests
- Submit new issues with detailed information
- Contact maintainers for critical security concerns

## 🎓 Learning Resources

### Cryptography

- AES-256 encryption standards
- XOR obfuscation techniques
- Base64 encoding/decoding

### Network Security

- Secure socket programming
- Authentication protocols
- Session management

### Python Development

- Rich library for terminal UIs
- Cryptography library usage
- Secure coding practices

## 🔮 Future Enhancements

### Planned Features

- **End-to-End Encryption:** Client-side encryption keys
- **Two-Factor Authentication:** Enhanced login security
- **Message Expiration:** Self-destructing messages
- **File Encryption:** Secure document sharing
- **Mobile Access:** QR code authentication
- **Web Interface:** Browser-based access
- **Database Integration:** Persistent message storage
- **Audit Logging:** Comprehensive activity tracking

### Roadmap

1. **v1.1** - Enhanced encryption and mobile support
2. **v1.2** - Web interface and API access
3. **v1.3** - Database integration and audit logging
4. **v2.0** - Full end-to-end encryption architecture

## 📊 System Requirements

### Minimum Requirements

- **Python:** 3.8+
- **Memory:** 512MB RAM
- **Storage:** 100MB disk space
- **Network:** Stable internet connection

### Recommended Requirements

- **Python:** 3.10+
- **Memory:** 1GB+ RAM
- **Storage:** 500MB+ disk space
- **Network:** Low-latency connection
- **OS:** Linux (best compatibility)

## 🎯 Quick Reference Cheat Sheet

```bash
# Start system
./setup.sh

# Launch server
./start_server.sh

# Connect client
./start_client.sh admin

# Create new agent
cd "Operational Tools"
python key_generator.py --create-agent <name> --clearance <level>

# Test network
python network_test.py

# Clean logs
python log_cleaner.py --execute

# View help
/help

# Send secure message
/secure bravo "This is a test message"

# Send priority message
/priority critical "EMERGENCY: All agents respond"
```

## 🔐 Security Best Practices

### Operational Security

- Always use virtual environments
- Regularly rotate encryption keys
- Monitor system logs for anomalies
- Keep dependencies updated
- Use strong, unique passwords
- Limit physical access to systems

### Network Security

- Use firewall rules to restrict access
- Monitor network traffic
- Use VPN for remote connections
- Implement network segmentation
- Regular security audits

### Data Security

- Encrypt sensitive data at rest
- Securely wipe unused data
- Backup critical information
- Implement access controls
- Monitor data access patterns

## 📝 Changelog

### Recent Updates

- **Enhanced UI:** Military-grade visual design
- **Triple-Layer Encryption:** Improved security architecture
- **Operational Tools:** Key management and network testing
- **Documentation:** Comprehensive manuals and guides
- **Error Handling:** Robust exception management

## 🌐 Community

Join the N0-BODYKNOWS community:

- Contribute code and improvements
- Report security vulnerabilities responsibly
- Share operational experiences
- Provide feedback and suggestions
- Help improve documentation

## 🎖️ Acknowledgments

Special thanks to:

- Open-source community for foundational libraries
- Security researchers for encryption standards
- Developers contributing to the project
- Users providing valuable feedback

## 📢 Final Notes

N0-BODYKNOWS represents the cutting edge of secure communication technology. Designed with military-grade security and professional interface, it provides a robust platform for secure operations. Always prioritize security, follow operational protocols, and maintain situational awareness when using this system.

**Stay secure. Stay covert. Mission success depends on operational security.**
