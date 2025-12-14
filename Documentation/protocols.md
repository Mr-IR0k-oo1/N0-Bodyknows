# N0-BODYKNOWS Communication Protocols

## Table of Contents
1. [Protocol Overview](#protocol-overview)
2. [Authentication Protocol](#authentication-protocol)
3. [Message Encryption](#message-encryption)
4. [Communication Flow](#communication-flow)
5. [Session Management](#session-management)
6. [Error Handling](#error-handling)
7. [Security Considerations](#security-considerations)

## Protocol Overview

The N0-BODYKNOWS network uses a secure, encrypted communication protocol designed for covert operations. All communications are protected by multiple layers of security and authentication.

### Protocol Stack

```
┌─────────────────────────────────┐
│   Application Layer (Messages)  │
├─────────────────────────────────┤
│   Session Layer (Sessions)      │
├─────────────────────────────────┤
│   Encryption Layer (AES-256)    │
├─────────────────────────────────┤
│   Transport Layer (TCP)         │
├─────────────────────────────────┤
│   Network Layer (IP)           │
└─────────────────────────────────┘
```

### Message Format

All messages follow this JSON structure:

```json
{
  "version": "1.0",
  "type": "message|command|system|auth",
  "timestamp": "2024-01-01T12:00:00Z",
  "sender": "agent_id",
  "recipient": "agent_id|broadcast",
  "clearance": "operative|field_agent|command|admin",
  "priority": "normal|high|critical",
  "encrypted_data": "base64_encrypted_content",
  "session_id": "session_identifier",
  "checksum": "sha256_hash"
}
```

## Authentication Protocol

### Initial Handshake

1. **Client Connection Request**
   ```
   TCP CONNECT → server:port
   ```

2. **Authentication Request**
   ```json
   {
     "type": "auth_request",
     "agent_id": "alpha",
     "password": "hashed_password",
     "client_version": "1.0",
     "timestamp": "2024-01-01T12:00:00Z"
   }
   ```

3. **Server Response**
   ```json
   {
     "type": "auth_response",
     "status": "success|failed",
     "session_key": "generated_session_key",
     "clearance": "field_agent",
     "expires": "2024-01-01T13:00:00Z",
     "server_version": "1.0"
   }
   ```

### Password Hashing

Passwords are hashed using PBKDF2 with the following parameters:
- Algorithm: SHA-256
- Iterations: 100,000
- Salt length: 16 bytes
- Key length: 32 bytes

```
hash = PBKDF2(password, salt, 100000, 32, SHA-256)
stored_hash = salt + ":" + hash
```

## Message Encryption

### Encryption Algorithm

- **Algorithm**: AES-256 in GCM mode
- **Key Derivation**: PBKDF2 with session-specific salt
- **Authentication**: HMAC-SHA256
- **Nonce**: 96-bit random nonce per message

### Encryption Process

1. **Key Derivation**
   ```
   encryption_key = PBKDF2(session_key, message_salt, 1000, 32, SHA-256)
   ```

2. **Message Encryption**
   ```
   nonce = random_bytes(12)
   ciphertext = AES-GCM(encryption_key, nonce, plaintext)
   tag = authentication_tag
   ```

3. **Package Assembly**
   ```json
   {
     "encrypted_data": "base64(nonce + ciphertext + tag)",
     "salt": "base64(message_salt)",
     "type": "encrypted_message"
   }
   ```

### Message Types

#### Regular Messages
```json
{
  "type": "message",
  "content": "plaintext_message",
  "recipient": "broadcast"
}
```

#### Secure Messages
```json
{
  "type": "secure_message",
  "content": "confidential_message",
  "recipient": "specific_agent_id"
}
```

#### Priority Messages
```json
{
  "type": "priority_message",
  "content": "urgent_message",
  "priority": "high|critical",
  "recipient": "broadcast"
}
```

#### System Messages
```json
{
  "type": "system",
  "content": "system_notification",
  "code": "connection|disconnection|error"
}
```

## Communication Flow

### Client Connection Sequence

```
1. TCP Connect
2. Send Authentication Request
3. Receive Authentication Response
4. Establish Session
5. Start Message Exchange
6. Session Maintenance
7. Disconnect
```

### Message Exchange Protocol

#### Sending Messages

1. **Message Creation**
   ```
   plaintext = user_input
   message_type = determine_type(plaintext)
   ```

2. **Encryption**
   ```
   encrypted_package = encrypt_message(plaintext, session_key)
   ```

3. **Transmission**
   ```
   send(encrypted_package)
   ```

#### Receiving Messages

1. **Reception**
   ```
   encrypted_package = receive()
   ```

2. **Decryption**
   ```
   plaintext = decrypt_message(encrypted_package, session_key)
   ```

3. **Processing**
   ```
   process_message(plaintext)
   ```

### Command Protocol

Commands use special prefixes:

- `/secure <agent_id> <message>` - Secure message
- `/priority <level> <message>` - Priority message
- `/status` - System status
- `/quit` - Disconnect

## Session Management

### Session Creation

```python
def create_session(agent_id):
    session_key = generate_random_key(32)
    expires = now() + SESSION_TIMEOUT
    session_id = generate_session_id()
    
    return {
        'session_id': session_id,
        'session_key': session_key,
        'agent_id': agent_id,
        'expires': expires,
        'created': now()
    }
```

### Session Validation

```python
def is_session_valid(session):
    return now() < session['expires'] and session['active']
```

### Session Renewal

Sessions are automatically renewed 5 minutes before expiration:

```python
def renew_session(session):
    if session['expires'] - now() < RENEWAL_THRESHOLD:
        session['expires'] = now() + SESSION_TIMEOUT
        return True
    return False
```

### Session Termination

Sessions terminate when:
- Client disconnects gracefully
- Session expires
- Emergency wipe is triggered
- Authentication fails

## Error Handling

### Error Codes

| Code | Description | Action |
|------|-------------|--------|
| 1001 | Authentication Failed | Close connection |
| 1002 | Session Expired | Request re-authentication |
| 1003 | Invalid Message Format | Ignore message |
| 1004 | Decryption Failed | Request retransmission |
| 1005 | Rate Limit Exceeded | Temporarily block |
| 1006 | Clearance Insufficient | Deny access |

### Error Response Format

```json
{
  "type": "error",
  "code": 1001,
  "message": "Authentication failed",
  "timestamp": "2024-01-01T12:00:00Z",
  "recoverable": false
}
```

### Recovery Procedures

#### Authentication Errors
1. Log failed attempt
2. Increment failure counter
3. Lock account after MAX_FAILED_ATTEMPTS
4. Require manual intervention

#### Network Errors
1. Implement exponential backoff
2. Cache undelivered messages
3. Attempt reconnection
4. Notify user of connection status

#### Encryption Errors
1. Verify key integrity
2. Regenerate session keys
3. Resynchronize encryption parameters

## Security Considerations

### Threat Mitigation

#### Eavesdropping
- All communications encrypted with AES-256
- Perfect forward secrecy with session keys
- Regular key rotation

#### Man-in-the-Middle
- Server authentication certificates
- Session key verification
- Message authentication codes

#### Replay Attacks
- Timestamp validation
- Nonce usage per message
- Sequence numbers

#### Session Hijacking
- Secure session management
- Regular session renewal
- IP binding (optional)

### Data Protection

#### Sensitive Data Handling
- Passwords never stored in plaintext
- Keys encrypted at rest
- Secure memory management

#### Log Security
- No sensitive data in logs
- Encrypted log storage
- Regular log rotation

#### Key Management
- Master key isolation
- Hierarchical key structure
- Secure key destruction

### Compliance

#### Data Retention
- Configurable retention periods
- Automatic cleanup procedures
- Secure deletion methods

#### Access Control
- Role-based permissions
- Audit trail maintenance
- Regular access reviews

## Protocol Extensions

### Future Enhancements

1. **Forward Secrecy**: Implement Diffie-Hellman key exchange
2. **Message Receipts**: Add delivery confirmation
3. **File Transfer**: Secure file sharing protocol
4. **Voice Communication**: Encrypted voice channels
5. **Multi-factor Authentication**: Additional security layers

### Version Compatibility

Protocol versioning ensures backward compatibility:
- Version negotiation during handshake
- Feature detection capabilities
- Graceful degradation for older clients

---

**CLASSIFICATION**: TOP SECRET // NOFORN
**DISTRIBUTION**: N0-BODYKNOWS Technical Personnel
**VERSION**: 1.0
**LAST UPDATED**: Current operational date