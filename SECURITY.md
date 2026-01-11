# Security Policy & Threat Model

**Application**: Camellia Shield
**Version**: 2.1 (Hardened)

## 🛡️ Security Architecture

### 1. Key Management
*   **Key Derivation Function (KDF)**: Argon2id (Memory-hard).
*   **Master Key (MK)**: 256-bit random key generated at registration.
*   **Key Wrapping**: The MK is encrypted (wrapped) using an AES-GCM Key Encryption Key (KEK) derived from the user's password.
*   **Session Security**: The MK is stored in volatile memory (RAM) only during an active session. It is never written to disk in plain text.

### 2. Encryption
*   **Algorithm**: AES-128-CBC (via Fernet) with HMAC-SHA256 for integrity.
*   **Metadata Protection**: Encrypted files are renamed to UUIDs to hide original filenames. Mapping is stored in an encrypted manifest (`vault_manifest.enc`).

### 3. Authentication
*   **Password Hashing**: Passwords are hashed using Argon2id for verification (Auth Verifier). This hash is DIFFERENT from the one used for key derivation, ensuring that a database leak does not compromise the Master Key immediately.
*   **2FA**: TOTP based 2FA is enforced for critical sessions.

## ⚠️ Threat Model

### Protected Against
*   **Cold Boot Attacks (Partial)**: Data at rest is encrypted.
*   **Database Leaks**: `users.db` contains wrapped keys and verification hashes, not passwords.
*   **Metadata Analysis**: Filenames and directory structures are hidden in the vault manifest.

### NOT Protected Against
*   **Live Memory Analysis**: If an attacker has root access while the application is running and unlocked, they can dump the Master Key from RAM.
*   **Keyloggers / Malware**: If the host machine is compromised, the user's password can be intercepted.
*   **Rubber Hose Cryptanalysis**: Coercion to reveal the password.

## 🚨 Reporting Vulnerabilities
Please report security issues directly to the development team. Do not open public issues for critical exploits.
