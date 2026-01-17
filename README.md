<h1 align="center">
  🛡️ <br>
  Camellia Shield
  <br>
</h1>

<h4 align="center">Hardened Secure Local Workspace & Deep Integrity Inspection</h4>

<p align="center">
  <a href="#-security-architecture">Security</a> •
  <a href="#-key-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-deep-integrity-inspection-dii">Deep Integrity (DII)</a>
</p>

---

## 🔒 Security Architecture (Whitepaper)

Camellia Shield is built on a **Zero-Trust Local Architecture**, designed to protect sensitive data even if the physical device is compromised (while at rest) or if malicious files are attempted to be introduced.

### Cryptographic Core
- **Master Key Derivation**: Uses **Argon2id** (memory-hard function) to derive the Key Encryption Key (KEK) from the user's password.
    - *Params*: t=2, m=64MB, p=4, salt=16 bytes.
- **Data Encryption**: **AES-256-GCM** (Galois/Counter Mode) for all file contents, ensuring confidentiality and integrity assurance (AEAD).
- **Metadata Protection**: Filenames and directory structures are hidden. On disk, all files are renamed to random UUIDs (`f47ac10b-58cc...`), mapped only in the encrypted `vault_manifest.enc`.
- **Key Hierarchy**:
    1.  `User Password` + `Salt` -> `KEK` (Argon2id)
    2.  `KEK` decrypts `Master Key` (AES-256-GCM)
    3.  `Master Key` decrypts `File Keys` (AES-256-GCM)
    4.  `File Keys` decrypt `File Content`

### Session Security
- **Ephemeral Keys**: Master Keys are held **only in RAM**. They are never written to disk unencrypted.
- **Panic Wipe**: Immediate destruction of session keys from memory upon triggering the Panic Button.
- **Auto-Lock**: Configurable inactivity timer to clear memory and require re-authentication.

---

## 🛡 Deep Integrity Inspection (DII)

Beyond standard encryption, Camellia Shield implements a proactive **Deep Integrity Inspection** engine to detect malicious or anomalous files transferred into the secure environment.

### 1. Magic Bytes Validation
Verifies file signatures against their extensions. A file named `report.pdf` MUST start with `%PDF-`. If it starts with `MZ` (Windows Executable), it is flagged immediately as **CRITICAL**.

### 2. Heuristic Entropy Analysis
Calculates the **Shannon Entropy** of file content to detect obfuscation.
- **Normal Text/Code**: Low entropy (< 6.0).
- **Compressed/Media**: High entropy (> 7.5).
- **Malicious/Packed Code**: High entropy in non-media files (e.g., a high-entropy `.js` or `.bat` file often indicates malicious packing).

### 3. Cryptographic Hashing
Generates **SHA-256** and **BLAKE2b** fingerprints for every file to verify bit-perfect integrity over time.

---

## 🚀 Key Features

- **Military-Grade Encryption**: AES-256-GCM + Argon2id.
- **Deep Integrity Scan**: Detects malware, spoofed extensions, and corrupted files.
- **Secure File Explorer**:
    - **Mobile-First Design**: Responsive interface that works on generic webviews and mobile browsers.
    - **Visual Risk Badges**: Clear indicators for Safe vs. Suspicious files.
- **Device Management**: Secure interaction with USB/MTP devices (Whitelisting capable).
- **Audit Logging**: Tamper-evident logging of all cryptographic operations.

---

## 📦 Installation & Setup

### Requirements
- **OS**: Linux (Preferred), macOS, or Windows.
- **Runtime**: Python 3.9+
- **Browser engine**: GTK/WebKit (Linux), Cocoa/WebKit (macOS), EdgeWebView2 (Windows).

### Quick Start (Dev)

```bash
# 1. Clone & Setup Virtual Environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install Dependencies
pip install -r requirements.txt

# 3. Build Frontend (React + Vite)
cd frontend
npm install
npm run build
cd ..

# 4. Run Application
# Desktop Mode (starts webview)
python main.py

# Headless Server Mode (for network access)
export DESKTOP_MODE=0
python app.py
```

### Configuration
Camellia Shield automatically generates a secure configuration on first run.
- **Vault Location**: `~/Documents/Camellia/Vault` (Default)
- **Keys Location**: `~/.camellia/keys` (Protect this folder!)

---

## ⚠️ Disclaimer
While Camellia Shield uses state-of-the-art cryptography, security is a process.
- **DII is not an Antivirus**: It detects anomalies, not specific virus signatures.
- **Backup**: Always keep offline backups of your Master Key/Password. There is **NO BACKDOOR** to recover data if you lose your credentials.
