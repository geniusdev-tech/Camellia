"""
Audit Logging System for Camellia Shield

Provides tamper-evident, cryptographically signed audit logs for compliance
and security monitoring. Implements append-only logging with digital signatures.

Compliant with:
- ISO 27001 (A.12.4 Logging and monitoring)
- NIST SP 800-53 (AU family)
- SOC 2 (CC7.2 Monitoring activities)
"""

import os
import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


class EventType:
    """Standard event types for audit logging"""
    # Authentication Events
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILURE = "auth.login.failure"
    LOGOUT = "auth.logout"
    PASSWORD_CHANGE = "auth.password_change"
    MFA_ENABLED = "auth.mfa.enabled"
    MFA_DISABLED = "auth.mfa.disabled"
    
    # Cryptographic Operations
    FILE_ENCRYPT = "crypto.file.encrypt"
    FILE_DECRYPT = "crypto.file.decrypt"
    KEY_ROTATION = "crypto.key.rotation"
    
    # Data Operations
    FILE_DELETE = "data.file.delete"
    MANIFEST_MODIFIED = "data.manifest.modified"
    
    # Administrative Actions
    ADMIN_USER_CREATE = "admin.user.create"
    ADMIN_USER_DELETE = "admin.user.delete"
    ADMIN_ROLE_CHANGE = "admin.role.change"
    
    # Security Events
    RATE_LIMIT_EXCEEDED = "security.rate_limit.exceeded"
    SUSPICIOUS_ACTIVITY = "security.suspicious_activity"
    UNAUTHORIZED_ACCESS = "security.unauthorized_access"


class AuditLogger:
    """
    Cryptographically signed audit logger with tamper-evident properties.
    
    Features:
    - Append-only log file (no modifications allowed)
    - Digital signatures on each entry (Ed25519)
    - Chained hashing for integrity verification
    - Structured JSON format for easy parsing
    """
    
    def __init__(self, log_path: str, signing_key_path: Optional[str] = None):
        """
        Initialize audit logger.
        
        Args:
            log_path: Path to audit log file
            signing_key_path: Path to Ed25519 private key (generates new if not exists)
        """
        self.log_path = log_path
        self.signing_key_path = signing_key_path or os.path.join(
            os.path.dirname(log_path), 
            '.audit_signing_key'
        )
        
        # Load or generate signing key
        self.signing_key = self._load_or_generate_signing_key()
        
        # Initialize log file if needed
        if not os.path.exists(log_path):
            self._initialize_log_file()
        
        # Load last entry hash for chaining
        self.last_hash = self._get_last_entry_hash()
    
    def _load_or_generate_signing_key(self) -> ed25519.Ed25519PrivateKey:
        """Load existing signing key or generate new one"""
        if os.path.exists(self.signing_key_path):
            with open(self.signing_key_path, 'rb') as f:
                key_data = f.read()
                return serialization.load_pem_private_key(key_data, password=None)
        else:
            # Generate new Ed25519 key pair
            private_key = ed25519.Ed25519PrivateKey.generate()
            
            # Save private key (should be protected with proper file permissions)
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            with open(self.signing_key_path, 'wb') as f:
                f.write(pem)
            
            # Set restrictive permissions (owner read/write only)
            os.chmod(self.signing_key_path, 0o600)
            
            return private_key
    
    def _initialize_log_file(self):
        """Create new audit log file with metadata header"""
        header = {
            "version": "1.0",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "public_key": self._get_public_key_hex(),
            "description": "Camellia Shield Audit Log - Cryptographically Signed"
        }
        
        with open(self.log_path, 'w') as f:
            f.write("# " + json.dumps(header) + "\n")
    
    def _get_public_key_hex(self) -> str:
        """Get public key in hex format for verification"""
        public_key = self.signing_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return public_bytes.hex()
    
    def _get_last_entry_hash(self) -> str:
        """Get hash of last log entry for chaining"""
        if not os.path.exists(self.log_path):
            return "0" * 64  # Genesis hash
        
        try:
            with open(self.log_path, 'r') as f:
                lines = f.readlines()
                
            # Find last non-comment line
            for line in reversed(lines):
                if not line.startswith('#'):
                    try:
                        entry = json.loads(line.strip())
                        return entry.get('entry_hash', "0" * 64)
                    except json.JSONDecodeError:
                        continue
            
            return "0" * 64  # No valid entries found
        except Exception:
            return "0" * 64
    
    def log_event(
        self,
        event_type: str,
        user: str,
        details: Dict[str, Any],
        severity: str = "INFO",
        ip_address: Optional[str] = None
    ):
        """
        Log an audit event with cryptographic signature.
        
        Args:
            event_type: Type of event (use EventType constants)
            user: User identifier (email or username)
            details: Additional event details (dict)
            severity: Log severity (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            ip_address: IP address of the client (if applicable)
        """
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        # Build log entry
        entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "user": user,
            "severity": severity,
            "details": details,
            "ip_address": ip_address,
            "previous_hash": self.last_hash
        }
        
        # Compute entry hash (before signature)
        entry_json = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256(entry_json.encode()).hexdigest()
        entry["entry_hash"] = entry_hash
        
        # Sign the entry
        signature = self.signing_key.sign(entry_json.encode())
        entry["signature"] = signature.hex()
        
        # Append to log file (atomic write)
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())  # Force write to disk
        
        # Update chain
        self.last_hash = entry_hash
    
    def verify_log_integrity(self) -> tuple[bool, list]:
        """
        Verify integrity of entire audit log.
        
        Returns:
            (is_valid, errors): Tuple of validity and list of error messages
        """
        errors = []
        
        if not os.path.exists(self.log_path):
            return False, ["Log file does not exist"]
        
        try:
            with open(self.log_path, 'r') as f:
                lines = f.readlines()
            
            # Extract public key from header
            header_line = lines[0] if lines else None
            if not header_line or not header_line.startswith('#'):
                errors.append("Invalid log header")
                return False, errors
            
            header = json.loads(header_line[1:].strip())
            public_key_hex = header.get('public_key')
            
            if not public_key_hex:
                errors.append("Missing public key in header")
                return False, errors
            
            # Reconstruct public key
            public_key_bytes = bytes.fromhex(public_key_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            
            # Verify each entry
            previous_hash = "0" * 64
            
            for idx, line in enumerate(lines[1:], start=1):
                if line.startswith('#'):
                    continue
                
                try:
                    entry = json.loads(line.strip())
                except json.JSONDecodeError:
                    errors.append(f"Line {idx}: Invalid JSON")
                    continue
                
                # Verify previous hash chain
                if entry.get('previous_hash') != previous_hash:
                    errors.append(f"Line {idx}: Broken hash chain")
                
                # Verify signature
                signature_hex = entry.get('signature')
                if not signature_hex:
                    errors.append(f"Line {idx}: Missing signature")
                    continue
                
                # Remove signature for verification
                entry_copy = entry.copy()
                del entry_copy['signature']
                del entry_copy['entry_hash']
                
                entry_json = json.dumps(entry_copy, sort_keys=True)
                signature = bytes.fromhex(signature_hex)
                
                try:
                    public_key.verify(signature, entry_json.encode())
                except Exception as e:
                    errors.append(f"Line {idx}: Invalid signature - {str(e)}")
                
                # Verify entry hash
                computed_hash = hashlib.sha256(entry_json.encode()).hexdigest()
                if computed_hash != entry.get('entry_hash'):
                    errors.append(f"Line {idx}: Hash mismatch")
                
                previous_hash = entry.get('entry_hash', "0" * 64)
            
            return len(errors) == 0, errors
            
        except Exception as e:
            return False, [f"Verification failed: {str(e)}"]
    
    def get_events(
        self,
        event_type: Optional[str] = None,
        user: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100
    ) -> list:
        """
        Query audit log events with filters.
        
        Args:
            event_type: Filter by event type
            user: Filter by user
            start_time: Filter by start timestamp
            end_time: Filter by end timestamp
            limit: Maximum number of events to return
        
        Returns:
            List of matching log entries
        """
        if not os.path.exists(self.log_path):
            return []
        
        results = []
        
        with open(self.log_path, 'r') as f:
            for line in f:
                if line.startswith('#'):
                    continue
                
                try:
                    entry = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue
                
                # Apply filters
                if event_type and entry.get('event_type') != event_type:
                    continue
                
                if user and entry.get('user') != user:
                    continue
                
                if start_time or end_time:
                    entry_time = datetime.fromisoformat(entry['timestamp'].replace('Z', '+00:00'))
                    if start_time and entry_time < start_time:
                        continue
                    if end_time and entry_time > end_time:
                        continue
                
                results.append(entry)
                
                if len(results) >= limit:
                    break
        
        return results


# Global audit logger instance (initialized by application)
_audit_logger: Optional[AuditLogger] = None


def init_audit_logger(log_path: str, signing_key_path: Optional[str] = None):
    """Initialize global audit logger"""
    global _audit_logger
    _audit_logger = AuditLogger(log_path, signing_key_path)


def get_audit_logger() -> AuditLogger:
    """Get global audit logger instance"""
    if _audit_logger is None:
        raise RuntimeError("Audit logger not initialized. Call init_audit_logger() first.")
    return _audit_logger


def log_event(event_type: str, user: str, details: Dict[str, Any], **kwargs):
    """Convenience function for logging events"""
    logger = get_audit_logger()
    logger.log_event(event_type, user, details, **kwargs)
