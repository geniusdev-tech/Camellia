import sqlite3
import os
import time
import json
import pyotp
import qrcode
import io
import base64
from core.crypto.engine import CryptoEngine
from core.audit.logger import AuditLogger, EventType, init_audit_logger, log_event
from core.security.rate_limiter import RateLimiter, init_rate_limiter, get_rate_limiter

class AuthManager:
    def __init__(self, db_path="users.db"):
        self.db_path = db_path
        self.crypto = CryptoEngine()
        self.session = None # Stores {email, master_key, login_time}
        
        # Initialize audit logging
        audit_log_path = os.path.join(os.path.dirname(db_path), 'audit.log')
        init_audit_logger(audit_log_path)
        
        # Initialize rate limiter
        init_rate_limiter()
        self.rate_limiter = get_rate_limiter()
        
        self.init_db()

    def init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        # Users table now stores Wrapped Master Key instead of simple password hash check
        # But for simpler auth verification (without unwrapping MK every time just for check),
        # we can store an 'auth_verifier' hash. 
        # Ideally: Password -> Argon2 -> AuthVerifier (stored)
        # AND Password -> Argon2(Salt2) -> KEK -> WrappedMK (stored)
        
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            auth_verifier TEXT NOT NULL, 
            wrapped_key JSON NOT NULL,
            totp_secret TEXT
        )''')
        conn.commit()
        conn.close()

    def register(self, email, password):
        # 1. Generate Auth Verifier
        auth_verifier = self.crypto.hash_password(password)
        
        # 2. Generate and Wrap Master Key
        master_key = self.crypto.generate_master_key()
        wrapped_key = self.crypto.wrap_master_key(master_key, password)
        
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("INSERT INTO users (email, auth_verifier, wrapped_key) VALUES (?, ?, ?)",
                      (email, auth_verifier, json.dumps(wrapped_key)))
            conn.commit()
            conn.close()
            
            # Audit log: successful registration
            log_event(
                EventType.ADMIN_USER_CREATE,
                user=email,
                details={"action": "user_registered"},
                severity="INFO"
            )
            
            return True, "User registered successfully."
        except sqlite3.IntegrityError:
            # Audit log: failed registration (duplicate email)
            log_event(
                EventType.LOGIN_FAILURE,
                user=email,
                details={"reason": "email_already_exists"},
                severity="WARNING"
            )
            return False, "Email already exists."

    def login(self, email, password, ip_address=None):
        # Check rate limit first
        allowed, retry_after = self.rate_limiter.check_limit("login", ip_address or email)
        if not allowed:
            log_event(
                EventType.RATE_LIMIT_EXCEEDED,
                user=email,
                details={"retry_after": retry_after, "ip": ip_address},
                severity="WARNING",
                ip_address=ip_address
            )
            return False, f"Too many login attempts. Try again in {retry_after} seconds."
        
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT auth_verifier, wrapped_key, totp_secret FROM users WHERE email=?", (email,))
        row = c.fetchone()
        conn.close()
        
        if not row:
            log_event(
                EventType.LOGIN_FAILURE,
                user=email,
                details={"reason": "user_not_found", "ip": ip_address},
                severity="WARNING",
                ip_address=ip_address
            )
            return False, "Invalid credentials"
            
        auth_verifier_hash, wrapped_key_json, totp_secret = row
        
        # 1. Verify Password
        if not self.crypto.verify_password(auth_verifier_hash, password):
            log_event(
                EventType.LOGIN_FAILURE,
                user=email,
                details={"reason": "invalid_password", "ip": ip_address},
                severity="WARNING",
                ip_address=ip_address
            )
            return False, "Invalid credentials"
            
        # 2. Check 2FA (if programmed to interrupt here)
        # We unwrap MK now if password is correct, 
        # but DO NOT grant session until 2FA passed if secret exists.

        # 3. Unwrap Master Key
        wrapped_key = json.loads(wrapped_key_json)
        try:
            master_key = self.crypto.unwrap_master_key(wrapped_key, password)
        except Exception:
            log_event(
                EventType.LOGIN_FAILURE,
                user=email,
                details={"reason": "key_unwrap_failed", "ip": ip_address},
                severity="ERROR",
                ip_address=ip_address
            )
            return False, "Critical: Key Unwrapping Failed (Data Corruption?)"

        # Success - Pending 2FA or Done
        if totp_secret:
             self._temp_login_state = {
                 "email": email,
                 "master_key": master_key,
                 "ip_address": ip_address
             }
             return False, "AUTH_2FA_REQUIRED"
        
        # Reset rate limit on successful login
        self.rate_limiter.reset("login", ip_address or email)
        
        self._create_session(email, master_key)
        
        # Audit log: successful login
        log_event(
            EventType.LOGIN_SUCCESS,
            user=email,
            details={"ip": ip_address},
            severity="INFO",
            ip_address=ip_address
        )
        
        return True, "Login successful"

    def verify_2fa(self, code):
        if not hasattr(self, '_temp_login_state'):
            return False, "No pending login"
            
        email = self._temp_login_state["email"]
        
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("SELECT totp_secret FROM users WHERE email=?", (email,)).fetchone()
        conn.close()
        
        if row and row[0]: # Ensure secret exists
            totp = pyotp.TOTP(row[0])
            if totp.verify(code):
                 self._create_session(email, self._temp_login_state["master_key"])
                 del self._temp_login_state
                 return True, "2FA Verified"
        
        return False, "Invalid Code"

    def generate_2fa_secret(self, email):
        """Generates a random secret and returns it along with a QR code base64 string."""
        secret = pyotp.random_base32()
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="CamelliaShield")
        
        # Generate QR Code
        img = qrcode.make(uri)
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_b64 = base64.b64encode(buffered.getvalue()).decode()
        
        return secret, qr_b64

    def enable_2fa(self, email, secret, code):
        """Verifies the code against the new secret and enables 2FA if correct."""
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("UPDATE users SET totp_secret=? WHERE email=?", (secret, email))
            conn.commit()
            conn.close()
            return True, "2FA Enabled Successfully"
        return False, "Invalid Code"

    def disable_2fa(self, email):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("UPDATE users SET totp_secret=NULL WHERE email=?", (email,))
        conn.commit()
        conn.close()
        return True, "2FA Disabled"

    def _create_session(self, email, master_key):
        self.session = {
            "email": email,
            "master_key": master_key,
            "created_at": time.time(),
            "last_activity": time.time()
        }

    def get_session(self):
        # Implement timeout check
        if self.session:
            if time.time() - self.session["last_activity"] > 300: # 5 min timeout
                self.logout()
                return None
            self.session["last_activity"] = time.time()
        return self.session

    def logout(self):
        if self.session:
            email = self.session.get("email")
            
            # Audit log: logout
            log_event(
                EventType.LOGOUT,
                user=email,
                details={"session_duration": time.time() - self.session.get("created_at", time.time())},
                severity="INFO"
            )
            
            # Wipe key from memory (best effort)
            self.session["master_key"] = b'\x00' * 32 
        self.session = None

    def get_master_key(self):
        s = self.get_session()
        return s["master_key"] if s else None
