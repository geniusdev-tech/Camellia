import os
import time
import pyotp
import qrcode
import jwt
import base64
from io import BytesIO
from typing import Tuple, Optional
from datetime import datetime, timedelta

# Import Crypto Engine for password hashing
from core.crypto.engine import CryptoEngine

# Secret for signing JWTs (should be loaded from config/env)
JWT_SECRET = os.getenv('JWT_SECRET', os.getenv('SECRET_KEY', 'dev-secret-change-me'))
JWT_ALGORITHM = "HS256"
MFA_ISSUER = "Camellia Shield Enterprise"

class AuthController:
    def __init__(self, db_session):
        self.db = db_session
        self.crypto = CryptoEngine()

    def verify_password(self, password_hash: str, password: str) -> bool:
        """Verify password against Argon2id hash."""
        return self.crypto.verify_password(password_hash, password)

    def hash_password(self, password: str) -> str:
        """Hash password using Argon2id."""
        return self.crypto.hash_password(password)

    # --- MFA Logic ---

    def generate_mfa_secret(self, username: str) -> Tuple[str, str]:
        """
        Generates a new TOTP secret and QR Code.
        Returns: (secret, qr_base64)
        """
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=username, issuer_name=MFA_ISSUER)
        
        # Generate QR Code
        img = qrcode.make(uri)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        qr_b64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
        
        return secret, qr_b64

    def verify_totp_token(self, secret: str, token: str) -> bool:
        """Verifies a TOTP token against a secret."""
        if not secret:
            return False
        totp = pyotp.TOTP(secret)
        return totp.verify(token)

    # --- Session / Token Logic ---

    def create_access_token(self, user_id: int, roles: list) -> str:
        """Creates a JWT access token."""
        payload = {
            "sub": str(user_id),
            "roles": roles,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(minutes=60) # Short lived
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    def create_refresh_token(self, user_id: int) -> str:
        """Creates a long-lived refresh token."""
        payload = {
            "sub": str(user_id),
            "type": "refresh",
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=7)
        }
        return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    def decode_token(self, token: str) -> Optional[dict]:
        """Decodes and validates a JWT token."""
        try:
            return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            print("Token Expired")
            return None # Expired
        except jwt.InvalidTokenError as e:
            print(f"Invalid Token: {e}")
            return None # Invalid
