import jwt
import argon2
import pyotp
import uuid
import os
from datetime import datetime, timezone, timedelta

class AuthController:
    def __init__(self, db=None):
        self.db = db
        self.ph = argon2.PasswordHasher()
        self.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

    def hash_password(self, password: str) -> str:
        return self.ph.hash(password)

    def verify_password(self, password_hash: str, password: str) -> bool:
        try:
            return self.ph.verify(password_hash, password)
        except Exception:
            return False

    def create_access_token(self, user_id: int, roles: list[str]) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,
            "roles": roles,
            "type": "access",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=15)).timestamp()),
            "jti": str(uuid.uuid4())
        }
        return jwt.encode(payload, self.secret_key, algorithm="HS256")

    def create_refresh_token(self, user_id: int, family: str = None) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,
            "type": "refresh",
            "family": family or str(uuid.uuid4()),
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=7)).timestamp()),
            "jti": str(uuid.uuid4())
        }
        return jwt.encode(payload, self.secret_key, algorithm="HS256")

    def decode_token(self, token: str) -> dict | None:
        try:
            return jwt.decode(token, self.secret_key, algorithms=["HS256"])
        except Exception:
            return None

    def generate_totp_secret(self) -> str:
        return pyotp.random_base32()

    def verify_totp_token(self, secret: str, token: str) -> bool:
        totp = pyotp.TOTP(secret)
        return totp.verify(token)

    def build_totp_uri(self, email: str, secret: str) -> str:
        return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="GateStack")
