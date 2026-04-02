import os
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


class AuthController:
    def __init__(self, db) -> None:
        self.db = db
        self._hasher = PasswordHasher()
        self._secret = os.getenv("SECRET_KEY", "camellia-dev-secret")

    def hash_password(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify_password(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    def _encode_token(self, sub: int | str, roles: list[str], token_type: str, minutes: int) -> str:
        now = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "sub": str(sub),
            "roles": roles,
            "type": token_type,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=minutes)).timestamp()),
        }
        return jwt.encode(payload, self._secret, algorithm="HS256")

    def create_access_token(self, sub: int | str, roles: list[str]) -> str:
        return self._encode_token(sub, roles, "access", 60)

    def create_refresh_token(self, sub: int | str) -> str:
        return self._encode_token(sub, [], "refresh", 60 * 24 * 7)

    def decode_token(self, token: str) -> dict[str, Any] | None:
        try:
            return jwt.decode(token, self._secret, algorithms=["HS256"])
        except Exception:
            return None

    def generate_totp_secret(self) -> str:
        return pyotp.random_base32()

    def build_totp_uri(self, username: str, secret: str) -> str:
        return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="Camellia Shield")

    def verify_totp_token(self, secret: str, code: str) -> bool:
        try:
            return pyotp.TOTP(secret).verify(code, valid_window=1)
        except Exception:
            return False
