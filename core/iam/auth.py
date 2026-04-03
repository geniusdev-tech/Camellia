import os
import hashlib
import uuid
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
        raw_secret = os.getenv("SECRET_KEY", "gatestack-dev-secret")
        self._secret = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()

    def hash_password(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify_password(self, password_hash: str, password: str) -> bool:
        try:
            return self._hasher.verify(password_hash, password)
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    def _encode_token(
        self,
        sub: int | str,
        roles: list[str],
        token_type: str,
        minutes: int,
        extra: dict[str, Any] | None = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "sub": str(sub),
            "roles": roles,
            "type": token_type,
            "jti": uuid.uuid4().hex,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=minutes)).timestamp()),
        }
        if extra:
            payload.update(extra)
        return jwt.encode(payload, self._secret, algorithm="HS256")

    def create_access_token(self, sub: int | str, roles: list[str]) -> str:
        return self._encode_token(sub, roles, "access", 60)

    def create_refresh_token(self, sub: int | str, session_family: str | None = None) -> str:
        family = session_family or uuid.uuid4().hex
        return self._encode_token(
            sub,
            [],
            "refresh",
            60 * 24 * 7,
            extra={"family": family},
        )

    def decode_token(self, token: str) -> dict[str, Any] | None:
        try:
            return jwt.decode(token, self._secret, algorithms=["HS256"])
        except Exception:
            return None

    def generate_totp_secret(self) -> str:
        return pyotp.random_base32()

    def build_totp_uri(self, username: str, secret: str) -> str:
        return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="GateStack")

    def verify_totp_token(self, secret: str, code: str) -> bool:
        try:
            return pyotp.TOTP(secret).verify(code, valid_window=1)
        except Exception:
            return False
