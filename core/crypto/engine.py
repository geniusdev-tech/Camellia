import base64
import hashlib
import os
from io import BytesIO

from cryptography.fernet import Fernet
import qrcode


class CryptoEngine:
    def generate_master_key(self) -> str:
        return base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")

    def _password_key(self, password: str) -> bytes:
        digest = hashlib.sha256(password.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)

    def wrap_master_key(self, master_key: str, password: str) -> dict[str, str]:
        token = Fernet(self._password_key(password)).encrypt(master_key.encode("utf-8"))
        return {"token": token.decode("utf-8")}

    def unwrap_master_key(self, wrapped: dict[str, str], password: str) -> str:
        token = wrapped["token"].encode("utf-8")
        return Fernet(self._password_key(password)).decrypt(token).decode("utf-8")

    def build_file_cipher(self, master_key: str) -> Fernet:
        digest = hashlib.sha256(master_key.encode("utf-8")).digest()
        return Fernet(base64.urlsafe_b64encode(digest))

    def make_qr_data_url(self, value: str) -> str:
        image = qrcode.make(value)
        buffer = BytesIO()
        image.save(buffer, format="PNG")
        encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
