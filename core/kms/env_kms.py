from cryptography.fernet import Fernet


class EnvKMSProvider:
    def __init__(self, encryption_key: str | None) -> None:
        if not encryption_key:
            raise ValueError("MASTER_KEY_ENCRYPTION_KEY is required")
        self._fernet = Fernet(encryption_key.encode("utf-8"))

    def encrypt(self, plaintext: bytes) -> bytes:
        return self._fernet.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self._fernet.decrypt(ciphertext)
