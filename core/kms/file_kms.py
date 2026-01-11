import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from core.kms.provider import KMSProvider


class FileKMS(KMSProvider):
    """Simple file-backed KMS for local testing only.

    Stores a single master key in a file (protected via file perms) and
    performs envelope encryption of data keys using AESGCM.
    """

    def __init__(self, key_path: str):
        self.key_path = key_path
        if not os.path.exists(key_path):
            mk = AESGCM.generate_key(bit_length=256)
            with open(key_path, 'wb') as f:
                f.write(mk)
            os.chmod(key_path, 0o600)

    def _load_master(self) -> bytes:
        with open(self.key_path, 'rb') as f:
            return f.read()

    def generate_data_key(self, key_name: str) -> tuple[bytes, bytes]:
        master = self._load_master()
        dek = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(master)
        nonce = os.urandom(12)
        enc = aesgcm.encrypt(nonce, dek, key_name.encode())
        # Return plaintext dek and ciphertext blob (nonce + enc)
        return dek, base64.b64encode(nonce + enc)

    def decrypt_data_key(self, encrypted_dek: bytes, key_name: str) -> bytes:
        master = self._load_master()
        data = base64.b64decode(encrypted_dek)
        nonce = data[:12]
        enc = data[12:]
        aesgcm = AESGCM(master)
        return aesgcm.decrypt(nonce, enc, key_name.encode())

    def rotate_master_key(self):
        # For local KMS: generate new master and overwrite file
        mk = AESGCM.generate_key(bit_length=256)
        with open(self.key_path, 'wb') as f:
            f.write(mk)
        os.chmod(self.key_path, 0o600)
