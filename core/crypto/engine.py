import os
import base64
import json
from argon2 import PasswordHasher, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
try:
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_encrypt,
        crypto_aead_xchacha20poly1305_ietf_decrypt,
    )
    _HAS_PYNACL = True
except Exception:
    _HAS_PYNACL = False

# AEAD selection: 'AESGCM' or 'XCHACHA20'
AEAD_ALGO = os.getenv('AEAD_ALGO', 'AESGCM').upper()

import os

# Constants with sensible, configurable defaults. Allowed to be tuned via env.
ARGON2_PARAMS = {
    "time_cost": int(os.getenv('ARGON2_TIME_COST', 3)),      # iterations
    "memory_cost": int(os.getenv('ARGON2_MEMORY_KB', 65536)), # in KB (64MB)
    "parallelism": int(os.getenv('ARGON2_PARALLELISM', 4)),
    "hash_len": int(os.getenv('ARGON2_HASH_LEN', 32)),
    "salt_len": int(os.getenv('ARGON2_SALT_LEN', 16)),
    "type": Type.ID
}

# Master key length (bytes)
MASTER_KEY_LEN = int(os.getenv('MASTER_KEY_LEN', 32))

class CryptoEngine:
    def __init__(self):
        # PasswordHasher primarily used for password verification storage
        self.ph = PasswordHasher(time_cost=ARGON2_PARAMS['time_cost'],
                     memory_cost=ARGON2_PARAMS['memory_cost'],
                     parallelism=ARGON2_PARAMS['parallelism'])
        self.current_master_key = None # Loaded in memory only during session

    def hash_password(self, password: str) -> str:
        """Hash password for storage (Auth verifier only)."""
        return self.ph.hash(password)

    def verify_password(self, hash_str: str, password: str) -> bool:
        try:
            return self.ph.verify(hash_str, password)
        except:
            return False

    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Derive a key from password using Argon2id manually for encryption keys."""
        # Using the low-level hash to get raw bytes for crypto keys
        # We need a predictable derived key for unwrapping the master key
        from argon2.low_level import hash_secret_raw, Type
        
        return hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=ARGON2_PARAMS["time_cost"],
            memory_cost=ARGON2_PARAMS["memory_cost"],
            parallelism=ARGON2_PARAMS["parallelism"],
            hash_len=ARGON2_PARAMS["hash_len"],
            type=Type.ID
        )

    def generate_master_key(self) -> bytes:
        """Generate a new random master key (256-bit for military-grade security)."""
        return os.urandom(MASTER_KEY_LEN)

    def wrap_master_key(self, master_key: bytes, password: str) -> dict:
        """Encrypts the Master Key using the user's password."""
        salt = os.urandom(16)
        kek = self.derive_key_from_password(password, salt) # Key Encryption Key
        # Select AEAD nonce size per algorithm
        aead_name = self.get_aead_name()
        if aead_name == 'XCHACHA20':
            # XChaCha20-Poly1305 uses 24-byte nonce
            nonce = os.urandom(24)
        else:
            nonce = os.urandom(12)

        encrypted_mk = self.aead_encrypt(kek, nonce, master_key, None)

        return {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext": base64.b64encode(encrypted_mk).decode('utf-8'),
            "aead": aead_name
        }

    def unwrap_master_key(self, wrapped_data: dict, password: str) -> bytes:
        """Decrypts the Master Key using the user's password."""
        salt = base64.b64decode(wrapped_data["salt"])
        nonce = base64.b64decode(wrapped_data["nonce"])
        ciphertext = base64.b64decode(wrapped_data["ciphertext"])
        
        kek = self.derive_key_from_password(password, salt)
        try:
            return self.aead_decrypt(kek, nonce, ciphertext, None)
        except Exception:
            raise ValueError("Invalid Password or Corrupted Key")

    def derive_subkey(self, master_key: bytes, context: bytes) -> bytes:
        """Derive a specific purpose subkey (e.g., 'auth', 'file_enc')."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=context,
        )
        return hkdf.derive(master_key)

    def get_aead_name(self) -> str:
        """Return the AEAD algorithm name in use."""
        if AEAD_ALGO == 'XCHACHA20' and _HAS_PYNACL:
            return 'XCHACHA20'
        return 'AESGCM'

    def aead_encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes | None = None, algo: str | None = None) -> bytes:
        """Encrypt using the selected AEAD."""
        target_algo = algo or self.get_aead_name()
        if target_algo == 'XCHACHA20':
            # PyNaCl bindings expect bytes key and nonce (24 bytes)
            return crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad or b'', nonce, key)
        else:
            aesgcm = AESGCM(key)
            return aesgcm.encrypt(nonce, plaintext, aad)

    def aead_decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes | None = None, algo: str | None = None) -> bytes:
        """Decrypt using the selected AEAD."""
        target_algo = algo or self.get_aead_name()
        if target_algo == 'XCHACHA20':
            return crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad or b'', nonce, key)
        else:
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(nonce, ciphertext, aad)
