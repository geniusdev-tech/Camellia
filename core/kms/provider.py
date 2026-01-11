from abc import ABC, abstractmethod


class KMSProvider(ABC):
    """Abstract KMS provider interface for envelope encryption."""

    @abstractmethod
    def generate_data_key(self, key_name: str) -> tuple[bytes, bytes]:
        """Return (plaintext_dek, encrypted_dek)
        encrypted_dek is the ciphertext that must be stored alongside data.
        """

    @abstractmethod
    def decrypt_data_key(self, encrypted_dek: bytes, key_name: str) -> bytes:
        """Return plaintext DEK for use in data encryption/decryption.
        `key_name` is used as AAD/context when decrypting.
        """

    @abstractmethod
    def rotate_master_key(self):
        """Rotate the KMS master key (if supported)."""
