
import os
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from core.crypto.engine import CryptoEngine
try:
    from nacl.bindings import (
        crypto_aead_xchacha20poly1305_ietf_encrypt,
        crypto_aead_xchacha20poly1305_ietf_decrypt,
    )
    _HAS_PYNACL = True
except Exception:
    _HAS_PYNACL = False

AEAD_ALGO = os.getenv('AEAD_ALGO', 'AESGCM').upper()

# Format:
# HEADER (Variable)
#   Magic (4 bytes): b'CAM2'  # Version 2 with AES-256
#   Salt (16 bytes)
#   NoncePrefix (12 bytes)
#   FileHash (64 bytes) - Blake2b hash of plaintext for integrity
# CHUNKS
#   Size (4 bytes)
#   Ciphertext (Size bytes) -> Includes Tag (16 bytes implicitly by AESGCM)

MAGIC = b'CAM2'  # Upgraded to v2 (AES-256)
CHUNK_SIZE = 64 * 1024 # 64KB chunks
TAG_SIZE = 16
HASH_SIZE = 64  # Blake2b produces 64-byte hash

class StreamEngine:
    def __init__(self):
        self.crypto = CryptoEngine()

    def encrypt_stream(self, input_path, output_path, key, progress_callback=None):
        """
        Encrypts a file in chunks using AES-256-GCM with Blake2b integrity verification.
        Key must be 32 bytes (256 bits) for military-grade AES-256.
        """
        # Validate key size for AES-256
        if len(key) != 32:
            raise ValueError(f"Key must be exactly 32 bytes for AES-256, got {len(key)} bytes")
        
        file_size = os.path.getsize(input_path)
        processed = 0
        
        salt = os.urandom(16)
        if AEAD_ALGO == 'XCHACHA20' and _HAS_PYNACL:
            # XChaCha20 uses 24-byte nonce; reserve 16 bytes prefix + 8-byte chunk idx
            nonce_prefix = os.urandom(16)
        else:
            nonce_prefix = os.urandom(12)
        
        # Step 1: Compute Blake2b hash of plaintext for integrity verification
        file_hash = hashlib.blake2b()
        with open(input_path, 'rb') as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
                file_hash.update(chunk)
        file_hash_digest = file_hash.digest()  # 64 bytes
        
        # Use CryptoEngine AEAD abstraction
        aead_name = self.crypto.get_aead_name()
        
        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            # Write Header with integrity hash
            fout.write(MAGIC)
            fout.write(salt)
            fout.write(nonce_prefix)
            fout.write(file_hash_digest)  # Blake2b hash for verification
            
            chunk_idx = 0
            while True:
                chunk = fin.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                if aead_name == 'XCHACHA20' and _HAS_PYNACL:
                    effective_nonce_prefix = nonce_prefix[:16]
                    nonce = effective_nonce_prefix + struct.pack('>Q', chunk_idx)
                    ciphertext = self.crypto.aead_encrypt(key, nonce, chunk, None)
                else:
                    effective_nonce_prefix = nonce_prefix[:8]
                    nonce = effective_nonce_prefix + struct.pack('>I', chunk_idx)
                    ciphertext = self.crypto.aead_encrypt(key, nonce, chunk, None)
                
                # Write Chunk Size (4 bytes) + Ciphertext
                fout.write(struct.pack('>I', len(ciphertext)))
                fout.write(ciphertext)
                
                chunk_idx += 1
                processed += len(chunk)
                if progress_callback:
                    progress_callback(processed, file_size)

    def decrypt_stream(self, input_path, output_path, key, progress_callback=None):
        """
        Decrypts a file encrypted with encrypt_stream.
        Verifies Blake2b integrity hash after decryption.
        Supports backward compatibility with CAM1 (AES-128) format.
        """
        # Validate key size for AES-256
        if len(key) != 32:
            raise ValueError(f"Key must be exactly 32 bytes for AES-256, got {len(key)} bytes")
        
        file_size = os.path.getsize(input_path)
        processed = 0
        
        with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
            # Read Header
            magic = fin.read(4)
            
            # Check format version
            is_v2 = (magic == b'CAM2')
            is_v1_legacy = (magic == b'CAM1')
            
            if not is_v2 and not is_v1_legacy:
                raise ValueError(f"Invalid File Format. Expected CAM2 or CAM1, got {magic}")
            
            salt = fin.read(16)
            if AEAD_ALGO == 'XCHACHA20' and _HAS_PYNACL:
                nonce_prefix = fin.read(16)
            else:
                nonce_prefix = fin.read(12)
            
            # V2 has Blake2b hash, V1 doesn't
            expected_hash = None
            if is_v2:
                expected_hash = fin.read(HASH_SIZE)  # 64 bytes
            
            if AEAD_ALGO == 'XCHACHA20' and _HAS_PYNACL:
                effective_nonce_prefix = nonce_prefix[:16]
            else:
                effective_nonce_prefix = nonce_prefix[:8]
            
            aead_name = self.crypto.get_aead_name()
            
            # For V2, compute hash while decrypting
            computed_hash = hashlib.blake2b() if is_v2 else None
            
            chunk_idx = 0
            while True:
                # Read Chunk Size
                size_data = fin.read(4)
                if not size_data:
                    break
                
                chunk_len = struct.unpack('>I', size_data)[0]
                ciphertext = fin.read(chunk_len)
                
                if len(ciphertext) != chunk_len:
                    raise ValueError("Truncated ciphertext - file may be corrupted")
                if aead_name == 'XCHACHA20' and _HAS_PYNACL:
                    nonce = effective_nonce_prefix + struct.pack('>Q', chunk_idx)
                    try:
                        plaintext = self.crypto.aead_decrypt(key, nonce, ciphertext, None)
                    except Exception as err:
                        raise ValueError(f"Decryption failed - invalid key or corrupted data: {err}")
                else:
                    nonce = effective_nonce_prefix + struct.pack('>I', chunk_idx)
                    try:
                        plaintext = self.crypto.aead_decrypt(key, nonce, ciphertext, None)
                    except Exception as err:
                        raise ValueError(f"Decryption failed - invalid key or corrupted data: {err}")
                
                fout.write(plaintext)
                
                # Update hash for V2
                if is_v2:
                    computed_hash.update(plaintext)
                
                chunk_idx += 1
                processed += chunk_len
                if progress_callback:
                    progress_callback(processed, file_size)
            
            # Verify integrity hash for V2
            if is_v2:
                if computed_hash.digest() != expected_hash:
                    # Delete output file on integrity failure
                    fout.close()
                    if os.path.exists(output_path):
                        os.remove(output_path)
                    raise ValueError("INTEGRITY CHECK FAILED: File hash mismatch. File may be corrupted or tampered with!")


