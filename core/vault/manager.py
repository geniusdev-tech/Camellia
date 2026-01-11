import os
import json
import uuid
import shutil
import time
import base64
from cryptography.fernet import Fernet
from core.crypto.engine import CryptoEngine
from core.crypto.stream import StreamEngine
from core.audit.logger import log_event, EventType
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

MANIFEST_FILENAME = "vault_manifest.enc"
MAX_MANIFEST_BACKUPS = 5  # Keep 5 backup versions

class VaultManager:
    def __init__(self, root_path, auth_manager, kms_provider=None):
        self.root_path = root_path
        self.auth_manager = auth_manager
        self.crypto_engine = CryptoEngine()
        self.stream_engine = StreamEngine()
        self.kms = kms_provider
        self.manifest = {}
        
    def _get_keys(self):
        mk = self.auth_manager.get_master_key()
        if not mk: raise PermissionError("Vault Locked or Session Expired")
        
        # Derive keys
        manifest_key = self.crypto_engine.derive_subkey(mk, b"manifest_encryption")
        file_key = self.crypto_engine.derive_subkey(mk, b"file_encryption_base")
        
        # Fernet keys must be urlsafe b64
        return {
            "manifest": base64.urlsafe_b64encode(manifest_key),
            "file_fernet": base64.urlsafe_b64encode(file_key),
            "file_aes": file_key # Raw bytes for AES-GCM
        }

    def _manifest_signing_key_paths(self):
        # Key files inside vault root
        priv = os.path.join(self.root_path, '.manifest_signing_key')
        pub = priv + '.pub'
        return priv, pub

    def _load_or_generate_manifest_key(self):
        priv_path, pub_path = self._manifest_signing_key_paths()
        if os.path.exists(priv_path):
            with open(priv_path, 'rb') as f:
                key_data = f.read()
                return serialization.load_pem_private_key(key_data, password=None)

        # Generate new Ed25519 key pair
        private_key = ed25519.Ed25519PrivateKey.generate()
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(priv_path, 'wb') as f:
            f.write(priv_pem)
        with open(pub_path, 'wb') as f:
            f.write(pub_pem)

        os.chmod(priv_path, 0o600)
        os.chmod(pub_path, 0o644)
        return private_key

    def _sign_manifest_blob(self, blob: bytes) -> bytes:
        """Sign raw bytes (the encrypted manifest blob) and return signature bytes."""
        priv = self._load_or_generate_manifest_key()
        sig = priv.sign(blob)
        return sig

    def _verify_manifest_signature(self, blob: bytes, sig: bytes) -> bool:
        priv_path, pub_path = self._manifest_signing_key_paths()
        if not os.path.exists(pub_path):
            return False
        try:
            with open(pub_path, 'rb') as f:
                pub_pem = f.read()
            pub = serialization.load_pem_public_key(pub_pem)
            pub.verify(sig, blob)
            return True
        except Exception:
            return False

    def _load_manifest(self):
        keys = self._get_keys()
        manifest_path = os.path.join(self.root_path, MANIFEST_FILENAME)
        
        if not os.path.exists(manifest_path):
            self.manifest = {}
            return

        with open(manifest_path, "rb") as f:
            encrypted_data = f.read()
        # If signature file exists, verify first
        sig_path = manifest_path + '.sig'
        if os.path.exists(sig_path):
            try:
                with open(sig_path, 'rb') as sf:
                    sig = sf.read()
                if not self._verify_manifest_signature(encrypted_data, sig):
                    # Signature verification failed - possible tampering
                    raise ValueError('Manifest signature verification failed')
            except Exception:
                # Treat manifest as missing/corrupted
                self.manifest = {}
                return

        fernet = Fernet(keys["manifest"])
        try:
            data = fernet.decrypt(encrypted_data)
            self.manifest = json.loads(data)
        except Exception:
            self.manifest = {}

    def _save_manifest(self):
        keys = self._get_keys()
        manifest_path = os.path.join(self.root_path, MANIFEST_FILENAME)
        
        data = json.dumps(self.manifest).encode()
        fernet = Fernet(keys["manifest"])
        encrypted_data = fernet.encrypt(data)

        # Sign encrypted blob for tamper-evidence (signature stored alongside manifest)
        try:
            signature = self._sign_manifest_blob(encrypted_data)
        except Exception:
            signature = None

        # Atomic write with backup rotation
        temp_path = manifest_path + '.tmp'
        
        # Write to temporary file first
        with open(temp_path, 'wb') as f:
            f.write(encrypted_data)
            f.flush()
            os.fsync(f.fileno())
        
        # Rotate backups if manifest exists
        if os.path.exists(manifest_path):
            # Keep last 5 backups
            for i in range(MAX_MANIFEST_BACKUPS - 1, 0, -1):
                old_backup = f"{manifest_path}.bak.{i}"
                new_backup = f"{manifest_path}.bak.{i+1}"
                if os.path.exists(old_backup):
                    shutil.move(old_backup, new_backup)
            
            # Backup current manifest
            shutil.copy2(manifest_path, f"{manifest_path}.bak.1")
        
        # Atomic replace
        os.replace(temp_path, manifest_path)

        # Write signature file (hex) next to manifest
        if signature is not None:
            sig_path = manifest_path + '.sig'
            with open(sig_path + '.tmp', 'wb') as f:
                f.write(signature)
                f.flush()
                os.fsync(f.fileno())
            os.replace(sig_path + '.tmp', sig_path)
            os.chmod(sig_path, 0o600)
        
        # Audit log
        session = self.auth_manager.get_session()
        if session:
            log_event(
                EventType.MANIFEST_MODIFIED,
                user=session['email'],
                details={"num_files": len(self.manifest)},
                severity="INFO"
            )

    def encrypt_file(self, file_path, progress_callback=None, device_id="local"):
        """Encrypts a file using StreamEngine (AES-GCM)."""
        self._load_manifest()
        keys = self._get_keys()
        if not os.path.exists(file_path): return False, "File not found"
        
        file_uuid = str(uuid.uuid4())
        from core.security.sanitizers import sanitize_filename, sanitize_path

        filename = sanitize_filename(os.path.basename(file_path))
        
        target_dir = sanitize_path(os.path.dirname(file_path)) or '.'
        target_path = os.path.join(target_dir, file_uuid)
        
        # Helper wrapper for callback
        def cb(curr, total):
            if progress_callback: progress_callback(curr, total, file_uuid)

        try:
            # Determine encryption key: use KMS envelope if configured
            if self.kms is not None:
                dek_plain, enc_dek = self.kms.generate_data_key(file_uuid)
                # Store encrypted DEK in manifest
                self.manifest[file_uuid] = {
                    "encrypted_dek": enc_dek.decode('utf-8') if isinstance(enc_dek, (bytes, bytearray)) else enc_dek,
                }
                enc_key = dek_plain
                method_name = "kms-envelope-aead"
            else:
                enc_key = keys["file_aes"]
                method_name = "aes-gcm-stream"

            # Encrypt stream using chosen key
            self.stream_engine.encrypt_stream(
                file_path,
                target_path,
                enc_key,
                progress_callback=cb
            )
            
            # Verify? (Optional hash check, costly for large files)
            
            # Update Manifest
            # Merge/ensure metadata
            meta = self.manifest.get(file_uuid, {})
            meta.update({
                "original_name": filename,
                "original_path": file_path,
                "timestamp": time.time(),
                "parent_dir": target_dir,
                "size": os.path.getsize(file_path),
                "device_id": device_id,
                "method": method_name
            })
            self.manifest[file_uuid] = meta
            self._save_manifest()
            
            # Delete Original
            os.remove(file_path)
            
            # Audit log: successful encryption
            session = self.auth_manager.get_session()
            if session:
                log_event(
                    EventType.FILE_ENCRYPT,
                    user=session['email'],
                    details={
                        "file": filename,
                        "size": self.manifest[file_uuid]["size"],
                        "device": device_id
                    },
                    severity="INFO"
                )
            
            return True, file_uuid
            
        except Exception as e:
            if os.path.exists(target_path):
                os.remove(target_path)
            
            # Audit log: encryption failure
            session = self.auth_manager.get_session()
            if session:
                log_event(
                    EventType.FILE_ENCRYPT,
                    user=session['email'],
                    details={"file": filename, "error": str(e)},
                    severity="ERROR"
                )
            
            return False, str(e)

    def decrypt_file(self, file_uuid, progress_callback=None):
        self._load_manifest()
        keys = self._get_keys()
        
        if file_uuid not in self.manifest:
            return False, "File ID not found in manifest"
            
        meta = self.manifest[file_uuid]
        from core.security.sanitizers import sanitize_filename, sanitize_path
        parent_dir = sanitize_path(meta.get("parent_dir", ".")) or '.'
        encrypted_path = os.path.join(parent_dir, file_uuid)
        
        if not os.path.exists(encrypted_path):
            return False, "Encrypted file missing"
            
        # Restore Path
        restore_path = os.path.join(meta["parent_dir"], meta["original_name"])
        
        def cb(curr, total):
            if progress_callback: progress_callback(curr, total, file_uuid)

        try:
            method = meta.get("method", "fernet-legacy")

            if method.startswith("kms-envelope") and self.kms is not None:
                enc_dek = meta.get("encrypted_dek")
                if not enc_dek:
                    raise ValueError("Missing encrypted DEK for KMS envelope")
                dek = self.kms.decrypt_data_key(enc_dek.encode('utf-8') if isinstance(enc_dek, str) else enc_dek, file_uuid)
                self.stream_engine.decrypt_stream(
                    encrypted_path,
                    restore_path,
                    dek,
                    progress_callback=cb
                )
            elif method == "aes-gcm-stream":
                self.stream_engine.decrypt_stream(
                    encrypted_path,
                    restore_path,
                    keys["file_aes"],
                    progress_callback=cb
                )
            else:
                # Legacy Fernet
                with open(encrypted_path, "rb") as f:
                    enc_data = f.read()
                fernet = Fernet(keys["file_fernet"])
                raw_data = fernet.decrypt(enc_data)
                with open(restore_path, "wb") as f:
                    f.write(raw_data)
                    
            # Cleanup
            os.remove(encrypted_path)
            del self.manifest[file_uuid]
            self._save_manifest()
            
            # Audit log: successful decryption
            session = self.auth_manager.get_session()
            if session:
                log_event(
                    EventType.FILE_DECRYPT,
                    user=session['email'],
                    details={
                        "file": meta["original_name"],
                        "size": meta.get("size", 0)
                    },
                    severity="INFO"
                )
            
            return True, meta["original_name"]
            
        except Exception as e:
            if os.path.exists(restore_path): os.remove(restore_path) # Partial cleanup
            import traceback
            tb = traceback.format_exc()

            # Audit log: decryption failure
            session = self.auth_manager.get_session()
            if session:
                log_event(
                    EventType.FILE_DECRYPT,
                    user=session['email'],
                    details={"file_uuid": file_uuid, "error": str(e), "trace": tb},
                    severity="ERROR"
                )

            return False, f"Decryption Failed: {repr(e)}\n{tb}"

    def list_files(self, directory):
        self._load_manifest()
        items = []
        uuid_map = {uid: m for uid, m in self.manifest.items() if m["parent_dir"] == directory}
        
        if os.path.exists(directory):
            try:
                # Use context manager for scandir and catch errors
                with os.scandir(directory) as entries:
                    for entry in entries:
                        try:
                            if entry.name == MANIFEST_FILENAME: continue
                            
                            if entry.name in uuid_map:
                                meta = uuid_map[entry.name]
                                items.append({
                                    "name": meta["original_name"],
                                    "is_encrypted": True,
                                    "uuid": entry.name,
                                    "path": entry.path,
                                    "is_dir": False,
                                    "size": meta.get("size", 0),
                                    "method": meta.get("method", "legacy")
                                })
                            else:
                                # Safe stat access
                                try:
                                    stats = entry.stat()
                                    size = stats.st_size
                                    is_dir = entry.is_dir()
                                except FileNotFoundError:
                                    continue # File disappeared

                                items.append({
                                    "name": entry.name,
                                    "is_encrypted": False,
                                    "path": entry.path,
                                    "is_dir": is_dir,
                                    "size": size
                                })
                        except (OSError, PermissionError):
                            continue # Skip bad entries
                            
            except (FileNotFoundError, PermissionError, OSError):
                # Directory inaccessible or disappeared
                pass
                
        return items

    def encrypt_batch(self, items, device_id="local", recursive=False):
        """
        Encrypts a list of files or directories.
        Returns a generator of progress/status updates.
        """
        queue = []
        
        # 1. Expand Directories
        for item_path in items:
            if os.path.isdir(item_path):
                if recursive:
                    for root, dirs, files in os.walk(item_path):
                        for f in files:
                            if f != MANIFEST_FILENAME and not f.endswith(".enc"): # Skip manifest/temp
                                queue.append(os.path.join(root, f))
            else:
                queue.append(item_path)
                
        # 2. Process Queue
        total_files = len(queue)
        processed_count = 0
        
        for file_path in queue:
            if os.path.basename(file_path) in self.manifest:
                yield {"status": "skipped", "file": file_path, "msg": "Already Encrypted"}
                continue
                
            success, res = self.encrypt_file(file_path, device_id=device_id)
            processed_count += 1
            
            yield {
                "status": "success" if success else "error",
                "file": file_path,
                "msg": res,
                "progress_global": (processed_count / total_files) * 100
            }

    def decrypt_batch(self, items, recursive=False):
        """
        Decrypts a list of files (UUIDs or paths resolving to UUIDs) or directories.
        Returns a generator of progress/status updates.
        """
        self._load_manifest()
        queue = []
        
        # 1. Expand Directories / Resolve Paths to UUIDs
        for item_path in items:
            if os.path.isdir(item_path):
                if recursive:
                    # Find all UUID files in this directory that are in manifest
                    for root, dirs, files in os.walk(item_path):
                        for f in files:
                            if f in self.manifest:
                                queue.append(f) # UUID
            else:
                # If item_path is a path, is it a UUID file or original name?
                # The UI sends paths.
                # If encrypted, the file on disk IS the UUID.
                filename = os.path.basename(item_path)
                if filename in self.manifest:
                    queue.append(filename)
                else:
                    # Maybe user selected original name but we only see it if listed?
                    # VaultManager.list_files returns "path" as the disk path (which is UUID for encrypted).
                    # So item_path should end in UUID.
                    pass
                    
        total_files = len(queue)
        processed_count = 0
        
        for file_uuid in queue:
            success, res = self.decrypt_file(file_uuid)
            processed_count += 1
            
            yield {
                "status": "success" if success else "error",
                "file": file_uuid, # We return UUID or original name?
                "msg": res,
                "progress_global": (processed_count / total_files) * 100
            }
