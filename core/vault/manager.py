import base64
import json
import os
import shutil
from pathlib import Path

from core.crypto.engine import CryptoEngine
from core.iam.session import key_manager


class VaultManager:
    def __init__(self, root_dir: str, auth_manager) -> None:
        self.root_dir = root_dir
        self.auth_manager = auth_manager

    def list_files(self, path: str, user_id=None) -> list[dict]:
        target = Path(path).expanduser().resolve()
        items: list[dict] = []
        for entry in sorted(
            target.iterdir(),
            key=lambda item: (not item.is_dir(), item.name.startswith("."), item.name.lower()),
        ):
            try:
                is_dir = entry.is_dir()
                stat = entry.stat()
            except OSError:
                continue
            items.append(
                {
                    "name": entry.name,
                    "path": str(entry),
                    "is_dir": is_dir,
                    "is_encrypted": entry.suffix == ".camellia",
                    "size": 0 if is_dir else stat.st_size,
                    "uuid": str(stat.st_ino),
                    "method": "rename",
                }
            )
        return items

    def delete_item(self, path: str, user_id=None) -> tuple[bool, str]:
        target = Path(path)
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink(missing_ok=True)
        return True, "Item removido"

    def transform_path(self, path: str, encrypt: bool, user_id=None) -> str:
        target = Path(path)
        if encrypt and target.suffix != ".camellia":
            master_key = key_manager.get_key(user_id) if user_id is not None else None
            if not master_key:
                raise PermissionError("Vault bloqueado ou sessão expirada")
            destination = target.with_name(target.name + ".camellia")
            cipher = CryptoEngine().build_file_cipher(master_key)
            raw = target.read_bytes()
            payload = {
                "name": target.name,
                "payload": base64.b64encode(cipher.encrypt(raw)).decode("ascii"),
            }
            destination.write_text(json.dumps(payload), encoding="utf-8")
            target.unlink()
            return str(destination)
        if not encrypt and target.suffix == ".camellia":
            master_key = key_manager.get_key(user_id) if user_id is not None else None
            if not master_key:
                raise PermissionError("Vault bloqueado ou sessão expirada")
            cipher = CryptoEngine().build_file_cipher(master_key)
            payload = json.loads(target.read_text(encoding="utf-8"))
            destination = target.with_name(payload.get("name") or target.stem)
            decrypted = cipher.decrypt(base64.b64decode(payload["payload"]))
            destination.write_bytes(decrypted)
            target.unlink()
            return str(destination)
        return str(target)
