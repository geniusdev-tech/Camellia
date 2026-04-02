import base64
import json
import os
from typing import Any

from core.crypto.engine import CryptoEngine
from core.kms.aws_kms import AWSKMSProvider
from core.kms.file_kms import FileKMS
from core.kms.transit_kms import TransitKMSProvider


def _default_provider_name() -> str:
    if os.getenv("VERCEL"):
        if os.getenv("AWS_KMS_KEY_ID"):
            return "aws"
        if os.getenv("VAULT_ADDR") and os.getenv("VAULT_TOKEN") and os.getenv("VAULT_TRANSIT_KEY_NAME"):
            return "transit"
        return "disabled"
    return "file"


def create_runtime_kms(default_file_path: str) -> Any:
    provider = os.getenv("KMS_PROVIDER", _default_provider_name()).lower()

    if provider == "aws":
        key_id = os.getenv("AWS_KMS_KEY_ID")
        region_name = os.getenv("AWS_REGION")
        return AWSKMSProvider(key_id, region_name=region_name) if key_id else None

    if provider == "transit":
        return TransitKMSProvider(
            address=os.getenv("VAULT_ADDR"),
            token=os.getenv("VAULT_TOKEN"),
            key_name=os.getenv("VAULT_TRANSIT_KEY_NAME"),
            mount_path=os.getenv("VAULT_TRANSIT_MOUNT", "transit"),
        )

    if provider == "file":
        kms_path = os.getenv("KMS_FILE_PATH", default_file_path)
        return FileKMS(kms_path)

    return None


def wrap_master_key(master_key: str, password: str, kms: Any = None) -> dict[str, str]:
    if kms and hasattr(kms, "encrypt"):
        ciphertext = kms.encrypt(master_key.encode("utf-8"))
        return {
            "type": kms.__class__.__name__,
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
    return CryptoEngine().wrap_master_key(master_key, password)


def unwrap_master_key(wrapped: dict[str, Any], password: str, kms: Any = None) -> str:
    wrapped_type = wrapped.get("type")
    if wrapped_type in {"aws_kms", "AWSKMSProvider", "TransitKMSProvider"}:
        if not kms or not hasattr(kms, "decrypt"):
            raise RuntimeError("An external KMS provider is required to unwrap this master key")
        ciphertext = base64.b64decode(wrapped["ciphertext"])
        return kms.decrypt(ciphertext).decode("utf-8")
    return CryptoEngine().unwrap_master_key(wrapped, password)


def dump_wrapped_key(payload: dict[str, Any]) -> str:
    return json.dumps(payload)
