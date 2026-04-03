import os
from pathlib import Path
from typing import BinaryIO, Dict, Any
from urllib.parse import quote

import requests

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")


def upload_to_supabase(bucket: str, filename: str, content: bytes, content_type: str) -> Dict[str, Any]:
    from io import BytesIO

    return upload_file_to_supabase(bucket, filename, BytesIO(content), content_type)


def upload_file_to_supabase(
    bucket: str,
    filename: str,
    file_obj: BinaryIO,
    content_type: str,
) -> Dict[str, Any]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        raise RuntimeError("Supabase storage credentials are not configured")
    url = f"{SUPABASE_URL.rstrip('/')}/storage/v1/object/{bucket}"
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "apikey": SUPABASE_SERVICE_KEY,
    }
    files = {
        "file": (Path(filename).name, file_obj, content_type),
    }
    response = requests.post(url, headers=headers, files=files)
    if not response.ok:
        raise RuntimeError(f"Supabase upload failed: {response.status_code} {response.text}")
    return response.json()


def create_signed_download_url(bucket: str, storage_key: str, expires_in: int = 900) -> str:
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        raise RuntimeError("Supabase storage credentials are not configured")

    path = quote(storage_key.lstrip("/"), safe="/")
    url = f"{SUPABASE_URL.rstrip('/')}/storage/v1/object/sign/{bucket}/{path}"
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "apikey": SUPABASE_SERVICE_KEY,
        "Content-Type": "application/json",
    }
    response = requests.post(url, headers=headers, json={"expiresIn": expires_in})
    if not response.ok:
        raise RuntimeError(f"Supabase signed URL failed: {response.status_code} {response.text}")

    data = response.json()
    signed_path = data.get("signedURL") or data.get("signedUrl")
    if not signed_path:
        raise RuntimeError("Supabase signed URL response missing signed URL")
    if signed_path.startswith("http://") or signed_path.startswith("https://"):
        return signed_path
    return f"{SUPABASE_URL.rstrip('/')}{signed_path}"


def delete_from_supabase(bucket: str, storage_key: str) -> None:
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        raise RuntimeError("Supabase storage credentials are not configured")

    path = quote(storage_key.lstrip("/"), safe="/")
    url = f"{SUPABASE_URL.rstrip('/')}/storage/v1/object/{bucket}/{path}"
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
        "apikey": SUPABASE_SERVICE_KEY,
    }
    response = requests.delete(url, headers=headers)
    if response.status_code not in (200, 204):
        raise RuntimeError(f"Supabase delete failed: {response.status_code} {response.text}")
