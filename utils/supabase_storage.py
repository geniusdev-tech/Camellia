import os
from typing import Dict, Any

import requests

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")


def upload_to_supabase(bucket: str, filename: str, content: bytes, content_type: str) -> Dict[str, Any]:
    if not SUPABASE_URL or not SUPABASE_SERVICE_KEY:
        raise RuntimeError("Supabase storage credentials are not configured")
    url = f"{SUPABASE_URL.rstrip('/')}/storage/v1/object/{bucket}"
    headers = {
        "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
    }
    files = {
        "file": (filename, content, content_type),
    }
    response = requests.post(url, headers=headers, files=files)
    if not response.ok:
        raise RuntimeError(f"Supabase upload failed: {response.status_code} {response.text}")
    return response.json()
