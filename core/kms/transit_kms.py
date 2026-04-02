import base64

import requests


class TransitKMSProvider:
    def __init__(self, address: str | None, token: str | None, key_name: str | None, mount_path: str | None = None) -> None:
        if not address:
            raise ValueError("Vault address is required")
        if not token:
            raise ValueError("Vault token is required")
        if not key_name:
            raise ValueError("Vault transit key name is required")

        self.address = address.rstrip("/")
        self.token = token
        self.key_name = key_name
        self.mount_path = (mount_path or "transit").strip("/")
        self._headers = {
            "X-Vault-Token": token,
            "Content-Type": "application/json",
        }

    def _url(self, action: str) -> str:
        return f"{self.address}/v1/{self.mount_path}/{action}/{self.key_name}"

    def encrypt(self, plaintext: bytes) -> bytes:
        payload = {
            "plaintext": base64.b64encode(plaintext).decode("ascii"),
        }
        response = requests.post(self._url("encrypt"), headers=self._headers, json=payload, timeout=15)
        response.raise_for_status()
        ciphertext = response.json()["data"]["ciphertext"]
        return ciphertext.encode("utf-8")

    def decrypt(self, ciphertext: bytes) -> bytes:
        payload = {
            "ciphertext": ciphertext.decode("utf-8"),
        }
        response = requests.post(self._url("decrypt"), headers=self._headers, json=payload, timeout=15)
        response.raise_for_status()
        plaintext = response.json()["data"]["plaintext"]
        return base64.b64decode(plaintext)
