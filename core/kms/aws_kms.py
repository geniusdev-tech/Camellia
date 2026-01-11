import base64
import os
from typing import Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .provider import KMSProvider


class AWSKMSProvider(KMSProvider):
    """AWS KMS provider using GenerateDataKey/Decrypt APIs.

    Expects AWS credentials available in environment or instance role.
    """

    def __init__(self, key_id: str, region_name: str | None = None):
        self.key_id = key_id
        self.client = boto3.client('kms', region_name=region_name)

    def generate_data_key(self, key_name: str) -> Tuple[bytes, bytes]:
        try:
            resp = self.client.generate_data_key(KeyId=self.key_id, KeySpec='AES_256')
            plaintext = resp['Plaintext']
            ciphertext = resp['CiphertextBlob']
            return plaintext, base64.b64encode(ciphertext)
        except (BotoCoreError, ClientError) as e:
            raise RuntimeError(f"KMS generate_data_key failed: {e}")

    def decrypt_data_key(self, encrypted_dek: bytes, key_name: str) -> bytes:
        try:
            blob = base64.b64decode(encrypted_dek)
            resp = self.client.decrypt(CiphertextBlob=blob)
            return resp['Plaintext']
        except (BotoCoreError, ClientError) as e:
            raise RuntimeError(f"KMS decrypt_data_key failed: {e}")

    def rotate_master_key(self):
        # Rotation in AWS KMS is managed by key policy; nothing to do client-side.
        raise NotImplementedError("Rotation managed by AWS KMS key policies")
