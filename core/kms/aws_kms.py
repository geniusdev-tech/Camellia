import boto3


class AWSKMSProvider:
    def __init__(self, key_id: str | None, region_name: str | None = None) -> None:
        if not key_id:
            raise ValueError("AWS KMS key id is required")
        self.key_id = key_id
        self.region_name = region_name
        self._client = boto3.client("kms", region_name=region_name)

    def encrypt(self, plaintext: bytes) -> bytes:
        response = self._client.encrypt(KeyId=self.key_id, Plaintext=plaintext)
        return response["CiphertextBlob"]

    def decrypt(self, ciphertext: bytes) -> bytes:
        response = self._client.decrypt(CiphertextBlob=ciphertext, KeyId=self.key_id)
        return response["Plaintext"]
