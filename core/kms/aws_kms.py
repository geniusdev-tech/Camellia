class AWSKMSProvider:
    def __init__(self, key_id: str | None, region_name: str | None = None) -> None:
        self.key_id = key_id
        self.region_name = region_name

    def get_key(self) -> bytes:
        raise RuntimeError("AWS KMS provider is not available in local development mode")
