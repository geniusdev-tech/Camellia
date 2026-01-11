import base64
import boto3
from unittest.mock import patch, MagicMock
from core.kms.aws_kms import AWSKMSProvider


def test_aws_kms_generate_decrypt(monkeypatch):
    mock_client = MagicMock()
    # fake plaintext and ciphertext
    mock_client.generate_data_key.return_value = {
        'Plaintext': b'\x00' * 32,
        'CiphertextBlob': b'cipher'
    }
    mock_client.decrypt.return_value = {'Plaintext': b'\x00' * 32}

    with patch('boto3.client', return_value=mock_client):
        kms = AWSKMSProvider('alias/test')
        plain, enc = kms.generate_data_key('file1')
        assert len(plain) == 32
        # enc should be base64
        assert base64.b64decode(enc) == b'cipher'

        dec = kms.decrypt_data_key(enc, 'file1')
        assert dec == plain
