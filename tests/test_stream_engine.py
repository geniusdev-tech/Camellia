import os
from core.crypto.stream import StreamEngine


def test_stream_encrypt_decrypt(tmp_path):
    se = StreamEngine()
    key = os.urandom(32)

    input_path = tmp_path / "input.bin"
    input_path.write_bytes(os.urandom(200_000))

    enc_path = tmp_path / "input.enc"
    out_path = tmp_path / "output.bin"

    se.encrypt_stream(str(input_path), str(enc_path), key)
    se.decrypt_stream(str(enc_path), str(out_path), key)

    assert out_path.read_bytes() == input_path.read_bytes()

def test_stream_integrity_failure(tmp_path):
    import pytest
    se = StreamEngine()
    key = b"0" * 32

    input_path = tmp_path / "input.bin"
    input_path.write_bytes(b"Sensitive data that should not be truncated.")

    enc_path = tmp_path / "input.enc"
    out_path = tmp_path / "output.bin"

    # Encrypt
    se.encrypt_stream(str(input_path), str(enc_path), key)

    # Truncate to header only (V3 Header: 97 bytes)
    HEADER_SIZE = 97
    with open(enc_path, "rb") as f:
        header = f.read(HEADER_SIZE)
    with open(enc_path, "wb") as f:
        f.write(header)

    # Decrypt should fail
    with pytest.raises(ValueError, match="INTEGRITY CHECK FAILED"):
        se.decrypt_stream(str(enc_path), str(out_path), key)
