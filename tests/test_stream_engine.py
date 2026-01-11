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
