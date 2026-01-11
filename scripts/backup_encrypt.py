#!/usr/bin/env python3
"""Create a tar.gz of given paths and encrypt with AES-GCM using provided key file."""
import argparse
import tarfile
import tempfile
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def create_archive(paths, out_path):
    with tarfile.open(out_path, 'w:gz') as tar:
        for p in paths:
            tar.add(p, arcname=os.path.basename(p))


def encrypt_file(key_path, in_path, out_path):
    with open(key_path, 'rb') as f:
        key = f.read()
    aes = AESGCM(key)
    nonce = os.urandom(12)
    with open(in_path, 'rb') as f:
        data = f.read()
    ct = aes.encrypt(nonce, data, None)
    with open(out_path, 'wb') as f:
        f.write(nonce + ct)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--key', required=True, help='Path to AES-256 key file')
    p.add_argument('--out', required=True, help='Encrypted output file')
    p.add_argument('paths', nargs='+')
    args = p.parse_args()

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        create_archive(args.paths, tmp.name)
        tmp.flush()
        encrypt_file(args.key, tmp.name, args.out)
        os.unlink(tmp.name)


if __name__ == '__main__':
    main()
