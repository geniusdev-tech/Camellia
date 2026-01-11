import os
import tempfile
from core.kms.file_kms import FileKMS
from core.vault.manager import VaultManager
from core.audit.logger import init_audit_logger


class FakeAuth:
    def __init__(self, mk):
        self._mk = mk

    def get_master_key(self):
        return self._mk

    def get_session(self):
        return {"email": "tester@example.com"}


def test_kms_envelope_roundtrip(tmp_path):
    mk = os.urandom(32)
    auth = FakeAuth(mk)

    # Initialize file KMS
    kms_file = tmp_path / 'kms.key'
    kms = FileKMS(str(kms_file))

    vm = VaultManager(str(tmp_path), auth, kms_provider=kms)
    # initialize audit logger
    init_audit_logger(os.path.join(str(tmp_path), 'audit.log'))

    # Create sample file
    sample = tmp_path / 'sample.txt'
    data = b'hello world - kms test'
    sample.write_bytes(data)

    ok, fid = vm.encrypt_file(str(sample))
    assert ok is True

    # Decrypt
    ok2, restored = vm.decrypt_file(fid)
    assert ok2 is True
    restored_path = tmp_path / restored
    assert restored_path.read_bytes() == data
