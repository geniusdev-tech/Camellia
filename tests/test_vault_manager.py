import os
import tempfile
from core.vault.manager import VaultManager
from core.audit.logger import init_audit_logger


class FakeAuth:
    def __init__(self, mk):
        self._mk = mk

    def get_master_key(self):
        return self._mk

    def get_session(self):
        return {"email": "tester@example.com"}


def test_manifest_save_and_load(tmp_path):
    mk = os.urandom(32)
    auth = FakeAuth(mk)
    # initialize audit logger to avoid RuntimeError during _save_manifest
    audit_log = os.path.join(str(tmp_path), 'audit.log')
    init_audit_logger(audit_log)

    vm = VaultManager(str(tmp_path), auth)
    # populate manifest minimally
    vm.manifest = {
        "file1": {
            "original_name": "a.txt",
            "parent_dir": str(tmp_path),
            "size": 10,
            "timestamp": 0
        }
    }

    vm._save_manifest()

    manifest_path = os.path.join(str(tmp_path), "vault_manifest.enc")
    assert os.path.exists(manifest_path)
    assert os.path.exists(manifest_path + ".sig")

    # Load into a fresh manager instance
    vm2 = VaultManager(str(tmp_path), auth)
    vm2._load_manifest()
    assert isinstance(vm2.manifest, dict)
    assert "file1" in vm2.manifest
