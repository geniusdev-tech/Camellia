
import unittest
import os
import shutil
import time
import sys
# Add root path to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from core.crypto.stream import StreamEngine
from core.crypto.engine import CryptoEngine
from core.vault.manager import VaultManager
from core.auth.manager import AuthManager

class TestStreamingAndBatch(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        
        # Setup Test Environment
        self.test_dir = "test_data"
        if os.path.exists(self.test_dir): shutil.rmtree(self.test_dir)
        os.makedirs(self.test_dir)
        
        # Auth Manager Stub
        self.db_path = "test_users.db"
        if os.path.exists(self.db_path): os.remove(self.db_path)
        self.auth = AuthManager(self.db_path)
        self.auth.register("admin@test.com", "admin123")
        self.auth.login("admin@test.com", "admin123")
        
        self.vault = VaultManager(self.test_dir, self.auth)

    def tearDown(self):
        if os.path.exists(self.test_dir): shutil.rmtree(self.test_dir)
        if os.path.exists(self.db_path): os.remove(self.db_path)

    def test_stream_crypto_large_file(self):
        """Test streaming encryption on a simulated large file."""
        # Create a file larger than chunks
        fname = os.path.join(self.test_dir, "large_file.bin")
        size = 1024 * 1024 * 5 # 5MB
        with open(fname, "wb") as f:
            f.write(os.urandom(size))
            
        initial_hash = self._file_hash(fname)
        
        # Encrypt
        success, uuid_res = self.vault.encrypt_file(fname)
        self.assertTrue(success)
        
        # Verify Manifest
        self.assertIn(uuid_res, self.vault.manifest)
        self.assertEqual(self.vault.manifest[uuid_res]['method'], 'aes-gcm-stream')
        
        # Decrypt
        success, name_res = self.vault.decrypt_file(uuid_res)
        self.assertTrue(success)
        
        # Verify Hash
        restored_path = os.path.join(self.test_dir, "large_file.bin")
        self.assertTrue(os.path.exists(restored_path))
        self.assertEqual(self._file_hash(restored_path), initial_hash)

    def test_batch_encryption_recursive(self):
        """Test recursive batch encryption."""
        # Structure:
        # test_data/
        #   folder1/
        #     file1.txt
        #     subfolder/
        #       file2.txt
        
        f1 = os.path.join(self.test_dir, "folder1")
        f2 = os.path.join(f1, "subfolder")
        os.makedirs(f2)
        
        with open(os.path.join(f1, "file1.txt"), "w") as f: f.write("DATA1")
        with open(os.path.join(f2, "file2.txt"), "w") as f: f.write("DATA2")
        
        # Run Batch via Generator directly
        items = [f1] # Select the folder
        gen = self.vault.encrypt_batch(items, recursive=True)
        results = list(gen)
        
        self.assertEqual(len(results), 2)
        self.assertTrue(all(r['status'] == 'success' for r in results))
        
        # Verify Manifest count
        self.assertEqual(len(self.vault.manifest), 2)
        
    def test_batch_decryption(self):
        """Test recursive batch decryption."""
        # Setup encrypted files
        f1 = os.path.join(self.test_dir, "to_encrypt.txt")
        with open(f1, "w") as f: f.write("SECRET")
        
        # Encrypt first
        gen = self.vault.encrypt_batch([f1])
        list(gen)
        
        # Now Batch Decrypt
        # We pass the path of the original file? Or the folder?
        # The API likely passes the list of selected paths from the UI.
        # If the file is encrypted, the UI sees "original_name" (mapped to UUID path internally if we kept that logic, 
        # but wait, VaultManager.list_files returns UUID path for encrypted items ?
        # Let's check VaultManager.list_files mock logic. 
        #  It returns item['path'] = entry.path (which is UUID on disk).
        # So we pass the UUID path.
        
        uuid_path = None
        for k, v in self.vault.manifest.items():
            if v['original_name'] == "to_encrypt.txt":
                uuid_path = os.path.join(v['parent_dir'], k)
                break
                
        self.assertTrue(uuid_path)
        
        gen = self.vault.decrypt_batch([uuid_path])
        results = list(gen)
        
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['status'], 'success')
        self.assertTrue(os.path.exists(f1))
        with open(f1, "r") as f: self.assertEqual(f.read(), "SECRET")

    def test_device_detection_logic(self):
        """Unit test for logic parsing mounts (mocked)."""
        from core.sys.devices import DeviceManager
        dm = DeviceManager()
        
        # Mock _read_mounts
        dm._read_mounts = lambda: [
            {'device': '/dev/sdb1', 'path': '/media/user/MyUSB', 'fs': 'vfat'},
            {'device': '/dev/sda1', 'path': '/', 'fs': 'ext4'}
        ]
        
        # Mock user
        dm.user = "user"
        
        devices = dm.list_devices()
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0]['name'], 'MyUSB')
        self.assertEqual(devices[0]['type'], 'usb')

    def _file_hash(self, path):
        import hashlib
        sha = hashlib.sha256()
        with open(path, 'rb') as f:
            while True:
                data = f.read(65536)
                if not data: break
                sha.update(data)
        return sha.hexdigest()

if __name__ == '__main__':
    unittest.main()
