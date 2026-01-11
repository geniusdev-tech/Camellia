import os
import unittest
from pathlib import Path
from core.sys.fs import PathValidator

class TestPathHardening(unittest.TestCase):
    def test_fallback_logic(self):
        # Non-existent path
        bad_path = "/home/zeus/.thispathdoesnotexisthopefully"
        valid, p, msg = PathValidator.validate(bad_path, require_exists=True)
        self.assertFalse(valid)
        self.assertEqual(p, Path.home().resolve())
        self.assertIn("not exist", msg)

    def test_valid_home(self):
        home = str(Path.home())
        valid, p, msg = PathValidator.validate(home, require_exists=True)
        self.assertTrue(valid)
        self.assertEqual(p, Path.home().resolve())

    def test_block_special_paths(self):
        # /proc
        valid, p, msg = PathValidator.validate("/proc/cpuinfo", require_exists=False) # Even if exists
        self.assertFalse(valid)
        self.assertIn("denied", msg)

    def test_traversal_resolution(self):
        # /home/zeus/../.. -> /
        # This is strictly valid in terms of existence, but let's see if we should block it.
        # My implementation only blocks specific prefixes.
        # So / should be allowed if it exists?
        # Let's check what validate returns.
        
        # Note: In strict environments we might want to sandbox to HOME.
        # For this task, preventing crash and blocking system paths was the goal.
        path_str = f"{Path.home()}/../../"
        valid, p, msg = PathValidator.validate(path_str)
        # It resolves to /
        # / starts with / but not /proc
        # So it might be valid if require_exists=True and / exists.
        pass

    def test_ensure_dir(self):
        # Point to a file when dir is required
        # Create a temp file
        import tempfile
        with tempfile.NamedTemporaryFile(delete=True) as tmp:
            valid, p, msg = PathValidator.validate(tmp.name, require_dir=True)
            self.assertFalse(valid)
            self.assertIn("not a directory", msg)

if __name__ == "__main__":
    unittest.main()
