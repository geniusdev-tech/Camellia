
import unittest
import json
import os
import sys
# Add root path to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from core.crypto.engine import CryptoEngine
import pyotp

class Test2FA(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.app.config['TESTING'] = True
        
        # Reset DB for tests
        if os.path.exists("users.db"):
            os.remove("users.db")
            
        # Register a user
        self.email = "test@example.com"
        self.password = "password123"
        self.client.post('/api/auth/register', json={'email': self.email, 'password': self.password})

    def tearDown(self):
        if os.path.exists("users.db"):
            os.remove("users.db")

    def test_2fa_flow(self):
        # 1. Login (Success, no 2FA)
        res = self.client.post('/api/auth/login', json={'email': self.email, 'password': self.password})
        self.assertTrue(res.json['success'])
        
        # 2. Setup 2FA
        res = self.client.post('/api/auth/2fa/setup')
        self.assertTrue(res.json['success'])
        secret = res.json['secret']
        self.assertIsNotNone(secret)
        
        # 3. Confirm 2FA
        totp = pyotp.TOTP(secret)
        code = totp.now()
        res = self.client.post('/api/auth/2fa/confirm', json={'secret': secret, 'code': code})
        self.assertTrue(res.json['success'])
        
        # 4. Status Check
        res = self.client.get('/api/auth/status')
        self.assertTrue(res.json['has_2fa'])
        
        # 5. Logout
        self.client.post('/api/auth/logout')
        
        # 6. Login (Should require 2FA)
        res = self.client.post('/api/auth/login', json={'email': self.email, 'password': self.password})
        self.assertFalse(res.json['success'])
        self.assertTrue(res.json['requires_2fa'])
        
        # 7. Verify 2FA
        # Note: In real app, /login returns state but verify_2fa relies on manager state.
        # However, Flask test client preserves cookies/session.
        # But wait, manager._temp_login_state is stored in the instance effectively... 
        # Actually Manager is re-instantiated or singleton?
        # In api/auth.py we do `from services import auth_manager`.
        # If `services.py` creates a singleton, it persists in memory for the process.
        # Let's hope services.py does what I think it does.
        # If not, this test might fail if Manager state is lost.
        # But `app.test_client()` is one process usually.
        
        code = totp.now()
        res = self.client.post('/api/auth/2fa/verify', json={'code': code})
        self.assertTrue(res.json['success'])
        
        # 8. Disable 2FA
        res = self.client.post('/api/auth/2fa/disable')
        self.assertTrue(res.json['success'])
        
        # 9. Status Check (No 2FA)
        res = self.client.get('/api/auth/status')
        self.assertFalse(res.json['has_2fa'])
        
        # 10. Logout and Login again (No 2FA)
        self.client.post('/api/auth/logout')
        res = self.client.post('/api/auth/login', json={'email': self.email, 'password': self.password})
        self.assertTrue(res.json['success'])
        self.assertNotIn('requires_2fa', res.json)

if __name__ == '__main__':
    unittest.main()
