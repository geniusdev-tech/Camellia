import sys
import os
import unittest

# Add root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app

class TestMFAProbe(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_mfa_probe_fails(self):
        # Try to call login/mfa with a user_id but NO session
        resp = self.client.post('/api/auth/login/mfa', json={
            'code': '123456',
            'user_id': 1
        })

        # Should return 'Credenciais inválidas' (401)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.json['msg'], 'Credenciais inválidas')
        print("MFA Probe Fails as expected.")

if __name__ == '__main__':
    unittest.main()
