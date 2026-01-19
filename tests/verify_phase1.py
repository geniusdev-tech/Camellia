import sys
import os
import json
import unittest
import time

# Add root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from core.iam.db import SessionLocal, init_db
from core.iam.models import User

class TestPhase1(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.db = SessionLocal()
        
    def tearDown(self):
        self.db.close()

    def test_full_flow(self):
        print("\n--- Testing Full Auth & Vault Flow ---")
        
        # 1. Login (Initial)
        resp = self.client.post('/api/auth/login', json={
            'email': 'admin@rodrigo.mail',
            'password': 'Nses@100'
        })
        print(f"Login Response: {resp.json}")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json['success'])
        
        token = resp.json['access_token']
        headers = {'Authorization': f'Bearer {token}'}
        
        # 2. Setup MFA
        print("Setting up MFA...")
        resp = self.client.post('/api/auth/mfa/setup', headers=headers)
        self.assertEqual(resp.status_code, 200)
        secret = resp.json['secret']
        print(f"MFA Secret: {secret}")
        
        # 3. Verify MFA
        import pyotp
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        resp = self.client.post('/api/auth/mfa/verify', headers=headers, json={'code': code})
        self.assertEqual(resp.status_code, 200)
        print("MFA Verified.")
        
        # 4. Login with MFA
        print("Logging in again with MFA flow...")
        resp = self.client.post('/api/auth/login', json={
            'email': 'admin@rodrigo.mail',
            'password': 'Nses@100'
        })
        self.assertTrue(resp.json['requires_mfa'])
        
        # Provide Code
        code = totp.now()
        # We need to maintain session cookie for 'pre_auth_user_id'
        with self.client.session_transaction() as sess:
             sess['pre_auth_user_id'] = resp.json['user_id']
             
        resp = self.client.post('/api/auth/login/mfa', json={
            'code': code,
            'user_id': resp.json['user_id']
        })
        # Note: test_client cookie handling might need explicit jar usage if we rely on session.
        # But 'login/mfa' checks 'user_id' in body as fallback in my code.
        
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json['success'])
        token = resp.json['access_token']
        headers = {'Authorization': f'Bearer {token}'}
        print("Login with MFA Successful.")
        
        # 5. Vault Operation (List Files)
        print("Listing Vault Files...")
        resp = self.client.post('/api/files/list', headers=headers, json={'path': '/home/zeus/Documentos'}) # Use a real path
        if resp.status_code == 404:
             # Folder might not exist, try '.'
             resp = self.client.post('/api/files/list', headers=headers, json={'path': '.'})
        
        print(f"List Files Response: {resp.status_code} - {resp.json.get('msg', 'OK')}")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json['success'])
        
        # 6. Encrypt Test File
        test_file = 'test_encrypt.txt'
        with open(test_file, 'w') as f:
            f.write("Secret Content")
            
        print("Encrypting File...")
        resp = self.client.post('/api/process/start', headers=headers, json={
            'path': os.path.abspath(test_file),
            'encrypt': True
        })
        print(f"Encrypt Task: {resp.json}")
        self.assertEqual(resp.status_code, 200)
        task_id = resp.json['task_id']
        
        # Wait for task
        for _ in range(10):
            time.sleep(1)
            status_resp = self.client.get(f'/api/process/status/{task_id}', headers=headers)
            status = status_resp.json['status']
            print(f"Task Status: {status}")
            if status in ['Completed', 'Error']:
                break
        
        self.assertEqual(status, 'Completed')
        print("Encryption Verified.")

if __name__ == '__main__':
    unittest.main()
