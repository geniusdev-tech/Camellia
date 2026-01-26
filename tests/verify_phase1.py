import sys
import os
import json
import unittest
import time
import pyotp

# Add root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import create_app
from core.iam.db import SessionLocal, init_db
from core.iam.models import User, Role
from core.iam.auth import AuthController
from core.crypto.engine import CryptoEngine

def setup_test_user(db):
    """Ensure admin user exists with correct password and no MFA."""
    role = db.query(Role).filter_by(name='owner').first()
    if not role:
        role = Role(name='owner', permissions=['*'])
        db.add(role); db.commit(); db.refresh(role)

    user = db.query(User).filter_by(username='admin@rodrigo.mail').first()
    controller = AuthController(db)
    if not user:
        user = User(username='admin@rodrigo.mail', role_id=role.id)
        db.add(user)

    user.password_hash = controller.hash_password('Nses@100')
    user.is_active = True
    user.mfa_secret_enc = None

    if not user.wrapped_key:
        crypto = CryptoEngine()
        mk = crypto.generate_master_key()
        user.wrapped_key = json.dumps(crypto.wrap_master_key(mk, 'Nses@100'))

    db.commit()
    return user

class TestPhase1(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()
        self.db = SessionLocal()
        setup_test_user(self.db)
        
    def tearDown(self):
        self.db.close()

    def test_full_flow(self):
        print("\n--- Testing Full Auth & Vault Flow ---")
        
        # 1. Login (Initial)
        resp = self.client.post('/api/auth/login', json={'email': 'admin@rodrigo.mail', 'password': 'Nses@100'})
        self.assertTrue(resp.json['success'])
        token = resp.json['access_token']
        headers = {'Authorization': f'Bearer {token}'}
        
        # 2. Setup MFA
        resp = self.client.post('/api/auth/mfa/setup', headers=headers)
        secret = resp.json['secret']
        
        # 3. Verify MFA
        totp = pyotp.TOTP(secret)
        resp = self.client.post('/api/auth/mfa/verify', headers=headers, json={'code': totp.now()})
        self.assertEqual(resp.status_code, 200)
        
        # 4. Login with MFA
        resp = self.client.post('/api/auth/login', json={'email': 'admin@rodrigo.mail', 'password': 'Nses@100'})
        self.assertTrue(resp.json['requires_mfa'])
        
        # 5. Provide Code (User ID comes from session)
        resp = self.client.post('/api/auth/login/mfa', json={'code': totp.now()})
        self.assertEqual(resp.status_code, 200)
        token = resp.json['access_token']
        headers = {'Authorization': f'Bearer {token}'}
        
        # 6. Vault Operation (List Files)
        resp = self.client.post('/api/files/list', headers=headers, json={'path': '.'})
        self.assertTrue(resp.json['success'])
        
        # 7. Encrypt Test File
        test_file = 'test_encrypt.txt'
        with open(test_file, 'w') as f: f.write("Secret Content")
            
        resp = self.client.post('/api/process/start', headers=headers, json={'path': os.path.abspath(test_file), 'encrypt': True})
        task_id = resp.json['task_id']
        
        # Wait for task
        for _ in range(5):
            time.sleep(1)
            status = self.client.get(f'/api/process/status/{task_id}', headers=headers).json['status']
            if status in ['Completed', 'Error']: break
        
        self.assertEqual(status, 'Completed')
        if os.path.exists(test_file): os.remove(test_file)

if __name__ == '__main__':
    unittest.main()
