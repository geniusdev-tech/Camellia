import os
import sys
import unittest
import json
from unittest.mock import patch

# Set environment variables before imports
os.environ['FLASK_ENV'] = 'development'
os.environ['SECRET_KEY'] = 'test-secret'

# Add root path to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

import core.iam.db
from core.iam.models import Base, User, Role
from core.crypto.engine import CryptoEngine
import pyotp
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

class TestMFAVulnerability(unittest.TestCase):
    def setUp(self):
        self.db_path = "test_enterprise_vuln.db"
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

        # Configure test database
        engine = create_engine(f"sqlite:///{self.db_path}")
        core.iam.db.engine = engine
        core.iam.db.SessionLocal = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)

        from app import create_app
        self.app = create_app()
        self.client = self.app.test_client()

        # Create user
        db = core.iam.db.SessionLocal()
        crypto = CryptoEngine()
        self.email = "victim@example.com"
        self.password = "victim-pass"

        role = Role(name="owner", permissions=["*"])
        db.add(role)
        db.commit()

        master_key = crypto.generate_master_key()
        wrapped_key = crypto.wrap_master_key(master_key, self.password)

        self.mfa_secret = pyotp.random_base32()
        user = User(
            username=self.email,
            password_hash=crypto.hash_password(self.password),
            wrapped_key=json.dumps(wrapped_key),
            role_id=role.id,
            mfa_secret_enc=self.mfa_secret
        )
        db.add(user)
        db.commit()
        self.user_id = user.id
        db.close()

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_mfa_session_bypass(self):
        # 1. Victim logs in (Phase 1)
        res = self.client.post('/api/auth/login', json={'email': self.email, 'password': self.password})
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.json.get('requires_mfa'))
        victim_user_id = res.json.get('user_id')

        # 2. Attacker (no session) tries to complete MFA
        totp = pyotp.TOTP(self.mfa_secret)
        code = totp.now()

        attacker_client = self.app.test_client()
        res = attacker_client.post('/api/auth/login/mfa', json={
            'code': code,
            'user_id': victim_user_id
        })

        print(f"\nResponse status: {res.status_code}")
        print(f"Response data: {res.json}")

        # VULNERABLE: returns 200
        self.assertEqual(res.status_code, 200, "VULNERABILITY: Attacker was able to complete MFA without session cookie!")
        self.assertTrue(res.json['success'])

if __name__ == '__main__':
    unittest.main()
