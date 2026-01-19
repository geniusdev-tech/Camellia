import sys
import os
import json

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.iam.db import init_db, SessionLocal
from core.iam.models import User, Role
from core.iam.auth import AuthController
from core.crypto.engine import CryptoEngine

def main():
    print("Initializing IAM Database...")
    init_db()
    
    session = SessionLocal()
    auth = AuthController(session)
    crypto = CryptoEngine()
    
    # Create Roles
    roles_data = [
        {"name": "owner", "permissions": ["*"], "description": "System Owner"},
        {"name": "admin", "permissions": ["user:*", "audit:*", "backup:*"], "description": "Administrator"},
        {"name": "auditor", "permissions": ["audit:read"], "description": "Compliance Auditor"},
        {"name": "user", "permissions": ["vault:*"], "description": "Regular User"},
        {"name": "readonly", "permissions": ["vault:read", "vault:decrypt"], "description": "Read Only User"}
    ]
    
    for r_data in roles_data:
        if not session.query(Role).filter_by(name=r_data['name']).first():
            role = Role(name=r_data['name'], permissions=r_data['permissions'], description=r_data['description'])
            session.add(role)
            print(f"Created role: {role.name}")
    
    session.commit()
    
    # Create admin@rodrigo.mail
    if not session.query(User).filter_by(username="admin@rodrigo.mail").first():
        password = "Nses@100"
        
        # 1. Hash Password
        pw_hash = auth.hash_password(password)
        
        # 2. Generate and Wrap Master Key
        master_key = crypto.generate_master_key()
        wrapped_key = crypto.wrap_master_key(master_key, password)
        
        owner_role = session.query(Role).filter_by(name="owner").first()
        
        user = User(
            username="admin@rodrigo.mail",
            password_hash=pw_hash,
            wrapped_key=json.dumps(wrapped_key),
            role=owner_role,
            is_active=True
        )
        session.add(user)
        print(f"Created default user: admin@rodrigo.mail / {password}")
    
    session.commit()
    session.close()
    print("Initialization Complete.")

if __name__ == "__main__":
    main()
