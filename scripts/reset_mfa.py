import sys
import os
import json

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.iam.db import SessionLocal
from core.iam.models import User

def reset_admin_mfa():
    session = SessionLocal()
    try:
        user = session.query(User).filter_by(username="admin@rodrigo.mail").first()
        if user:
            print(f"Found user: {user.username}")
            if user.mfa_secret_enc:
                print("MFA was enabled. Disabling...")
                user.mfa_secret_enc = None
                session.commit()
                print("MFA disabled successfully.")
            else:
                print("MFA is already disabled for this user.")
        else:
            print("User admin@rodrigo.mail not found!")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        session.close()

if __name__ == "__main__":
    reset_admin_mfa()
