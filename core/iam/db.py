import os
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


DB_PATH = os.getenv("IAM_DB_PATH", os.path.join(os.getcwd(), "camellia-dev.db"))
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def init_db() -> None:
    from argon2 import PasswordHasher

    from core.crypto.engine import CryptoEngine
    from core.iam.models import Base, Role, User

    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        owner_role = db.query(Role).filter_by(name="owner").first()
        user_role = db.query(Role).filter_by(name="user").first()

        if owner_role is None:
            owner_role = Role(name="owner")
            db.add(owner_role)
        if user_role is None:
            user_role = Role(name="user")
            db.add(user_role)
        db.commit()

        admin_email = os.getenv("CAMELLIA_DEV_EMAIL", "rodrigo@mail.com")
        admin_password = os.getenv("CAMELLIA_DEV_PASSWORD", "Nses@100")
        admin = db.query(User).filter_by(username=admin_email).first()
        if admin is None:
            wrapped_key = CryptoEngine().wrap_master_key(
                CryptoEngine().generate_master_key(),
                admin_password,
            )
            admin = User(
                username=admin_email,
                password_hash=PasswordHasher().hash(admin_password),
                wrapped_key=json.dumps(wrapped_key),
                role=owner_role,
                is_active=True,
            )
            db.add(admin)
            db.commit()
        elif not admin.wrapped_key:
            admin.wrapped_key = json.dumps(
                CryptoEngine().wrap_master_key(
                    CryptoEngine().generate_master_key(),
                    admin_password,
                )
            )
            db.commit()
    finally:
        db.close()
