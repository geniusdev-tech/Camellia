import os
import json

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from core.kms.manager import create_runtime_kms, wrap_master_key


def _default_db_path() -> str:
    if os.getenv("VERCEL"):
        return "/tmp/camellia-dev.db"
    return os.path.join(os.getcwd(), "camellia-dev.db")


def _resolve_database_url() -> str:
    database_url = (
        os.getenv("IAM_DATABASE_URL")
        or os.getenv("DATABASE_URL")
        or os.getenv("POSTGRES_URL")
    )
    if database_url:
        if database_url.startswith("postgres://"):
            return database_url.replace("postgres://", "postgresql+psycopg://", 1)
        if database_url.startswith("postgresql://") and "+psycopg" not in database_url:
            return database_url.replace("postgresql://", "postgresql+psycopg://", 1)
        return database_url
    return f"sqlite:///{os.getenv('IAM_DB_PATH', _default_db_path())}"


DATABASE_URL = _resolve_database_url()
ENGINE_KWARGS = {"pool_pre_ping": True}

if DATABASE_URL.startswith("sqlite:///"):
    ENGINE_KWARGS["connect_args"] = {"check_same_thread": False}
elif os.getenv("VERCEL"):
    ENGINE_KWARGS["poolclass"] = NullPool

engine = create_engine(DATABASE_URL, **ENGINE_KWARGS)
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

        env = os.getenv("FLASK_ENV", "production").lower()
        is_serverless = bool(os.getenv("VERCEL"))

        admin_email = os.getenv("CAMELLIA_DEV_EMAIL")
        admin_password = os.getenv("CAMELLIA_DEV_PASSWORD")

        # Keep local development bootstrapping convenient, but never rely on
        # hardcoded credentials in production/serverless runtimes.
        if (not admin_email or not admin_password) and env == "development" and not is_serverless:
            admin_email = "rodrigo@mail.com"
            admin_password = "Nses@100"

        if not admin_email or not admin_password:
            return

        admin = db.query(User).filter_by(username=admin_email).first()
        if admin is None:
            kms = create_runtime_kms("/tmp/kms.key" if os.getenv("VERCEL") else os.path.join(os.getcwd(), "kms.key"))
            wrapped_key = wrap_master_key(
                CryptoEngine().generate_master_key(),
                admin_password,
                kms=kms,
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
            kms = create_runtime_kms("/tmp/kms.key" if os.getenv("VERCEL") else os.path.join(os.getcwd(), "kms.key"))
            admin.wrapped_key = json.dumps(
                wrap_master_key(
                    CryptoEngine().generate_master_key(),
                    admin_password,
                    kms=kms,
                )
            )
            db.commit()
    finally:
        db.close()
