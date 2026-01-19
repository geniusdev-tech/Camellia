from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from core.iam.models import Base
import os

# Use a separate DB for IAM implementation or migrate the existing one
# For now, we will use a new DB file to avoid breaking the existing raw SQLite one immediately,
# or better yet, use the same file but let SQLAlchemy manage tables.
# Existing DB is ~/.camellia_users.db and has 'users' table.
# SQLAlchemy 'users' table definition might conflict if columns differ.
# We will use ~/.camellia_enterprise.db for the V2 features to be safe during dev.

DB_PATH = os.path.expanduser("~/.camellia_enterprise.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
