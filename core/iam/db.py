import os

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

def _default_db_path() -> str:
    if os.getenv("VERCEL"):
        return "/tmp/gatestack-dev.db"
    return os.path.join(os.getcwd(), "gatestack-dev.db")


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


def _ensure_project_upload_columns() -> None:
    inspector = inspect(engine)
    if not inspector.has_table("project_uploads"):
        return

    existing = {column["name"] for column in inspector.get_columns("project_uploads")}
    expected_columns = {
        "package_name": "VARCHAR(255) NOT NULL DEFAULT 'default-package'",
        "package_version": "VARCHAR(64) NOT NULL DEFAULT '1.0.0'",
        "description": "TEXT",
        "changelog": "TEXT",
        "checksum_sha256": "VARCHAR(64) NOT NULL DEFAULT ''",
        "visibility": "VARCHAR(32) NOT NULL DEFAULT 'private'",
        "lifecycle_status": "VARCHAR(32) NOT NULL DEFAULT 'pending'",
        "status_reason": "TEXT",
        "is_latest": "BOOLEAN NOT NULL DEFAULT 0",
        "shared_with": "TEXT",
        "metadata_json": "TEXT",
        "zip_entry_count": "INTEGER NOT NULL DEFAULT 0",
        "uncompressed_size_bytes": "INTEGER NOT NULL DEFAULT 0",
        "duplicate_of_id": "VARCHAR(36)",
        "download_count": "INTEGER NOT NULL DEFAULT 0",
        "reviewed_by": "INTEGER",
        "reviewed_at": "VARCHAR(64)",
        "submitted_at": "VARCHAR(64)",
        "approved_at": "VARCHAR(64)",
        "published_at": "VARCHAR(64)",
        "archived_at": "VARCHAR(64)",
        "rejected_at": "VARCHAR(64)",
    }

    with engine.begin() as connection:
        for column_name, column_sql in expected_columns.items():
            if column_name in existing:
                continue
            connection.execute(
                text(f"ALTER TABLE project_uploads ADD COLUMN {column_name} {column_sql}")
            )


def _backfill_project_share_grants() -> None:
    inspector = inspect(engine)
    if not inspector.has_table("project_uploads") or not inspector.has_table("project_share_grants"):
        return

    columns = {column["name"] for column in inspector.get_columns("project_uploads")}
    if "shared_with" not in columns:
        return

    with engine.begin() as connection:
        rows = connection.execute(
            text("SELECT id, shared_with FROM project_uploads WHERE shared_with IS NOT NULL AND shared_with != ''")
        ).fetchall()
        for project_id, shared_with in rows:
            for raw_user_id in str(shared_with).split(","):
                raw_user_id = raw_user_id.strip()
                if not raw_user_id:
                    continue
                try:
                    user_id = int(raw_user_id)
                except ValueError:
                    continue
                connection.execute(
                    text(
                        """
                        INSERT INTO project_share_grants (id, project_id, grantee_user_id, grant_role, created_at)
                        SELECT :id, :project_id, :grantee_user_id, :grant_role, :created_at
                        WHERE NOT EXISTS (
                          SELECT 1 FROM project_share_grants
                          WHERE project_id = :project_id AND grantee_user_id = :grantee_user_id
                        )
                        """
                    ),
                    {
                        "id": os.urandom(16).hex(),
                        "project_id": project_id,
                        "grantee_user_id": user_id,
                        "grant_role": "viewer",
                        "created_at": "1970-01-01T00:00:00+00:00",
                    },
                )


def init_db() -> None:
    from argon2 import PasswordHasher

    from core.iam.models import Base, Role, User

    Base.metadata.create_all(bind=engine)
    _ensure_project_upload_columns()
    _backfill_project_share_grants()

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

        admin_email = os.getenv("GATESTACK_DEV_EMAIL")
        admin_password = os.getenv("GATESTACK_DEV_PASSWORD")

        # Keep local development bootstrapping convenient, but never rely on
        # hardcoded credentials in production/serverless runtimes.
        if (not admin_email or not admin_password) and env == "development" and not is_serverless:
            admin_email = "rodrigo@mail.com"
            admin_password = "Nses@100"

        if not admin_email or not admin_password:
            return

        admin = db.query(User).filter_by(username=admin_email).first()
        if admin is None:
            admin = User(
                username=admin_email,
                password_hash=PasswordHasher().hash(admin_password),
                role=owner_role,
                is_active=True,
            )
            db.add(admin)
            db.commit()
    finally:
        db.close()
