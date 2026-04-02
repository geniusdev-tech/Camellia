from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime, timezone
import uuid
import os


Base = declarative_base()

ROLE_PERMISSIONS = {
    "owner": {
        "vault:read",
        "vault:write",
        "audit:read",
    },
    "user": {
        "vault:read",
        "vault:write",
    },
}


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    wrapped_key = Column(Text, nullable=True)
    mfa_secret_enc = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=True)

    role = relationship("Role")

    def has_permission(self, permission: str) -> bool:
        role_name = self.role.name if self.role else "user"
        return permission in ROLE_PERMISSIONS.get(role_name, set())


class ProjectUpload(Base):
    __tablename__ = "project_uploads"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    content_type = Column(String(255), nullable=True)
    size_bytes = Column(Integer, nullable=False)
    storage_key = Column(String(512), nullable=False)
    bucket = Column(String(128), nullable=False, default=lambda: os.getenv("SUPABASE_BUCKET", ""))
    created_at = Column(
        String(64),
        nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )

    user = relationship("User")
