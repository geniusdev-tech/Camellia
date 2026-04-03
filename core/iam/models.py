from sqlalchemy import Boolean, Column, Enum, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime, timezone
import uuid
import os


Base = declarative_base()

ROLE_PERMISSIONS = {
    "owner": {
        "projects:read",
        "projects:write",
        "projects:read_all",
        "projects:approve",
        "projects:share",
        "audit:read",
    },
    "user": {
        "projects:read",
        "projects:write",
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


class RefreshTokenSession(Base):
    __tablename__ = "refresh_token_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_jti = Column(String(64), nullable=False, unique=True, index=True)
    token_type = Column(String(32), nullable=False, default="refresh")
    issued_at = Column(
        String(64),
        nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )
    expires_at = Column(String(64), nullable=False)
    revoked_at = Column(String(64), nullable=True)
    replaced_by_jti = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    ip_address = Column(String(64), nullable=True)

    user = relationship("User")


class Team(Base):
    __tablename__ = "teams"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(255), nullable=False, unique=True)
    owner_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    created_at = Column(
        String(64),
        nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )

    owner = relationship("User")


class TeamMember(Base):
    __tablename__ = "team_members"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    team_id = Column(String(36), ForeignKey("teams.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role = Column(String(32), nullable=False, default="member")
    created_at = Column(
        String(64),
        nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )

    team = relationship("Team")
    user = relationship("User")


class ShareInvite(Base):
    __tablename__ = "share_invites"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    team_id = Column(String(36), ForeignKey("teams.id"), nullable=False, index=True)
    email = Column(String(255), nullable=False, index=True)
    token = Column(String(64), nullable=False, unique=True, index=True)
    role = Column(String(32), nullable=False, default="member")
    expires_at = Column(String(64), nullable=True)
    accepted_at = Column(String(64), nullable=True)
    created_at = Column(
        String(64),
        nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )

    team = relationship("Team")


class ProjectUpload(Base):
    __tablename__ = "project_uploads"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    package_name = Column(String(255), nullable=False, default="default-package", index=True)
    package_version = Column(String(64), nullable=False, default="1.0.0", index=True)
    filename = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    changelog = Column(Text, nullable=True)
    content_type = Column(String(255), nullable=True)
    size_bytes = Column(Integer, nullable=False)
    checksum_sha256 = Column(String(64), nullable=False, default="", index=True)
    storage_key = Column(String(512), nullable=False)
    bucket = Column(String(128), nullable=False, default=lambda: os.getenv("SUPABASE_BUCKET", ""))
    visibility = Column(String(32), nullable=False, default="private")
    lifecycle_status = Column(String(32), nullable=False, default="pending", index=True)
    status_reason = Column(Text, nullable=True)
    is_latest = Column(Boolean, nullable=False, default=False, index=True)
    ci_status = Column(String(32), nullable=True)
    ci_last_event = Column(Text, nullable=True)
    ci_updated_at = Column(String(64), nullable=True)
    shared_with = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True)
    zip_entry_count = Column(Integer, nullable=False, default=0)
    uncompressed_size_bytes = Column(Integer, nullable=False, default=0)
    duplicate_of_id = Column(String(36), nullable=True)
    download_count = Column(Integer, nullable=False, default=0)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(String(64), nullable=True)
    submitted_at = Column(String(64), nullable=True)
    approved_at = Column(String(64), nullable=True)
    published_at = Column(String(64), nullable=True)
    archived_at = Column(String(64), nullable=True)
    rejected_at = Column(String(64), nullable=True)
    created_at = Column(
        String(64),
        nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )

    user = relationship("User", foreign_keys=[user_id])
    reviewer = relationship("User", foreign_keys=[reviewed_by])
    share_grants = relationship(
        "ProjectShareGrant",
        back_populates="project",
        cascade="all, delete-orphan",
    )
    team_grants = relationship(
        "ProjectTeamGrant",
        back_populates="project",
        cascade="all, delete-orphan",
    )


class ProjectStatusEvent(Base):
    __tablename__ = "project_status_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("project_uploads.id"), nullable=False, index=True)
    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    from_status = Column(String(32), nullable=True)
    to_status = Column(String(32), nullable=False)
    reason = Column(Text, nullable=True)
    created_at = Column(
        String(64),
        nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )

    project = relationship("ProjectUpload")
    actor = relationship("User")


class ProjectShareGrant(Base):
    __tablename__ = "project_share_grants"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("project_uploads.id"), nullable=False, index=True)
    grantee_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    grant_role = Column(String(32), nullable=False, default="viewer")
    expires_at = Column(String(64), nullable=True)
    created_at = Column(
        String(64),
        nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )

    project = relationship("ProjectUpload", back_populates="share_grants")
    grantee = relationship("User")


class ProjectTeamGrant(Base):
    __tablename__ = "project_team_grants"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("project_uploads.id"), nullable=False, index=True)
    team_id = Column(String(36), ForeignKey("teams.id"), nullable=False, index=True)
    grant_role = Column(String(32), nullable=False, default="viewer")
    expires_at = Column(String(64), nullable=True)
    created_at = Column(
        String(64),
        nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )

    project = relationship("ProjectUpload", back_populates="team_grants")
    team = relationship("Team")


class AsyncJob(Base):
    __tablename__ = "async_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_type = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="queued", index=True)
    priority = Column(Integer, nullable=False, default=100)
    payload_json = Column(Text, nullable=False, default="{}")
    result_json = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    project_id = Column(String(36), ForeignKey("project_uploads.id"), nullable=True, index=True)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    started_at = Column(String(64), nullable=True)
    finished_at = Column(String(64), nullable=True)
    created_at = Column(
        String(64),
        nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )

    project = relationship("ProjectUpload")
    created_by = relationship("User")


class WorkflowApproval(Base):
    __tablename__ = "workflow_approvals"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("project_uploads.id"), nullable=False, index=True)
    requested_by = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    required_role = Column(String(32), nullable=False, default="owner")
    reason = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    approved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(
        String(64),
        nullable=False,
        default=lambda: datetime.now(timezone.utc).isoformat(),
    )
    decided_at = Column(String(64), nullable=True)

    project = relationship("ProjectUpload")
    requester = relationship("User", foreign_keys=[requested_by])
    approver = relationship("User", foreign_keys=[approved_by])
