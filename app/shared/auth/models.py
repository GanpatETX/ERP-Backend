"""
app/shared/auth/models.py

SQLAlchemy ORM models for the authentication domain.
- User         : Internal employees + admin (Zoho SSO only)
- Candidate    : External candidates (Email OTP only)
- AuthOTP      : Time-limited OTP / magic-link tokens for candidates
- RefreshToken : Rotatable refresh tokens for internal users
"""

import uuid
import enum

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    String,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from app.core.database import Base



# Enumerations
class UserRole(str, enum.Enum):
    admin            = "admin"
    ptc              = "ptc"
    founder          = "founder"
    project_director = "project_director"
    chief_of_staff   = "chief_of_staff"
    hiring_manager   = "hiring_manager"
    supporting_member = "supporting_member"


class OTPPurpose(str, enum.Enum):
    candidate_login = "candidate_login"

# Models
class User(Base):
    """
    Internal employee / admin.
    Authentication: Zoho OpenID Connect only.
    No password_hash — SSO is the sole identity provider.
    """

    __tablename__ = "users"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email      = Column(String, unique=True, nullable=False, index=True)
    full_name  = Column(String, nullable=False)  # populated / refreshed from Zoho on login
    role       = Column(SAEnum(UserRole, name="user_role"), nullable=False)
    department = Column(String, nullable=True)
    is_active  = Column(Boolean, default=True, nullable=False)

    # Audit
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    deleted_at = Column(DateTime(timezone=True), nullable=True)

    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan"
    )


class Candidate(Base):
    """
    External candidate.
    Authentication: Email OTP only.
    """

    __tablename__ = "candidates"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email      = Column(String, unique=True, nullable=False, index=True)
    full_name  = Column(String, nullable=True)  # collected later via profile completion
    is_active  = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class AuthOTP(Base):
    """
    Single-use, time-limited OTP stored as a bcrypt hash.
    Used exclusively for candidate email-OTP login.
    """

    __tablename__ = "auth_otps"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email      = Column(String, nullable=False, index=True)
    otp_hash   = Column(String, nullable=False)
    purpose    = Column(SAEnum(OTPPurpose, name="otp_purpose"), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at    = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class RefreshToken(Base):
    """
    Rotatable refresh token for internal users.
    Stored as SHA-256 hash; raw token is returned once and never persisted.
    """

    __tablename__ = "refresh_tokens"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id    = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash = Column(String, unique=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="refresh_tokens")