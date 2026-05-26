"""
app/shared/auth/repository.py

Data-access layer — pure DB queries with zero business logic.
All functions are async and accept an AsyncSession.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.shared.auth.models import AuthOTP, Candidate, OTPPurpose, RefreshToken, User


# ---------------------------------------------------------------------------
# User (employee) queries
# ---------------------------------------------------------------------------

class UserRepository:

    @staticmethod
    async def get_by_id(db: AsyncSession, user_id: UUID) -> Optional[User]:
        result = await db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def get_by_email(db: AsyncSession, email: str) -> Optional[User]:
        result = await db.execute(
            select(User).where(User.email == email.lower().strip())
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create(
        db: AsyncSession,
        *,
        email: str,
        full_name: str,
        role: str,
        department: Optional[str] = None,
        created_by: Optional[UUID] = None,
    ) -> User:
        user = User(
            email=email.lower().strip(),
            full_name=full_name,
            role=role,
            department=department,
            created_by=created_by,
        )
        db.add(user)
        await db.flush()   # get user.id without committing
        return user

    @staticmethod
    async def update_full_name(db: AsyncSession, user: User, full_name: str) -> None:
        """Called on every Zoho login to keep name in sync with the IdP."""
        user.full_name = full_name
        await db.flush()

    @staticmethod
    async def list_active(db: AsyncSession) -> list[User]:
        result = await db.execute(select(User).where(User.deleted_at.is_(None)))
        return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Refresh token queries  (employees only)
# ---------------------------------------------------------------------------

class RefreshTokenRepository:

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    @classmethod
    async def create(
        cls,
        db: AsyncSession,
        *,
        user_id: UUID,
        raw_token: str,
        ttl_days: int = 7,
    ) -> RefreshToken:
        rt = RefreshToken(
            user_id=user_id,
            token_hash=cls._hash(raw_token),
            expires_at=datetime.now(timezone.utc) + timedelta(days=ttl_days),
        )
        db.add(rt)
        await db.flush()
        return rt

    @classmethod
    async def get_valid(
        cls, db: AsyncSession, raw_token: str
    ) -> Optional[RefreshToken]:
        token_hash = cls._hash(raw_token)
        result = await db.execute(
            select(RefreshToken).where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > datetime.now(timezone.utc),
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def revoke(db: AsyncSession, refresh_token: RefreshToken) -> None:
        refresh_token.revoked_at = datetime.now(timezone.utc)
        await db.flush()

    @staticmethod
    async def revoke_all_for_user(db: AsyncSession, user_id: UUID) -> None:
        """Used during logout or account deactivation."""
        await db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=datetime.now(timezone.utc))
        )
        await db.flush()


# ---------------------------------------------------------------------------
# Candidate queries
# ---------------------------------------------------------------------------

class CandidateRepository:

    @staticmethod
    async def get_by_email(db: AsyncSession, email: str) -> Optional[Candidate]:
        result = await db.execute(
            select(Candidate).where(Candidate.email == email.lower().strip())
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def get_or_create(db: AsyncSession, email: str) -> tuple[Candidate, bool]:
        """Returns (candidate, created: bool)."""
        email = email.lower().strip()
        result = await db.execute(select(Candidate).where(Candidate.email == email))
        candidate = result.scalar_one_or_none()
        if candidate:
            return candidate, False
        candidate = Candidate(email=email)
        db.add(candidate)
        await db.flush()
        return candidate, True


# ---------------------------------------------------------------------------
# OTP queries  (candidates only)
# ---------------------------------------------------------------------------

class OTPRepository:

    @staticmethod
    async def create(
        db: AsyncSession,
        *,
        email: str,
        otp_hash: str,
        purpose: OTPPurpose,
        ttl_minutes: int = 10,
    ) -> AuthOTP:
        otp = AuthOTP(
            email=email.lower().strip(),
            otp_hash=otp_hash,
            purpose=purpose,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes),
        )
        db.add(otp)
        await db.flush()
        return otp

    @staticmethod
    async def get_latest_unused(
        db: AsyncSession, email: str, purpose: OTPPurpose
    ) -> Optional[AuthOTP]:
        result = await db.execute(
            select(AuthOTP)
            .where(
                AuthOTP.email == email.lower().strip(),
                AuthOTP.purpose == purpose,
                AuthOTP.used_at.is_(None),
            )
            .order_by(AuthOTP.created_at.desc())
        )
        return result.scalars().first()

    @staticmethod
    async def mark_used(db: AsyncSession, otp: AuthOTP) -> None:
        otp.used_at = datetime.now(timezone.utc)
        await db.flush()