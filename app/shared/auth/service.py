"""
app/shared/auth/service.py

Business-logic layer.
Orchestrates repository calls, token creation, email dispatch, and Zoho OIDC.
Never imports FastAPI — keeps business logic framework-agnostic.
"""

import logging
import secrets
import string
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.email import send_email
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    hash_password,
    verify_password,
)
from app.shared.auth.models import OTPPurpose, UserRole
from app.shared.auth.repository import (
    CandidateRepository,
    OTPRepository,
    RefreshTokenRepository,
    UserRepository,
)

logger = logging.getLogger(__name__)

_OTP_LENGTH    = 6
_OTP_TTL_MIN   = 10   # minutes
_TOKEN_TTL_DAYS = 7   # refresh token TTL


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _generate_numeric_otp(length: int = _OTP_LENGTH) -> str:
    """Cryptographically secure numeric OTP."""
    return "".join(secrets.choice(string.digits) for _ in range(length))


# ---------------------------------------------------------------------------
# Employee (Zoho SSO) service
# ---------------------------------------------------------------------------

class EmployeeAuthService:
    """
    Handles the Zoho OpenID Connect flow for internal employees.

    Flow:
        1. Frontend redirects user to Zoho → /auth/zoho/login  (redirect URL)
        2. Zoho redirects back with ?code=   → /auth/zoho/callback
        3. We exchange code → access_token, fetch user info, issue our JWT pair.
    """

    @staticmethod
    def build_zoho_authorization_url() -> str:
        if not settings.ZOHO_CLIENT_ID:
            raise ConfigurationError("Zoho SSO is not configured.")

        params = (
            "response_type=code"
            f"&client_id={settings.ZOHO_CLIENT_ID}"
            "&scope=openid+profile+email"
            f"&redirect_uri={settings.ZOHO_REDIRECT_URI}"
            "&access_type=online"
        )
        return f"https://accounts.zoho.com/oauth/v2/auth?{params}"

    @staticmethod
    async def _exchange_code_for_user_info(code: str) -> dict:
        """
        Exchange the Zoho authorization code for an access token,
        then fetch the OIDC user-info from Zoho.
        Raises ConfigurationError / AuthenticationError on failure.
        """
        if not settings.ZOHO_CLIENT_ID or not settings.ZOHO_CLIENT_SECRET:
            raise ConfigurationError("Zoho SSO is not configured.")

        async with httpx.AsyncClient(timeout=10.0) as client:
            # Step 1 — token exchange
            token_resp = await client.post(
                "https://accounts.zoho.com/oauth/v2/token",
                data={
                    "grant_type":    "authorization_code",
                    "client_id":     settings.ZOHO_CLIENT_ID,
                    "client_secret": settings.ZOHO_CLIENT_SECRET,
                    "redirect_uri":  settings.ZOHO_REDIRECT_URI,
                    "code":          code,
                },
            )
            token_data = token_resp.json()

            if "access_token" not in token_data:
                logger.error("Zoho token exchange failed: %s", token_data)
                raise AuthenticationError("Failed to obtain access token from Zoho.")

            zoho_access_token = token_data["access_token"]

            # Step 2 — user info (OIDC standard endpoint)
            user_resp = await client.get(
                "https://accounts.zoho.com/oauth/user/info",
                headers={"Authorization": f"Zoho-oauthtoken {zoho_access_token}"},
            )
            return user_resp.json()

    @classmethod
    async def handle_zoho_callback(
        cls, db: AsyncSession, code: str
    ) -> dict:
        """
        Complete the Zoho SSO callback.
        - Only pre-registered (admin-invited) employees may log in.
        - On every successful login the full_name is synced from Zoho.
        Returns a dict with access_token + refresh_token.
        """
        user_info = await cls._exchange_code_for_user_info(code)

        email     = (user_info.get("Email") or "").lower().strip()
        full_name = user_info.get("Display_Name") or user_info.get("FirstName") or ""

        if not email:
            raise AuthenticationError("Zoho did not return an email address.")

        user = await UserRepository.get_by_email(db, email)
        if not user:
            raise AuthorizationError(
                "Your Zoho account is not authorised for this system. "
                "Contact an administrator to be invited."
            )
        if not user.is_active:
            raise AuthorizationError("Your account has been deactivated.")

        # Keep name in sync with the IdP
        if full_name and full_name != user.full_name:
            await UserRepository.update_full_name(db, user, full_name)

        tokens = await cls._issue_token_pair(db, user)
        await db.commit()
        return tokens

    @staticmethod
    async def _issue_token_pair(db: AsyncSession, user) -> dict:
        access_token  = create_access_token(
            user_id=str(user.id),
            role=user.role.value if hasattr(user.role, "value") else user.role,
            subject_type="employee",
        )
        raw_refresh   = create_refresh_token(user_id=str(user.id))
        await RefreshTokenRepository.create(
            db, user_id=user.id, raw_token=raw_refresh, ttl_days=_TOKEN_TTL_DAYS
        )
        return {
            "access_token":  access_token,
            "refresh_token": raw_refresh,
            "token_type":    "bearer",
        }

    @staticmethod
    async def rotate_refresh_token(db: AsyncSession, raw_refresh: str) -> dict:
        """
        Refresh-token rotation:
        1. Validate the incoming token.
        2. Revoke it.
        3. Issue a new pair.
        """
        payload = decode_refresh_token(raw_refresh)
        if not payload:
            raise AuthenticationError("Invalid or expired refresh token.")

        stored = await RefreshTokenRepository.get_valid(db, raw_refresh)
        if not stored:
            raise AuthenticationError("Refresh token has been revoked or does not exist.")

        user = await UserRepository.get_by_id(db, stored.user_id)
        if not user or not user.is_active:
            raise AuthorizationError("User not found or deactivated.")

        await RefreshTokenRepository.revoke(db, stored)
        tokens = await EmployeeAuthService._issue_token_pair(db, user)
        await db.commit()
        return tokens


# ---------------------------------------------------------------------------
# Admin — employee management service
# ---------------------------------------------------------------------------

class AdminEmployeeService:
    """
    Admin-only operations: invite employee, update role, deactivate.
    All methods enforce that the acting user has the 'admin' role
    via the router's dependency — service is role-agnostic.
    """

    @staticmethod
    async def invite_employee(
        db: AsyncSession,
        *,
        email: str,
        role: str,
        department: Optional[str],
        created_by_id: UUID,
    ) -> "User":
        # Validate role
        try:
            UserRole(role)
        except ValueError:
            raise ValidationError(f"Invalid role '{role}'.")

        existing = await UserRepository.get_by_email(db, email)
        if existing:
            raise ConflictError(f"An employee with email '{email}' already exists.")

        # full_name will be populated from Zoho on first login
        user = await UserRepository.create(
            db,
            email=email,
            full_name="",
            role=role,
            department=department,
            created_by=created_by_id,
        )
        await db.commit()
        await db.refresh(user)
        return user

    @staticmethod
    async def update_employee(
        db: AsyncSession,
        *,
        employee_id: UUID,
        role: Optional[str] = None,
        department: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> "User":
        user = await UserRepository.get_by_id(db, employee_id)
        if not user:
            raise NotFoundError("Employee not found.")

        if role is not None:
            try:
                UserRole(role)
            except ValueError:
                raise ValidationError(f"Invalid role '{role}'.")
            user.role = role

        if department is not None:
            user.department = department

        if is_active is not None:
            user.is_active = is_active
            if not is_active:
                # Immediately revoke all refresh tokens on deactivation
                await RefreshTokenRepository.revoke_all_for_user(db, user.id)

        await db.commit()
        await db.refresh(user)
        return user

    @staticmethod
    async def list_employees(db: AsyncSession) -> list:
        return await UserRepository.list_active(db)


# ---------------------------------------------------------------------------
# Candidate (Email OTP) service
# ---------------------------------------------------------------------------

class CandidateAuthService:
    """
    Handles the email OTP flow for external candidates.

    Flow:
        1. Candidate submits email → send_otp()  → 6-digit OTP sent via email.
        2. Candidate submits email + OTP → verify_otp() → short-lived access token.
    No refresh tokens for candidates; they re-authenticate via OTP as needed.
    """

    @staticmethod
    async def send_otp(db: AsyncSession, email: str) -> None:
        """
        Generate a 6-digit OTP, persist its hash, and dispatch via email.
        Any previously unused OTPs remain in the DB but the latest one wins.
        """
        # Auto-provision candidate account on first contact
        await CandidateRepository.get_or_create(db, email)

        raw_otp  = _generate_numeric_otp(_OTP_LENGTH)
        otp_hash = hash_password(raw_otp)  # bcrypt

        await OTPRepository.create(
            db,
            email=email,
            otp_hash=otp_hash,
            purpose=OTPPurpose.candidate_login,
            ttl_minutes=_OTP_TTL_MIN,
        )
        await db.commit()

        await _dispatch_otp_email(email, raw_otp)

    @staticmethod
    async def verify_otp(db: AsyncSession, email: str, raw_otp: str) -> dict:
        """
        Verify the OTP and return a short-lived access token for the candidate.
        Raises AuthenticationError on any verification failure.
        """
        candidate = await CandidateRepository.get_by_email(db, email)
        if not candidate or not candidate.is_active:
            raise AuthorizationError("Candidate account not found or inactive.")

        otp_record = await OTPRepository.get_latest_unused(
            db, email, OTPPurpose.candidate_login
        )
        if not otp_record:
            raise AuthenticationError("No active OTP found. Please request a new one.")

        # Check expiry
        if otp_record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
            raise AuthenticationError("OTP has expired. Please request a new one.")

        # Constant-time bcrypt verification
        if not verify_password(raw_otp, otp_record.otp_hash):
            raise AuthenticationError("Invalid OTP.")

        await OTPRepository.mark_used(db, otp_record)
        await db.commit()

        access_token = create_access_token(
            user_id=str(candidate.id),
            role="candidate",
            subject_type="candidate",
        )
        return {"access_token": access_token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Email helper
# ---------------------------------------------------------------------------

async def _dispatch_otp_email(email: str, otp: str) -> None:
    subject = "Your Login OTP"
    body_html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 480px; margin: auto;">
        <h2>Login Verification Code</h2>
        <p>Use the code below to log in. It expires in <strong>{_OTP_TTL_MIN} minutes</strong>.</p>
        <div style="font-size: 36px; font-weight: bold; letter-spacing: 8px;
                    padding: 16px 24px; background: #f4f4f4; border-radius: 6px;
                    display: inline-block; margin: 16px 0;">
            {otp}
        </div>
        <p style="color: #888; font-size: 13px;">
            If you did not request this, you can safely ignore this email.
        </p>
    </div>
    """
    try:
        await send_email(to=email, subject=subject, body_html=body_html)
    except Exception:
        logger.exception("Failed to send OTP email to %s", email)
        # Do not surface email errors to the client; OTP is already persisted