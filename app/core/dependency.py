"""
app/shared/auth/dependencies.py

FastAPI dependency-injection helpers for authentication & authorisation.

Dependency tree
---------------
get_current_employee   → validates employee JWT, returns User ORM object
get_current_candidate  → validates candidate JWT, returns Candidate ORM object
require_roles(*roles)  → wraps get_current_employee with a role check
"""

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import decode_access_token
from app.shared.auth.models import Candidate, User
from app.shared.auth.repository import CandidateRepository, UserRepository

_bearer = HTTPBearer(auto_error=True)

# ---------------------------------------------------------------------------
# Shared token decoder
# ---------------------------------------------------------------------------

def _extract_payload(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict:
    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload


# ---------------------------------------------------------------------------
# Employee dependency
# ---------------------------------------------------------------------------

async def get_current_employee(
    payload: dict = Depends(_extract_payload),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Validates that the token belongs to an active internal employee.
    Raises 401 if invalid, 403 if the token belongs to a candidate.
    """
    if payload.get("subject_type") != "employee":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint is restricted to internal employees.",
        )

    from uuid import UUID
    user = await UserRepository.get_by_id(db, UUID(payload["sub"]))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or has been deactivated.",
        )
    return user


# ---------------------------------------------------------------------------
# Candidate dependency
# ---------------------------------------------------------------------------

async def get_current_candidate(
    payload: dict = Depends(_extract_payload),
    db: AsyncSession = Depends(get_db),
) -> Candidate:
    """
    Validates that the token belongs to an active external candidate.
    """
    if payload.get("subject_type") != "candidate":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This endpoint is restricted to external candidates.",
        )

    from uuid import UUID
    candidate = await CandidateRepository.get_by_email(db, payload["sub"])
    # sub is stored as candidate.id (UUID string) for candidates too
    # fall back to ID look-up
    if not candidate:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Candidate account not found.",
        )
    if not candidate.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Candidate account is inactive.",
        )
    return candidate


# ---------------------------------------------------------------------------
# Role-based access control
# ---------------------------------------------------------------------------

def require_roles(*roles: str):
    """
    Factory that returns a FastAPI dependency enforcing one of the given roles.

    Usage:
        @router.get("/...", dependencies=[Depends(require_roles("admin"))])

    Roles map directly to UserRole enum values (strings).
    """

    async def _checker(current_user: User = Depends(get_current_employee)) -> User:
        user_role = (
            current_user.role.value
            if hasattr(current_user.role, "value")
            else current_user.role
        )
        if user_role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access requires one of: {', '.join(roles)}.",
            )
        return current_user

    return _checker