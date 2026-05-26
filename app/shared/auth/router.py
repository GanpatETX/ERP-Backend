"""
app/shared/auth/router.py

HTTP layer — thin adapters between FastAPI and the service layer.
No business logic lives here.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConfigurationError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.shared.auth import schemas
from app.shared.auth.dependencies import get_current_employee, require_roles
from app.shared.auth.service import (
    AdminEmployeeService,
    CandidateAuthService,
    EmployeeAuthService,
)

router = APIRouter(tags=["Authentication"])


# ---------------------------------------------------------------------------
# Zoho SSO — employee login
# ---------------------------------------------------------------------------

@router.get(
    "/zoho/login",
    summary="Redirect browser to Zoho OAuth2 consent screen",
    status_code=status.HTTP_302_FOUND,
)
async def zoho_login() -> RedirectResponse:
    try:
        url = EmployeeAuthService.build_zoho_authorization_url()
    except ConfigurationError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    return RedirectResponse(url)


@router.get(
    "/zoho/callback",
    summary="Zoho OAuth2 callback — exchanges code for tokens",
    response_model=schemas.FullTokenResponse,
)
async def zoho_callback(
    code: str,
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    try:
        tokens = await EmployeeAuthService.handle_zoho_callback(db, code)
    except ConfigurationError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc))
    except AuthenticationError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(exc))
    except AuthorizationError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(exc))

    # Redirect browser to the SPA; tokens passed as query params (use secure storage on FE)
    from app.core.config import settings
    redirect_url = (
        f"{settings.FRONTEND_URL}/auth/callback"
        f"?access_token={tokens['access_token']}"
        f"&refresh_token={tokens['refresh_token']}"
    )
    return RedirectResponse(redirect_url, status_code=status.HTTP_302_FOUND)


@router.post(
    "/employee/refresh",
    summary="Rotate employee refresh token",
    response_model=schemas.FullTokenResponse,
)
async def refresh_employee_token(
    payload: schemas.RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        return await EmployeeAuthService.rotate_refresh_token(db, payload.refresh_token)
    except (AuthenticationError, AuthorizationError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(exc))


# ---------------------------------------------------------------------------
# Admin — employee management
# ---------------------------------------------------------------------------

@router.post(
    "/admin/employees",
    summary="Invite a new employee (admin only)",
    response_model=schemas.UserOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles("admin"))],
)
async def invite_employee(
    payload: schemas.CreateEmployeeRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_employee),
) -> schemas.UserOut:
    try:
        user = await AdminEmployeeService.invite_employee(
            db,
            email=payload.email,
            role=payload.role,
            department=payload.department,
            created_by_id=current_user.id,
        )
    except ValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except ConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=str(exc))
    return schemas.UserOut.model_validate(user)


@router.patch(
    "/admin/employees/{employee_id}",
    summary="Update employee role / department / status (admin only)",
    response_model=schemas.UserOut,
    dependencies=[Depends(require_roles("admin"))],
)
async def update_employee(
    employee_id: str,
    payload: schemas.UpdateEmployeeRequest,
    db: AsyncSession = Depends(get_db),
) -> schemas.UserOut:
    from uuid import UUID as _UUID
    try:
        user = await AdminEmployeeService.update_employee(
            db,
            employee_id=_UUID(employee_id),
            role=payload.role,
            department=payload.department,
            is_active=payload.is_active,
        )
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except NotFoundError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=str(exc))
    return schemas.UserOut.model_validate(user)


@router.get(
    "/admin/employees",
    summary="List all employees (admin only)",
    response_model=list[schemas.UserOut],
    dependencies=[Depends(require_roles("admin"))],
)
async def list_employees(db: AsyncSession = Depends(get_db)) -> list[schemas.UserOut]:
    users = await AdminEmployeeService.list_employees(db)
    return [schemas.UserOut.model_validate(u) for u in users]


# ---------------------------------------------------------------------------
# Candidate OTP flow
# ---------------------------------------------------------------------------

@router.post(
    "/candidate/send-otp",
    summary="Send a 6-digit OTP to the candidate's email",
    status_code=status.HTTP_200_OK,
)
async def send_candidate_otp(
    payload: schemas.CandidateSendOTPRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    await CandidateAuthService.send_otp(db, payload.email)
    # Always return a generic message to prevent email enumeration
    return {"message": "If that email is registered, an OTP has been sent."}


@router.post(
    "/candidate/verify-otp",
    summary="Verify the OTP and receive an access token",
    response_model=schemas.AccessTokenResponse,
)
async def verify_candidate_otp(
    payload: schemas.CandidateVerifyOTPRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    try:
        return await CandidateAuthService.verify_otp(db, payload.email, payload.otp)
    except (AuthenticationError, AuthorizationError) as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=str(exc))