"""
app/shared/auth/schemas.py

Pydantic v2 request / response schemas for the auth domain.
"""

from datetime import datetime
from uuid import UUID
from typing import Optional

from pydantic import BaseModel, EmailStr, field_validator


# Internal user (employee) schemas
class UserOut(BaseModel):
    id:         UUID
    email:      EmailStr
    full_name:  str
    role:       str
    department: Optional[str] = None
    is_active:  bool
    created_at: datetime

    model_config = {"from_attributes": True}


# Token schemas  (shared by employee SSO + candidate OTP flows)
class AccessTokenResponse(BaseModel):
    """Returned after candidate OTP verification (no refresh token needed)."""
    access_token: str
    token_type:   str = "bearer"


class FullTokenResponse(BaseModel):
    """Returned after employee Zoho SSO login."""
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"


class RefreshTokenRequest(BaseModel):
    refresh_token: str



# Candidate OTP schemas
class CandidateSendOTPRequest(BaseModel):
    email: EmailStr


class CandidateVerifyOTPRequest(BaseModel):
    email: EmailStr
    otp:   str

    @field_validator("otp")
    @classmethod
    def otp_must_be_digits(cls, v: str) -> str:
        if not v.strip().isdigit():
            raise ValueError("OTP must contain only digits.")
        if len(v.strip()) != 6:
            raise ValueError("OTP must be exactly 6 digits.")
        return v.strip()



# Admin — employee management schemas
class CreateEmployeeRequest(BaseModel):
    email:      EmailStr
    role:       str          # validated against UserRole enum in the service layer
    department: Optional[str] = None


class UpdateEmployeeRequest(BaseModel):
    role:       Optional[str] = None
    department: Optional[str] = None
    is_active:  Optional[bool] = None