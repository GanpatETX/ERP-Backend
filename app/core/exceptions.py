"""
app/core/exceptions.py

Domain exception hierarchy.
Services raise these; routers translate them to HTTPExceptions.
Keeps business logic completely decoupled from HTTP status codes.
"""


class AppBaseException(Exception):
    """Base class for all application exceptions."""


class AuthenticationError(AppBaseException):
    """Identity could not be verified (wrong OTP, expired token, etc.)."""


class AuthorizationError(AppBaseException):
    """Identity verified but not permitted to perform the action."""


class ConfigurationError(AppBaseException):
    """Required environment variable or external service is not configured."""


class NotFoundError(AppBaseException):
    """Requested resource does not exist."""


class ConflictError(AppBaseException):
    """Resource already exists (duplicate email, etc.)."""


class ValidationError(AppBaseException):
    """Input data is semantically invalid (beyond Pydantic schema checks)."""