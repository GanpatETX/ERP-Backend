"""
app/core/config.py
 
Central settings loaded from environment variables via pydantic-settings.
"""
from pydantic_settings import BaseSettings, settingsconfigDict
from typing import List

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
 
    # Application
    APP_NAME:  str = "Aerospace ERP"
    DEBUG:     bool = False
    SECRET_KEY: str  # REQUIRED — set in .env
 
    # JWT
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS:   int = 7
 
    
 
    # Zoho OIDC
    ZOHO_CLIENT_ID:     str = ""
    ZOHO_CLIENT_SECRET: str = ""
    ZOHO_REDIRECT_URI:  str = ""   # e.g. https://erp.example.com/api/auth/zoho/callback
 
    # Frontend
    FRONTEND_URL: str = "http://localhost:5173"
 
    # Email (SMTP)
    SMTP_HOST:     str = ""
    SMTP_PORT:     int = 587
    SMTP_USER:     str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM:     str = "noreply@company.com"
    SMTP_STARTTLS: bool = True

    # REDIS_URL: str = "redis://localhost:6379/0"

    

    # MINIO_ENDPOINT: str
    # MINIO_ACCESS_KEY: str
    # MINIO_SECRET_KEY: str
    # MINIO_BUCKET_NAME: str
    # MINIO_USE_SSL: bool = False


    @property
    def DATABASE_URL(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()