from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432


    # REDIS_URL: str = "redis://localhost:6379/0"

    # SECRET_KEY: str
    # ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    # REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # MINIO_ENDPOINT: str
    # MINIO_ACCESS_KEY: str
    # MINIO_SECRET_KEY: str
    # MINIO_BUCKET_NAME: str
    # MINIO_USE_SSL: bool = False

    # SMTP_HOST: str
    # SMTP_PORT: int = 587
    # SMTP_USER: str
    # SMTP_PASSWORD: str
    # EMAIL_FROM_NAME: str = "Aerospace Recruitment"

    # ZOHO_CLIENT_ID: str = ""
    # ZOHO_CLIENT_SECRET: str = ""
    # ZOHO_PEOPLE_API_BASE: str = ""
    # ZOHO_BOOKINGS_API_BASE: str = ""

    # FRONTEND_URL: str
    # CORS_ORIGINS: List[str] = ["http://localhost:5173"]

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