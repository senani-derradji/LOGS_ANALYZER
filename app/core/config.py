from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional
from pathlib import Path
import os


def get_env_file_path():
    project_root = Path(__file__).resolve().parent
    env_path = project_root / ".env"
    if env_path.exists():
        return str(env_path)
    return ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=get_env_file_path(),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    DATABASE_URL: str = Field(default="", description="PostgreSQL connection URL")
    REDIS_URL: str = Field(default="redis://localhost:6379", description="Redis connection URL")
    MQ_URL: str = Field(default="amqp://guest:guest@localhost/", description="RabbitMQ connection URL")

    CLOUDFLARE_API_TOKEN: str = Field(default="", description="Cloudflare API token")
    CLOUDFLARE_ACCOUNT_ID: str = Field(default="", description="Cloudflare account ID")
    CLOUDFLARE_URL: str = Field(default="", description="Cloudflare URL")
    CLOUDFLARE_BUCKET: str = Field(default="", description="Cloudflare bucket")



    SECRET_KEY: str = Field(default="", description="JWT secret key")
    ALGORITHM: str = Field(default="HS256", description="JWT algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=4320, description="Token expiration in minutes (3 days)")

    API_KEY: Optional[str] = Field(default=None, description="External API key")
    OPENROUTER_API_KEY: Optional[str] = Field(default=None, description="OpenRouter API key")
    OPENROUTER_BASE_URL: str = Field(default="https://openrouter.ai/api/v1/chat/completions", description="OpenRouter base URL")
    HF_TOKEN: Optional[str] = Field(default=None, description="HuggingFace token")

    CORS_ORIGINS: str = Field(default="*", description="Comma-separated CORS origins")

    RATE_LIMIT_PER_MINUTE: int = Field(default=60, description="Rate limit per minute")
    RATE_LIMIT_LOGIN_PER_MINUTE: int = Field(default=5, description="Rate limit for login endpoint")

    ENVIRONMENT: str = Field(default="development", description="Environment: development/staging/production")

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @property
    def cors_origins_list(self) -> list[str]:
        if self.CORS_ORIGINS == "*":
            return ["*"]
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


def validate_settings() -> Settings:
    settings = Settings()

    missing_fields = []
    if not settings.DATABASE_URL:
        missing_fields.append("DATABASE_URL")
    if not settings.SECRET_KEY:
        missing_fields.append("SECRET_KEY")

    if not settings.CLOUDFLARE_API_TOKEN:
        missing_fields.append("CLOUDFLARE_API_TOKEN")
    if not settings.CLOUDFLARE_ACCOUNT_ID:
        missing_fields.append("CLOUDFLARE_ACCOUNT_ID")
    if not settings.CLOUDFLARE_URL:
        missing_fields.append("CLOUDFLARE_URL")
    if not settings.REDIS_URL:
        missing_fields.append("REDIS_URL")
    if not settings.MQ_URL:
        missing_fields.append("MQ_URL")
    if not settings.CLOUDFLARE_BUCKET:
        missing_fields.append("CLOUDFLARE_BUCKET")


    if missing_fields and settings.ENVIRONMENT.lower() == "production":
        raise ValueError(f"Missing required environment variables for production: {', '.join(missing_fields)}")

    return settings


settings = validate_settings()