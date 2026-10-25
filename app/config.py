from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    database_url: str = Field(
        ...,
        description="Подключение SQLAlchemy"
    )

    jwt_secret: str = Field(..., min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_ttl_min: int = Field(60, ge=1, le=24 * 60)

    password_pepper: str = Field(..., min_length=32)
    password_min_length: int = Field(12, ge=8, le=128)

    environment: str = "development"
    app_name: str = "Vault"

settings = Settings()