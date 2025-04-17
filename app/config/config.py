# config.py
from pydantic_settings import BaseSettings
from pydantic import Field

class Settings(BaseSettings):
    # Database configuration
    postgres_user: str = Field(..., env="POSTGRES_USER")
    postgres_password: str = Field(..., env="POSTGRES_PASSWORD")
    postgres_db: str = Field(..., env="POSTGRES_DB")
    postgres_host: str = Field(..., env="POSTGRES_HOST")
    postgres_port: int = Field(..., env="POSTGRES_PORT")
    database_url: str = Field(..., env="DATABASE_URL")

    # Zoho API credentials
    client_id: str = Field(..., env="CLIENT_ID")
    client_secret: str = Field(..., env="CLIENT_SECRET")
    refresh_token: str = Field(..., env="REFRESH_TOKEN")
    access_token: str = Field(..., env="ACCESS_TOKEN")
    zoho_api_url: str = Field(..., env="ZOHO_API_URL")

    # JWT configuration
    secret_key: str = Field(..., env="SECRET_KEY")
    algorithm: str = Field(default="HS256", env="ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=30, env="REFRESH_TOKEN_EXPIRE_DAYS")
    # JWT configuration
    REDIS_URL: str = Field(..., env="REDIS_URL") # Or your Redis URL
    FAILED_LOGIN_RETENTION_DAYS: int = 30
    MAX_USER_ATTEMPTS: int = 5
    MAX_IP_ATTEMPTS: int = 20

    class Config:
        env_file = ".env"

settings = Settings()