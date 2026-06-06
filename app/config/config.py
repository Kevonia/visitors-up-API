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

    # Local/dev only: when true, signup and /users/me skip Zoho contact/address
    # verification so test accounts work without live Zoho data. Leave false in prod.
    dev_skip_zoho: bool = Field(default=False, env="DEV_SKIP_ZOHO")

    # Secret used to derive the AES key that encrypts PII columns at rest.
    # MUST be set to a strong, stable secret in production (changing it makes
    # existing encrypted data unreadable).
    pii_encryption_key: str = Field(
        default="dev-only-insecure-pii-key-change-me", env="PII_ENCRYPTION_KEY")

    # Resident notifications (email + SMS).
    # NOTIFICATIONS_TRANSPORT: "brevo" (prod, via Brevo API) or "smtp" (dev, via a
    # local Mailpit catcher). Set NOTIFICATIONS_ENABLED=true to turn on.
    notifications_enabled: bool = Field(default=False, env="NOTIFICATIONS_ENABLED")
    notifications_transport: str = Field(default="brevo", env="NOTIFICATIONS_TRANSPORT")
    smtp_host: str = Field(default="mailpit", env="SMTP_HOST")
    smtp_port: int = Field(default=1025, env="SMTP_PORT")
    brevo_api_key: str = Field(default="", env="BREVO_API_KEY")
    brevo_sender_email: str = Field(
        default="no-reply@twickenhamglades.com", env="BREVO_SENDER_EMAIL")
    brevo_sender_name: str = Field(default="Twickenham Glades", env="BREVO_SENDER_NAME")
    brevo_sms_sender: str = Field(default="TwickGlades", env="BREVO_SMS_SENDER")

    # Bootstrap accounts created by scripts/seed_prod.py on deploy. Override the
    # passwords (and ideally emails/phones) with strong values in production.
    admin_email: str = Field(default="admin@twickenham.com", env="ADMIN_EMAIL")
    admin_password: str = Field(default="admin123", env="ADMIN_PASSWORD")
    admin_phone: str = Field(default="18760000111", env="ADMIN_PHONE")
    security_email: str = Field(default="security@twickenham.com", env="SECURITY_EMAIL")
    security_password: str = Field(default="security123", env="SECURITY_PASSWORD")
    security_phone: str = Field(default="18760000777", env="SECURITY_PHONE")

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
        # Ignore unrelated env vars (e.g. API_PORT used only by docker-compose)
        # instead of failing validation.
        extra = "ignore"

settings = Settings()