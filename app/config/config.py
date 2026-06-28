# config.py
from pydantic_settings import BaseSettings
from pydantic import Field, model_validator

# Known-insecure development defaults. Refused at startup when APP_ENV=production
# so a misconfigured prod deploy fails closed instead of running wide open.
_INSECURE_PII_KEY = "dev-only-insecure-pii-key-change-me"
_INSECURE_ADMIN_PW = "admin123"
_INSECURE_SECURITY_PW = "security123"

class Settings(BaseSettings):
    # Deployment environment: "development" (default) or "production". In
    # production the validator below refuses insecure defaults.
    app_env: str = Field(default="development", env="APP_ENV")

    # Comma-separated list of browser origins allowed by CORS. Lock this to the
    # admin app's origin in production; the dev default covers local Vite/nginx.
    cors_allow_origins: str = Field(
        default="http://localhost:8080,http://localhost:5173", env="CORS_ALLOW_ORIGINS")

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

    # Public base URL of this API, used to build absolute links (e.g. the logo)
    # inside notification emails. Set to the deployed API origin in production.
    public_base_url: str = Field(default="http://localhost:8001", env="PUBLIC_BASE_URL")

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

    # Firebase Cloud Messaging: path to the service-account JSON (server secret,
    # never committed). Relative paths resolve from the app working dir (/app).
    firebase_credentials: str = Field(
        default="firebase-service-account.json", env="FIREBASE_CREDENTIALS")

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
    # Zoho Invoice organization id — required on every Invoice API call.
    zoho_org_id: str = Field(default="", env="ZOHO_ORG_ID")

    # Resident payment-list / caching settings.
    # RED list = not on a payment plan AND outstanding balance over this amount.
    red_balance_threshold: float = Field(default=18000.0, env="RED_BALANCE_THRESHOLD")
    # How long cached Zoho data on a resident stays fresh before a lazy refresh.
    zoho_cache_ttl: int = Field(default=6 * 3600, env="ZOHO_CACHE_TTL")
    # Block checking in a visitor whose resident is RED (delinquent).
    gate_block_delinquent: bool = Field(default=True, env="GATE_BLOCK_DELINQUENT")

    # ── In-app payments (WiPay / DimePay) ────────────────────────────────────
    # Off by default; turn on once a provider's credentials are set. providers is
    # a CSV of enabled provider names (wipay,dimepay,test). default_payment_provider
    # is used when the client doesn't name one.
    payments_enabled: bool = Field(default=False, env="PAYMENTS_ENABLED")
    payments_providers: str = Field(default="", env="PAYMENTS_PROVIDERS")
    default_payment_provider: str = Field(default="", env="DEFAULT_PAYMENT_PROVIDER")
    # Absolute base the provider redirects back to after checkout, e.g.
    # https://vms-api.onrender.com/api/v1/payments/return
    payment_return_base_url: str = Field(default="", env="PAYMENT_RETURN_BASE_URL")
    # Optional platform fee (%) recorded on each payment (0 = none).
    platform_fee_pct: float = Field(default=0.0, env="PLATFORM_FEE_PCT")
    # Reconcile PENDING payments older than this many minutes via the cron poll.
    payment_pending_grace_minutes: int = Field(default=20, env="PAYMENT_PENDING_GRACE_MINUTES")

    # WiPay (Jamaica) — hosted redirect checkout.
    wipay_env: str = Field(default="sandbox", env="WIPAY_ENV")  # sandbox | live
    wipay_base_url: str = Field(default="https://jm.wipayfinancial.com", env="WIPAY_BASE_URL")
    wipay_account_number: str = Field(default="", env="WIPAY_ACCOUNT_NUMBER")  # business key
    wipay_api_key: str = Field(default="", env="WIPAY_API_KEY")
    wipay_country: str = Field(default="JM", env="WIPAY_COUNTRY")

    # DimePay — REST API (client_key header). No webhooks → return + poll.
    dimepay_env: str = Field(default="sandbox", env="DIMEPAY_ENV")  # sandbox | live
    dimepay_base_url: str = Field(default="https://sandbox.api.dimepay.app/dapi/v1", env="DIMEPAY_BASE_URL")
    dimepay_client_key: str = Field(default="", env="DIMEPAY_CLIENT_KEY")

    # ── Observability ────────────────────────────────────────────────────────
    # Sentry error tracking (set SENTRY_DSN to enable). traces_sample_rate keeps
    # perf tracing light. Prometheus /metrics is on unless disabled.
    sentry_dsn: str = Field(default="", env="SENTRY_DSN")
    sentry_traces_sample_rate: float = Field(default=0.0, env="SENTRY_TRACES_SAMPLE_RATE")
    metrics_enabled: bool = Field(default=True, env="METRICS_ENABLED")

    # ── Accounting provider (Zoho today; QuickBooks optional) ────────────────
    # Selects which accounting back-end syncs invoices/dues and receives payment
    # write-backs. "zoho" (default, unchanged) or "quickbooks".
    accounting_provider: str = Field(default="zoho", env="ACCOUNTING_PROVIDER")

    # QuickBooks Online (OAuth2). The rotating refresh token + realm id are stored
    # in the integration_tokens table (obtained via the admin Connect flow), not here.
    qbo_client_id: str = Field(default="", env="QBO_CLIENT_ID")
    qbo_client_secret: str = Field(default="", env="QBO_CLIENT_SECRET")
    qbo_redirect_uri: str = Field(default="", env="QBO_REDIRECT_URI")
    qbo_env: str = Field(default="sandbox", env="QBO_ENV")  # sandbox | production
    qbo_base_url: str = Field(default="", env="QBO_BASE_URL")  # auto by env if blank
    qbo_minor_version: str = Field(default="65", env="QBO_MINOR_VERSION")

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

    @model_validator(mode="after")
    def _enforce_production_secrets(self):
        """Fail closed: refuse to boot in production with insecure defaults."""
        if self.app_env.strip().lower() != "production":
            return self
        problems = []
        if self.pii_encryption_key == _INSECURE_PII_KEY:
            problems.append("PII_ENCRYPTION_KEY is the insecure dev default")
        if not self.secret_key or len(self.secret_key) < 16:
            problems.append("SECRET_KEY is missing or too short (need >= 16 chars)")
        if self.admin_password == _INSECURE_ADMIN_PW:
            problems.append("ADMIN_PASSWORD is the insecure dev default")
        if self.security_password == _INSECURE_SECURITY_PW:
            problems.append("SECURITY_PASSWORD is the insecure dev default")
        if self.dev_skip_zoho:
            problems.append("DEV_SKIP_ZOHO must be false in production")
        if problems:
            # Raise a non-ValueError so pydantic doesn't wrap it in a
            # ValidationError that would dump every setting (incl. secrets).
            raise RuntimeError(
                "Refusing to start in production with insecure config:\n  - "
                + "\n  - ".join(problems)
            )
        return self

    class Config:
        env_file = ".env"
        # Ignore unrelated env vars (e.g. API_PORT used only by docker-compose)
        # instead of failing validation.
        extra = "ignore"

settings = Settings()