import logging
import time
import uuid

from fastapi import FastAPI, Response, Request, Depends, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from .routers import user, resident, allowlist, role, permission, visitor, auth, user_visitor, gate, guard_account, zoho_admin, announcements, tenant, audit, incidents, passes, analytics, maintenance, gates, payments, qb_admin
from .seed_roles import seed_roles  # Import the roles seeder function
# from .seed_permissions import seed_permissions  # Import the permissions seeder function
from .logging_config import logger
from app.zoho_integration.routes import router as zoho_router
from app.config.auth import require_roles
from app.config.config import settings
from app.enums import RoleEnum


# Hide the interactive API docs (and the OpenAPI schema) in production.
_IS_PROD = settings.app_env.strip().lower() == "production"
app = FastAPI(
    title="Twickenham Glades API",
    docs_url=None if _IS_PROD else "/docs",
    redoc_url=None if _IS_PROD else "/redoc",
    openapi_url=None if _IS_PROD else "/openapi.json",
)


@app.get("/health", tags=["Health"], include_in_schema=False)
def health():
    """Lightweight liveness probe (used by Render's health check)."""
    return {"status": "ok"}

# Role groups for route-level authorization
admin_only = require_roles(RoleEnum.ADMIN.value)
admin_or_manager = require_roles(RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)



# Lock CORS to the configured origins (the admin app). A wildcard with
# allow_credentials is both unsafe and rejected by browsers.
origins = [o.strip() for o in settings.cors_allow_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static assets (e.g. the logo used in notification emails) at /static.
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.middleware("http")
async def request_context(request: Request, call_next):
    """Tag every request with an id, time it, log the outcome, and ensure any
    unhandled error becomes a clean, traceable 500 (never a leaked stack)."""
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:12]
    request.state.request_id = request_id
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        elapsed = (time.perf_counter() - start) * 1000
        logger.exception(
            f"[{request_id}] {request.method} {request.url.path} -> 500 ({elapsed:.1f}ms)")
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": request_id},
            headers={"X-Request-ID": request_id},
        )
    elapsed = (time.perf_counter() - start) * 1000
    response.headers["X-Process-Time"] = f"{elapsed:.1f}ms"
    response.headers["X-Request-ID"] = request_id
    _apply_security_headers(request, response)
    log = logger.warning if response.status_code >= 500 else logger.info
    log(f"[{request_id}] {request.method} {request.url.path} -> {response.status_code} ({elapsed:.1f}ms)")
    return response


def _apply_security_headers(request: Request, response: Response) -> None:
    """Baseline hardening headers on every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Only assert HSTS when the request actually arrived over HTTPS (Render
    # terminates TLS at the proxy and forwards the scheme in this header).
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    if proto == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", "-")


def _scrub_errors(errors: list) -> list:
    """Drop the 'input' echo from validation errors so request bodies (which may
    contain passwords/PII) never reach the logs or the response."""
    cleaned = []
    for e in errors:
        cleaned.append({k: v for k, v in e.items() if k not in ("input", "ctx")})
    return cleaned


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    rid = _request_id(request)
    safe = _scrub_errors(exc.errors())
    logger.warning(f"[{rid}] Validation error on {request.method} {request.url.path}: {safe}")
    return JSONResponse(
        status_code=422,
        content={"detail": safe, "request_id": rid},
        headers={"X-Request-ID": rid},
    )


@app.exception_handler(IntegrityError)
async def integrity_error_handler(request: Request, exc: IntegrityError):
    rid = _request_id(request)
    logger.warning(f"[{rid}] DB integrity error on {request.method} {request.url.path}: {exc.orig}")
    return JSONResponse(
        status_code=409,
        content={"detail": "This record conflicts with an existing one.", "request_id": rid},
        headers={"X-Request-ID": rid},
    )


@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_error_handler(request: Request, exc: SQLAlchemyError):
    rid = _request_id(request)
    logger.error(f"[{rid}] Database error on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=503,
        content={"detail": "A database error occurred. Please try again.", "request_id": rid},
        headers={"X-Request-ID": rid},
    )

# Public + self-service (auth handles its own access control internally)
app.include_router(auth.router, prefix="/api/v1", tags=["Auth"])
# Resident self-service: any authenticated user (ownership enforced in-route)
app.include_router(user_visitor.router, prefix="/api/v1/user", tags=["User Visitor"])
# Announcements: residents read; admin/manager mutate (guarded per-route)
app.include_router(announcements.router, prefix="/api/v1", tags=["Announcements"])
# Tenants: any authenticated user (resident apps add their own; admin manages all)
app.include_router(tenant.router, prefix="/api/v1", tags=["Tenant"])

# Admin / management surfaces — restricted by role
app.include_router(user.router, prefix="/api/v1", tags=["User"], dependencies=[Depends(admin_or_manager)])
app.include_router(resident.router, prefix="/api/v1", tags=["Resident"], dependencies=[Depends(admin_or_manager)])
app.include_router(allowlist.router, prefix="/api/v1", tags=["Allow List"], dependencies=[Depends(admin_or_manager)])
app.include_router(visitor.router, prefix="/api/v1", tags=["Visitor"], dependencies=[Depends(admin_or_manager)])
app.include_router(guard_account.router, prefix="/api/v1", tags=["Guard Accounts"])
app.include_router(role.router, prefix="/api/v1", tags=["Role"], dependencies=[Depends(admin_only)])
app.include_router(permission.router, prefix="/api/v1", tags=["Permission"], dependencies=[Depends(admin_only)])

# Gate operations — security guards, managers, admins
app.include_router(gate.router, prefix="/api/v1/gate", tags=["Gate"])
# Zoho admin: bulk delinquency sync, cache-bust and metrics
app.include_router(zoho_admin.router, prefix="/api/v1/admin", tags=["Zoho Admin"])
# Security audit trail (read-only) — admin/manager only
app.include_router(audit.router, prefix="/api/v1/admin", tags=["Audit"], dependencies=[Depends(admin_or_manager)])
# Panic/SOS incidents: any authed user can raise; guards/admins respond (per-route).
app.include_router(incidents.router, prefix="/api/v1", tags=["Incidents"])
# Public pre-registration pass lookup (no auth).
app.include_router(passes.router, prefix="/api/v1", tags=["Passes"])
# Board analytics dashboards (admin/manager).
app.include_router(analytics.router, prefix="/api/v1/admin", tags=["Analytics"], dependencies=[Depends(admin_or_manager)])
# Maintenance / "Report Issue": residents file (per-route auth); managers manage.
app.include_router(maintenance.router, prefix="/api/v1", tags=["Maintenance"])
# Gate configuration (admin): manage physical gates + test the relay. The
# guard-facing open/list endpoints live in the gate router above.
app.include_router(gates.router, prefix="/api/v1/admin", tags=["Gates"], dependencies=[Depends(admin_or_manager)])
# In-app payments: resident checkout + public return/webhook + admin list
# (per-route auth: residents create their own, public return/webhook verified).
app.include_router(payments.router, prefix="/api/v1", tags=["Payments"])
# QuickBooks Online admin (coexists with Zoho). Per-route auth: the OAuth callback
# is public (validated by state); connect/sync/metrics require admin/manager.
app.include_router(qb_admin.router, prefix="/api/v1/admin", tags=["QuickBooks"])
# app.include_router(zoho_router, prefix="/api/v1/zoho", tags=["Zoho Invoice"])

@app.on_event("startup")
async def startup_event():
    logger.info("Starting up the application...")
    try:
        seed_roles()
    except Exception as e:
        logger.error(f"Role seeding failed at startup: {e}")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down the application...")