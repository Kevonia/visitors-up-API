import logging
from fastapi import FastAPI, Response, Request, Depends
from .routers import user, resident, allowlist, role, permission, visitor, auth, user_visitor, gate, guard_account, zoho_admin
from .seed_roles import seed_roles  # Import the roles seeder function
# from .seed_permissions import seed_permissions  # Import the permissions seeder function
from .logging_config import logger
from fastapi.middleware.cors import CORSMiddleware
from app.zoho_integration.routes import router as zoho_router
from app.config.auth import require_roles
from app.enums import RoleEnum
import time


app = FastAPI()

# Role groups for route-level authorization
admin_only = require_roles(RoleEnum.ADMIN.value)
admin_or_manager = require_roles(RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)



origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = time.perf_counter() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response

# Public + self-service (auth handles its own access control internally)
app.include_router(auth.router, prefix="/api/v1", tags=["Auth"])
# Resident self-service: any authenticated user (ownership enforced in-route)
app.include_router(user_visitor.router, prefix="/api/v1/user", tags=["User Visitor"])

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