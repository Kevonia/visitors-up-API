import logging
import os
from fastapi import FastAPI,Response, Request
from .routers import user, resident, allowlist, role, permission, visitor,auth,user_visitor
# from .seed_roles import seed_roles  # Import the roles seeder function
# from .seed_permissions import seed_permissions  # Import the permissions seeder function
from .logging_config import logger
from fastapi.middleware.cors import CORSMiddleware
from .zoho_integration.routes import router as zoho_router
import time
from fastapi_admin.app import app as admin_app
# from fastapi_admin.app import app as admin_app
from fastapi_admin.providers.login import UsernamePasswordProvider
from app.models import User
import aioredis
from app.config.config import  settings
# app = FastAPI()
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
# app.mount("/admin", admin_app)


# login_provider = UsernamePasswordProvider(
#     admin_model=User,
#     # enable_captcha=True,
#     login_logo_url="https://preview.tabler.io/static/logo.svg"
# )


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

app.include_router(auth.router, prefix="/api/v1", tags=["Auth"])
app.include_router(user.router, prefix="/api/v1", tags=["User"])
app.include_router(resident.router, prefix="/api/v1", tags=["Resident"])
app.include_router(allowlist.router, prefix="/api/v1", tags=["Allow List"])
app.include_router(role.router, prefix="/api/v1", tags=["Role"])
app.include_router(permission.router, prefix="/api/v1", tags=["Permission"])
app.include_router(visitor.router, prefix="/api/v1", tags=["Visitor"])
app.include_router(user_visitor.router, prefix="/api/v1/user", tags=["User Visitor"])
# app.include_router(zoho_router, prefix="/api/v1/zoho", tags=["Zoho Invoice"])

@app.on_event("startup")
async def startup_event():
    
    # redis = await  aioredis.Redis.from_url(settings.REDIS_URL, encoding="utf8")
    # admin_app.configure(
    #     logo_url="https://preview.tabler.io/static/logo-white.svg",
    #     template_folders=[os.path.join(os.path.dirname(__file__), "templates")],
    #     providers=[login_provider],
    #     redis=redis,
    # )
    # seed_roles()
    # seed_permissions()
    # await init_cache()
    logger.info("Starting up the application...")

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Shutting down the application...")