"""White-label branding: the community name, colour palette and logo.

A single global config row. Public GETs feed every client (admin, mobile,
marketing); the admin endpoints (manager+) edit it. The logo lives in Postgres
(the deploy's rsync --delete would wipe a runtime-written static file).
"""
import re
import time

from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile
from sqlalchemy.orm import Session

from .. import models, schemas, audit
from ..enums import RoleEnum
from ..utilities.db_util import get_db
from ..config.auth import require_roles
from ..logging_config import logger

router = APIRouter()

manager = require_roles(RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)

_HEX = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
_LOGO_TYPES = {"image/png", "image/jpeg", "image/webp", "image/svg+xml"}
_LOGO_MAX_BYTES = 1_048_576  # 1 MB


def _get_or_create(db: Session) -> "models.BrandingConfig":
    cfg = db.query(models.BrandingConfig).first()
    if not cfg:
        now = int(time.time())
        cfg = models.BrandingConfig(created_at=now, updated_at=now)  # model defaults = current brand
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return cfg


def _valid_color(value: str) -> bool:
    return bool(value) and bool(_HEX.match(value.strip()))


@router.get("/branding", response_model=schemas.BrandingOut)
def get_branding(db: Session = Depends(get_db)):
    """Public: the active branding (consumed by admin, mobile, marketing)."""
    return _get_or_create(db).to_dict()


@router.get("/branding/logo", include_in_schema=False)
def get_branding_logo(db: Session = Depends(get_db)):
    """Public: the raw logo bytes (or 404 when none is set)."""
    cfg = db.query(models.BrandingConfig).first()
    if not cfg or not cfg.logo_data:
        raise HTTPException(status_code=404, detail="No logo set")
    return Response(
        content=cfg.logo_data,
        media_type=cfg.logo_content_type or "image/png",
        headers={"Cache-Control": "public, max-age=300"},
    )


@router.put("/admin/branding", response_model=schemas.BrandingOut)
def update_branding(
    payload: schemas.BrandingUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(manager),
):
    cfg = _get_or_create(db)
    if payload.community_name is not None:
        name = payload.community_name.strip()
        if not name:
            raise HTTPException(status_code=422, detail="Community name cannot be empty.")
        cfg.community_name = name[:120]
    if payload.tagline is not None:
        cfg.tagline = payload.tagline.strip()[:160] or None
    for field in ("primary_color", "accent_color", "sidebar_color", "sidebar_text_color"):
        val = getattr(payload, field)
        if val is not None:
            if not _valid_color(val):
                raise HTTPException(status_code=422, detail=f"{field} must be a hex colour like #1e5631")
            setattr(cfg, field, val.strip().lower())
    cfg.updated_at = int(time.time())
    db.commit()
    db.refresh(cfg)
    audit.record("branding.update", user=user, request=request, detail="branding settings updated")
    return cfg.to_dict()


@router.post("/admin/branding/logo", response_model=schemas.BrandingOut)
async def upload_branding_logo(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user=Depends(manager),
):
    if file.content_type not in _LOGO_TYPES:
        raise HTTPException(status_code=422, detail="Logo must be a PNG, JPG, WEBP or SVG image.")
    data = await file.read()
    if not data:
        raise HTTPException(status_code=422, detail="Empty file.")
    if len(data) > _LOGO_MAX_BYTES:
        raise HTTPException(status_code=413, detail="Logo is too large (max 1 MB).")
    cfg = _get_or_create(db)
    cfg.logo_data = data
    cfg.logo_content_type = file.content_type
    cfg.updated_at = int(time.time())
    db.commit()
    db.refresh(cfg)
    audit.record("branding.logo", user=user, request=request, detail=f"logo set ({len(data)} bytes)")
    logger.info("Branding logo updated (%d bytes, %s)", len(data), file.content_type)
    return cfg.to_dict()
