# app/routers/announcements.py
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import schemas, crud
from ..utilities.db_util import get_db
from ..config.auth import get_current_user, require_roles
from ..enums import RoleEnum
from ..notifications.service import notify_announcement
from ..logging_config import logger

router = APIRouter()

# Mutations are restricted to admins/managers; reads are open to any
# authenticated resident.
admin_or_manager = require_roles(RoleEnum.ADMIN.value, RoleEnum.MANAGER.value)


@router.get("/announcements/", response_model=list[schemas.Announcement])
def read_announcements(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.UserBase = Depends(get_current_user),
):
    """Published, non-expired announcements for residents (newest first)."""
    return crud.get_announcements(db, skip=skip, limit=limit)


@router.get("/announcements/{announcement_id}", response_model=schemas.Announcement)
def read_announcement(
    announcement_id: str,
    db: Session = Depends(get_db),
    current_user: schemas.UserBase = Depends(get_current_user),
):
    announcement = crud.get_announcement(db, announcement_id=announcement_id)
    if announcement is None:
        raise HTTPException(status_code=404, detail="Announcement not found")
    return announcement


@router.post(
    "/announcements/",
    response_model=schemas.Announcement,
    dependencies=[Depends(admin_or_manager)],
)
def create_announcement(
    announcement: schemas.AnnouncementCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: schemas.UserBase = Depends(get_current_user),
):
    user = crud.get_user_by_email(db, email=current_user.email)
    created_by = str(user.id) if user else None
    created = crud.create_announcement(db, announcement=announcement, created_by=created_by)
    # Email + SMS all residents about the new announcement (best-effort).
    background_tasks.add_task(
        notify_announcement,
        created.get("title", ""), created.get("body", ""), created.get("category", "info"),
    )
    return created


@router.put(
    "/announcements/{announcement_id}",
    response_model=schemas.Announcement,
    dependencies=[Depends(admin_or_manager)],
)
def update_announcement(
    announcement_id: str,
    announcement: schemas.AnnouncementUpdate,
    db: Session = Depends(get_db),
):
    updated = crud.update_announcement(db, announcement_id=announcement_id, announcement=announcement)
    if updated is None:
        raise HTTPException(status_code=404, detail="Announcement not found")
    return updated


@router.delete(
    "/announcements/{announcement_id}",
    response_model=schemas.Announcement,
    dependencies=[Depends(admin_or_manager)],
)
def delete_announcement(
    announcement_id: str,
    db: Session = Depends(get_db),
):
    deleted = crud.delete_announcement(db, announcement_id=announcement_id)
    if deleted is None:
        raise HTTPException(status_code=404, detail="Announcement not found")
    return deleted
