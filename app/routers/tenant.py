from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from .. import schemas, crud
from ..utilities.db_util import get_db
from ..config.auth import get_current_user

router = APIRouter()


# Create a tenant (resident apps + admin panel both post here)
@router.post("/tenants/", response_model=schemas.TenantOut)
def create_tenant(tenant: schemas.TenantCreate, db: Session = Depends(get_db),
                  current_user: schemas.UserBase = Depends(get_current_user)):
    return crud.create_tenant(db=db, tenant=tenant)


# List tenants, optionally filtered to one resident (?resident_id=...)
@router.get("/tenants/", response_model=list[schemas.TenantOut])
def read_tenants(skip: int = 0, limit: int = 100, resident_id: str = None,
                 db: Session = Depends(get_db),
                 current_user: schemas.UserBase = Depends(get_current_user)):
    return crud.get_tenants(db, skip=skip, limit=limit, resident_id=resident_id)


@router.get("/tenants/{tenant_id}", response_model=schemas.TenantOut)
def read_tenant(tenant_id: str, db: Session = Depends(get_db),
                current_user: schemas.UserBase = Depends(get_current_user)):
    db_tenant = crud.get_tenant(db, tenant_id=tenant_id)
    if db_tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return db_tenant


@router.put("/tenants/{tenant_id}", response_model=schemas.TenantOut)
def update_tenant(tenant_id: str, tenant: schemas.TenantUpdate, db: Session = Depends(get_db),
                  current_user: schemas.UserBase = Depends(get_current_user)):
    db_tenant = crud.update_tenant(db, tenant_id=tenant_id, tenant=tenant)
    if db_tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return db_tenant


@router.delete("/tenants/{tenant_id}", response_model=schemas.TenantOut)
def delete_tenant(tenant_id: str, db: Session = Depends(get_db),
                  current_user: schemas.UserBase = Depends(get_current_user)):
    db_tenant = crud.delete_tenant(db, tenant_id=tenant_id)
    if db_tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return db_tenant
