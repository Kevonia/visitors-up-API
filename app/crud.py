import time
from sqlalchemy.orm import Session
from . import models, schemas
from .logging_config import logger
from fastapi import HTTPException, status
from app.utilities.authutil import get_password_hash

# CRUD operations for User
def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first().to_dict()

def create_user(db: Session, user: schemas.UserCreate):
    logger.info(f"Creating user with email: {user.email}")
    
    # Check if the phone number exists in the AllowList
    db_allowlist = db.query(models.AllowList).filter(models.AllowList.phone_number == user.phone_number).first()
    db_role = db.query(models.Role).filter(models.Role.name == "USER").first()
    
    if user.role_id is None:
       logger.info(f"Getting default role {user.role_id}")
       user.role_id = db_role.id
       
     # Ensure this is a string
    if not db_allowlist:
        logger.warning(f"Phone number {user.phone_number} not found in AllowList")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number not found in AllowList. User creation denied.",
        )
    hashed_password = get_password_hash(user.password)
    # Create the user
    db_user = models.User(
        email=user.email,
        phone_number=user.phone_number,
        role_id=user.role_id,
        hashed_password=hashed_password,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    logger.info(f"User created successfully: {db_user.id}")
    return db_user.to_dict()

def get_user(db: Session, user_id: str):
    logger.info(f"Fetching user with ID: {user_id}")
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user is None:
        logger.warning(f"User with ID {user_id} not found")
    return db_user.to_dict()

def get_users(db: Session, skip: int = 0, limit: int = 100):
    logger.info(f"Fetching residents with skip: {skip}, limit: {limit}")
    users = db.query(models.User).offset(skip).limit(limit).all()
    return [user.to_dict() for user in users]  # Convert each instance to a dictionary

def get_visitors(db: Session, skip: int = 0, limit: int = 100):
    logger.info(f"Fetching visitors with skip: {skip}, limit: {limit}")
    visitors = db.query(models.Visitor).offset(skip).limit(limit).all()
    return [visitor.to_dict() for visitor in visitors]  # Convert each instance to a dictionary

def update_user(db: Session, user_id: str, user: schemas.UserUpdate):
    logger.info(f"Updating user with ID: {user_id}")
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        if user.email:
            db_user.email = user.email
        if user.phone_number:
            db_user.phone_number = user.phone_number
        if user.role_id:
            db_user.role_id = user.role_id
        if user.password:
            db_user.hashed_password = get_password_hash(user.password)
        db.commit()
        db.refresh(db_user)
        logger.info(f"User updated successfully: {db_user.id}")
    else:
        logger.warning(f"User with ID {user_id} not found")
    return db_user.to_dict()

def delete_user(db: Session, user_id: str):
    logger.info(f"Deleting user with ID: {user_id}")
    db_user = db.query(models.User).filter(models.User.id == user_id).first()
    if db_user:
        db.delete(db_user)
        db.commit()
        logger.info(f"User deleted successfully: {db_user.id}")
    else:
        logger.warning(f"User with ID {user_id} not found")
    return db_user.to_dict()

# CRUD operations for Resident
def create_resident(db: Session, resident: schemas.ResidentCreate):
    logger.info(f"Creating resident with lot number: {resident.lot_no}")
    db_resident = models.Resident(
        lot_no=resident.lot_no,
        status=resident.status,
        delinquency_status=resident.delinquency_status,
        user_id=resident.user_id,
    )
    db.add(db_resident)
    db.commit()
    db.refresh(db_resident)
    logger.info(f"Resident created successfully: {db_resident.id}")
    return db_resident.to_dict()

def get_resident(db: Session, resident_id: str):
    logger.info(f"Fetching resident with ID: {resident_id}")
    db_resident = db.query(models.Resident).filter(models.Resident.id == resident_id).first()
    if db_resident is None:
        logger.warning(f"Resident with ID {resident_id} not found")
    return db_resident.to_dict()

def get_residents(db: Session, skip: int = 0, limit: int = 100):
    logger.info(f"Fetching residents with skip: {skip}, limit: {limit}")
    residents = db.query(models.Resident).offset(skip).limit(limit).all()
    return [resident.to_dict() for resident in residents]  # Convert each instance to a dictionary

def update_resident(db: Session, resident_id: str, resident: schemas.ResidentUpdate):
    logger.info(f"Updating resident with ID: {resident_id}")
    db_resident = db.query(models.Resident).filter(models.Resident.id == resident_id).first()
    if db_resident:
        if resident.lot_no:
            db_resident.lot_no = resident.lot_no
        if resident.status:
            db_resident.status = resident.status
        if resident.delinquency_status:
            db_resident.delinquency_status = resident.delinquency_status
        if resident.user_id:
            db_resident.user_id = resident.user_id
        db.commit()
        db.refresh(db_resident)
        logger.info(f"Resident updated successfully: {db_resident.id}")
    else:
        logger.warning(f"Resident with ID {resident_id} not found")
    return db_resident.to_dict()

def delete_resident(db: Session, resident_id: str):
    logger.info(f"Deleting resident with ID: {resident_id}")
    db_resident = db.query(models.Resident).filter(models.Resident.id == resident_id).first()
    if db_resident:
        db.delete(db_resident)
        db.commit()
        logger.info(f"Resident deleted successfully: {db_resident.id}")
    else:
        logger.warning(f"Resident with ID {resident_id} not found")
    return db_resident.to_dict()

# CRUD operations for AllowList
def create_allowlist(db: Session, allowlist: schemas.AllowListCreate):
    logger.info(f"Creating allowlist entry with email: {allowlist.email}")
    db_allowlist = models.AllowList(
        email=allowlist.email,
        phone_number=allowlist.phone_number,
    )
    db.add(db_allowlist)
    db.commit()
    db.refresh(db_allowlist)
    logger.info(f"AllowList entry created successfully: {db_allowlist.id}")
    return db_allowlist.to_dict()


def get_allowlist(db: Session, allowlist_id: str):
    logger.info(f"Fetching allowlist entry with ID: {allowlist_id}")
    db_allowlist = db.query(models.AllowList).filter(models.AllowList.id == allowlist_id).first()
    if db_allowlist is None:
        logger.warning(f"AllowList entry with ID {allowlist_id} not found")
    return db_allowlist.to_dict()

def get_all_allowlists(db: Session, skip: int = 0, limit: int = 100):
    logger.info(f"Fetching allowlist entries with skip: {skip}, limit: {limit}")
    allowlists = db.query(models.AllowList).offset(skip).limit(limit).all()
    return [allowlist.to_dict() for allowlist in allowlists]  # Convert each instance to a dictionary


def update_allowlist(db: Session, allowlist_id: str, allowlist: schemas.AllowListUpdate):
    logger.info(f"Updating allowlist entry with ID: {allowlist_id}")
    db_allowlist = db.query(models.AllowList).filter(models.AllowList.id == allowlist_id).first()
    if db_allowlist:
        if allowlist.email:
            db_allowlist.email = allowlist.email
        if allowlist.phone_number:
            db_allowlist.phone_number = allowlist.phone_number
        db_allowlist.updated_at =   time.time()
        db.commit()
        db.refresh(db_allowlist)
        logger.info(f"AllowList entry updated successfully: {db_allowlist.id}")
    else:
        logger.warning(f"AllowList entry with ID {allowlist_id} not found")
    return db_allowlist.to_dict()

def delete_allowlist(db: Session, allowlist_id: str):
    logger.info(f"Deleting allowlist entry with ID: {allowlist_id}")
    db_allowlist = db.query(models.AllowList).filter(models.AllowList.id == allowlist_id).first()
    if db_allowlist:
        db.delete(db_allowlist)
        db.commit()
        logger.info(f"AllowList entry deleted successfully: {db_allowlist.id}")
    else:
        logger.warning(f"AllowList entry with ID {allowlist_id} not found")
    return db_allowlist.to_dict()

# CRUD operations for Role
def create_role(db: Session, role: schemas.RoleCreate):
    logger.info(f"Creating role with name: {role.name}")
    db_role = models.Role(
        name=role.name,
        description=role.description,
    )
    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    logger.info(f"Role created successfully: {db_role.id}")
    return db_role.to_dict()

def get_role(db: Session, role_id: str):
    logger.info(f"Fetching role with ID: {role_id}")
    db_role = db.query(models.Role).filter(models.Role.id == role_id).first()
    if db_role is None:
        logger.warning(f"Role with ID {role_id} not found")
    return db_role.to_dict()

# app/crud.py
def get_roles(db: Session, skip: int = 0, limit: int = 100):
    logger.info(f"Fetching roles with skip: {skip}, limit: {limit}")
    roles = db.query(models.Role).offset(skip).limit(limit).all()
    return [role.to_dict() for role in roles]  # Convert each instance to a dictionary

def update_role(db: Session, role_id: str, role: schemas.RoleUpdate):
    logger.info(f"Updating role with ID: {role_id}")
    db_role = db.query(models.Role).filter(models.Role.id == role_id).first()
    if db_role:
        if role.name:
            db_role.name = role.name
        if role.description:
            db_role.description = role.description
        db.commit()
        db.refresh(db_role)
        logger.info(f"Role updated successfully: {db_role.id}")
    else:
        logger.warning(f"Role with ID {role_id} not found")
    return db_role.to_dict()

def delete_role(db: Session, role_id: str):
    logger.info(f"Deleting role with ID: {role_id}")
    db_role = db.query(models.Role).filter(models.Role.id == role_id).first()
    if db_role:
        db.delete(db_role)
        db.commit()
        logger.info(f"Role deleted successfully: {db_role.id}")
    else:
        logger.warning(f"Role with ID {role_id} not found")
    return db_role.to_dict()

# CRUD operations for Permission
def create_permission(db: Session, permission: schemas.PermissionCreate):
    logger.info(f"Creating permission with name: {permission.name}")
    db_permission = models.Permission(
        name=permission.name,
        description=permission.description,
    )
    db.add(db_permission)
    db.commit()
    db.refresh(db_permission)
    logger.info(f"Permission created successfully: {db_permission.id}")
    return db_permission.to_dict()

def get_permission(db: Session, permission_id: str):
    logger.info(f"Fetching permission with ID: {permission_id}")
    db_permission = db.query(models.Permission).filter(models.Permission.id == permission_id).first()
    if db_permission is None:
        logger.warning(f"Permission with ID {permission_id} not found")
    return db_permission.to_dict()

# app/crud.py
def get_permissions(db: Session, skip: int = 0, limit: int = 100):
    logger.info(f"Fetching permissions with skip: {skip}, limit: {limit}")
    permissions = db.query(models.Permission).offset(skip).limit(limit).all()
    return [permission.to_dict() for permission in permissions]  # Convert each instance to a dictionary

def update_permission(db: Session, permission_id: str, permission: schemas.PermissionUpdate):
    logger.info(f"Updating permission with ID: {permission_id}")
    db_permission = db.query(models.Permission).filter(models.Permission.id == permission_id).first()
    if db_permission:
        if permission.name:
            db_permission.name = permission.name
        if permission.description:
            db_permission.description = permission.description
        db.commit()
        db.refresh(db_permission)
        logger.info(f"Permission updated successfully: {db_permission.id}")
    else:
        logger.warning(f"Permission with ID {permission_id} not found")
    return db_permission.to_dict()

def delete_permission(db: Session, permission_id: str):
    logger.info(f"Deleting permission with ID: {permission_id}")
    db_permission = db.query(models.Permission).filter(models.Permission.id == permission_id).first()
    if db_permission:
        db.delete(db_permission)
        db.commit()
        logger.info(f"Permission deleted successfully: {db_permission.id}")
    else:
        logger.warning(f"Permission with ID {permission_id} not found")
    return db_permission.to_dict()

# CRUD operations for Visitor
def create_visitor(db: Session, visitor: schemas.VisitorCreate):
    logger.info(f"Creating visitor with name: {visitor.name}")
    db_visitor = models.Visitor(
        name=visitor.name,
        relationship_type=visitor.relationship_type,
        created_by=visitor.created_by,
    )
    db.add(db_visitor)
    db.commit()
    db.refresh(db_visitor)
    logger.info(f"Visitor created successfully: {db_visitor.id}")
    return db_visitor.to_dict()

def get_visitor(db: Session, visitor_id: str):
    logger.info(f"Fetching visitor with ID: {visitor_id}")
    db_visitor = db.query(models.Visitor).filter(models.Visitor.id == visitor_id).first()
    if db_visitor is None:
        logger.warning(f"Visitor with ID {visitor_id} not found")
    return db_visitor.to_dict()

def get_visitors(db: Session, skip: int = 0, limit: int = 100):
    logger.info(f"Fetching visitors with skip: {skip}, limit: {limit}")
    visitors = db.query(models.Visitor).offset(skip).limit(limit).all()
    return [visitor.to_dict() for visitor in visitors]  # Convert each instance to a dictionary

def update_visitor(db: Session, visitor_id: str, visitor: schemas.VisitorUpdate):
    logger.info(f"Updating visitor with ID: {visitor_id}")
    db_visitor = db.query(models.Visitor).filter(models.Visitor.id == visitor_id).first()
    if db_visitor:
        if visitor.name:
            db_visitor.name = visitor.name
        if visitor.relationship_type:
            db_visitor.relationship_type = visitor.relationship_type
        if visitor.created_by:
            db_visitor.created_by = visitor.created_by
        db.commit()
        db.refresh(db_visitor)
        logger.info(f"Visitor updated successfully: {db_visitor.id}")
    else:
        logger.warning(f"Visitor with ID {visitor_id} not found")
    return db_visitor.to_dict()

def delete_visitor(db: Session, visitor_id: str):
    logger.info(f"Deleting visitor with ID: {visitor_id}")
    db_visitor = db.query(models.Visitor).filter(models.Visitor.id == visitor_id).first()
    if db_visitor:
        db.delete(db_visitor)
        db.commit()
        logger.info(f"Visitor deleted successfully: {db_visitor.id}")
    else:
        logger.warning(f"Visitor with ID {visitor_id} not found")
    return db_visitor.to_dict()