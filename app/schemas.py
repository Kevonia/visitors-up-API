# app/schemas.py
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
from uuid import UUID  # Import UUID

# User schemas
class UserBase(BaseModel):
    email: str
    phone_number: str
    role_id: str  # Ensure this is a string

class UserCreate(UserBase):
    hashed_password: str

class UserUpdate(BaseModel):
    email: Optional[str] = None
    phone_number: Optional[str] = None
    role_id: Optional[str] = None
    hashed_password: Optional[str] = None

class User(UserBase):
    id: str  # Ensure this is a string
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        json_encoders = {
            UUID: lambda v: str(v),  # Convert UUID to string
        }

# Resident schemas
class ResidentBase(BaseModel):
    lot_no: str
    status: str  # Ensure this is a string (or use Enum if applicable)
    delinquency_status: str  # Ensure this is a string (or use Enum if applicable)
    user_id: str  # Ensure this is a string

class ResidentCreate(ResidentBase):
    pass

class ResidentUpdate(BaseModel):
    lot_no: Optional[str] = None
    status: Optional[str] = None
    delinquency_status: Optional[str] = None
    user_id: Optional[str] = None

class Resident(ResidentBase):
    id: str  # Ensure this is a string
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        json_encoders = {
            UUID: lambda v: str(v),  # Convert UUID to string
        }

# AllowList schemas
class AllowListBase(BaseModel):
    email: str
    phone_number: str

class AllowListCreate(AllowListBase):
    pass

class AllowListUpdate(BaseModel):
    email: Optional[str] = None
    phone_number: Optional[str] = None

class AllowList(AllowListBase):
    id: str  # Ensure this is a string
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        json_encoders = {
            UUID: lambda v: str(v),  # Convert UUID to string
        }

# Role schemas
class RoleBase(BaseModel):
    name: str  # Ensure this is a string (or use Enum if applicable)
    description: Optional[str] = None

class RoleCreate(RoleBase):
    pass

class RoleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class Role(RoleBase):
    id: str  # Ensure this is a string
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        json_encoders = {
            UUID: lambda v: str(v),  # Convert UUID to string
        }

# Permission schemas
class PermissionBase(BaseModel):
    name: str  # Ensure this is a string (or use Enum if applicable)
    description: Optional[str] = None

class PermissionCreate(PermissionBase):
    pass

class PermissionUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None

class Permission(PermissionBase):
    id: str  # Ensure this is a string
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        json_encoders = {
            UUID: lambda v: str(v),  # Convert UUID to string
        }

# Visitor schemas
class VisitorBase(BaseModel):
    name: str
    relationship_type: str
    created_by: str  # Ensure this is a string

class VisitorCreate(VisitorBase):
    pass

class VisitorUpdate(BaseModel):
    name: Optional[str] = None
    relationship_type: Optional[str] = None
    created_by: Optional[str] = None

class Visitor(VisitorBase):
    id: str  # Ensure this is a string
    date_created: datetime

    class Config:
        orm_mode = True
        json_encoders = {
            UUID: lambda v: str(v),  # Convert UUID to string
        }