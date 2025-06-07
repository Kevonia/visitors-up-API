# app/models.py
from datetime import datetime
from sqlalchemy import Column, Integer, String, UUID as SQLAlchemyUUID, Enum, ForeignKey, Table,DateTime
from sqlalchemy.orm import relationship
from .database import Base
import time
import uuid
from .enums import StatusEnum, DelinquencyEnum  

# Association table for many-to-many relationship between Role and Permission
role_permission_association = Table(
    "role_permission",
    Base.metadata,
    Column("role_id", SQLAlchemyUUID(as_uuid=True), ForeignKey("roles.id")),
    Column("permission_id", SQLAlchemyUUID(as_uuid=True), ForeignKey("permissions.id")),
)

class User(Base):
    __tablename__ = "users"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True)
    phone_number = Column(String, unique=True, index=True)
    role_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("roles.id"))
    role = relationship("Role", back_populates="users", lazy="joined")
    hashed_password = Column(String)
   # One-to-one relationship with Resident
    resident = relationship("Resident", back_populates="user", uselist=False)
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        user_dict = {
            "id": str(self.id),
            "email": self.email,
            "phone_number": self.phone_number,
            "role_id": str(self.role_id),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

        # Include role if it's loaded
        if self.role:
            user_dict["role"] = self.role.to_dict()

        # Include residents if they're loaded
        if self.resident:
            user_dict["resident"] = self.resident.to_dict() 
        return user_dict


class Resident(Base):
    __tablename__ = "residents"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    lot_no = Column(String, unique=True, index=True)
    status = Column(Enum(StatusEnum), default=StatusEnum.ACTIVE)
    delinquency_status = Column(Enum(DelinquencyEnum), default=DelinquencyEnum.INACTIVE)
    user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), unique=True)
    number_of_children = Column(Integer, nullable=True, default=0)  
      # One-to-one relationship with User
    user = relationship("User", back_populates="resident")
    visitors = relationship("Visitor", back_populates="created_by_user", lazy="joined")
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)
    
    def to_dict(self):
        return {
            "id": str(self.id),
            "lot_no": self.lot_no,
            "status": self.status.value,  # Use .value to get the enum value
            "delinquency_status": self.delinquency_status.value,  # Use .value to get the enum value
            "user_id": str(self.user_id),
            "Number_of_children": self.number_of_children,
            # "user": self.user.to_dict() if self.user else None,  # Include user details
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class Tenant(Base):
    __tablename__ = "tenants"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True) 
    phone_number = Column(String, unique=True, index=True)
    number_of_children = Column(Integer, nullable=True, default=0)  
    resident_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("residents.id"))
    resident = relationship("Resident", back_populates="tenants", lazy="joined")
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)
    
      # One-to-one relationship with User
    
    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "email": self.email,  # Use .value to get the enum value
            "phone_number": self.phone_number,  # Use .value to get the enum value
            "resident_id": self.resident_id,
            "resident": self.resident.to_dict() if self.resident else None,  # Include resident details
               # "user": self.user.to_dict() if self.user else None,  # Include user details
            "created_at": self.created_at,
            "updated_at": self.updated_at,
           
        }

class AllowList(Base):
    __tablename__ = "allowList"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    email = Column(String, unique=True, index=True)
    phone_number = Column(String, unique=True, index=True)
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        return {
            "id": str(self.id),
            "email": self.email,
            "phone_number": self.phone_number,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class Role(Base):
    __tablename__ = "roles"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)
    users = relationship("User", back_populates="role", lazy="joined")
    permissions = relationship("Permission", secondary=role_permission_association, back_populates="roles", lazy="joined")
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,  # Use .value to get the enum value
            "description": self.description,
            # "users": [user.to_dict() for user in self.users] if self.users else [],
            "permissions": [permission.to_dict() for permission in self.permissions] if self.permissions else [],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class Permission(Base):
    __tablename__ = "permissions"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)
    roles = relationship("Role", secondary=role_permission_association, back_populates="permissions", lazy="joined")
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,  # Use .value to get the enum value
            "description": self.description,
            "roles": [role.to_dict() for role in self.roles] if self.roles else [],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class Visitor(Base):
    __tablename__ = "visitors"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    relationship_type = Column(String, nullable=False)
    date_created = Column(Integer, default=time.time)
    created_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("residents.id"))
    created_by_user = relationship("Resident", back_populates="visitors", lazy="joined")

    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "relationship_type": self.relationship_type,
            "date_created": self.date_created,
            "created_by": str(self.created_by),
            "created_by_user": self.created_by_user.to_dict() if self.created_by_user else None,  # Include user details
        }
        
class PasswordReset(Base):
    __tablename__ = "password_resets"
    
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String, nullable=False, index=True)
    token_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    
    def __repr__(self):
        return f"<PasswordReset {self.email}>"