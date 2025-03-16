# app/models.py
from sqlalchemy import Column, Integer, String, UUID as SQLAlchemyUUID, Enum, ForeignKey, Table
from sqlalchemy.orm import relationship
from .database import Base
import time
import uuid
from .enums import StatusEnum, DelinquencyEnum, RoleEnum, PermissionEnum

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
    role = relationship("Role", back_populates="users")
    hashed_password = Column(String)
    residents = relationship("Resident", back_populates="user")
    visitors = relationship("Visitor", back_populates="created_by_user")
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        return {
            "id": str(self.id),
            "email": self.email,
            "phone_number": self.phone_number,
            "role_id": str(self.role_id),
            "hashed_password": self.hashed_password,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

class Resident(Base):
    __tablename__ = "residents"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    lot_no = Column(String, unique=True, index=True)
    status = Column(Enum(StatusEnum), default=StatusEnum.ACTIVE)
    delinquency_status = Column(Enum(DelinquencyEnum), default=DelinquencyEnum.NONE)
    user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"))
    user = relationship("User", back_populates="residents")
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        return {
            "id": str(self.id),
            "lot_no": self.lot_no,
            "status": self.status,
            "delinquency_status": self.delinquency_status,
            "user_id": str(self.user_id),
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
    name = Column(Enum(RoleEnum), unique=True, nullable=False)
    description = Column(String, nullable=True)
    users = relationship("User", back_populates="role")
    permissions = relationship("Permission", secondary=role_permission_association, back_populates="roles")
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

class Permission(Base):
    __tablename__ = "permissions"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    name = Column(Enum(PermissionEnum), unique=True, nullable=False)
    description = Column(String, nullable=True)
    roles = relationship("Role", secondary=role_permission_association, back_populates="permissions")
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

class Visitor(Base):
    __tablename__ = "visitors"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    relationship_type = Column(String, nullable=False)
    date_created = Column(Integer, default=time.time)
    created_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"))
    created_by_user = relationship("User", back_populates="visitors")

    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "relationship_type": self.relationship_type,
            "date_created": self.date_created,
            "created_by": str(self.created_by),
        }