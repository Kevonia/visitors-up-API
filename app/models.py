# app/models.py
from sqlalchemy import Column, Integer, String, Float, UUID as SQLAlchemyUUID, Enum, ForeignKey, Table
from sqlalchemy.orm import relationship
from .database import Base
import time
import uuid
from .enums import StatusEnum, DelinquencyEnum, VisitType, VisitorStatus, ListCategory
from .security.pii import EncryptedStr

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
    email = Column(EncryptedStr, unique=True, index=True)
    phone_number = Column(EncryptedStr, unique=True, index=True)
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
    lot_no = Column(EncryptedStr, unique=True, index=True)
    status = Column(Enum(StatusEnum), default=StatusEnum.ACTIVE)
    delinquency_status = Column(Enum(DelinquencyEnum), default=DelinquencyEnum.INACTIVE)
    user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), unique=True)
      # One-to-one relationship with User
    user = relationship("User", back_populates="resident")
    visitors = relationship("Visitor", back_populates="created_by_user", lazy="joined")
    # Cached Zoho contact fields (denormalised so list/UI reads never hit Zoho).
    zoho_contact_id = Column(String, nullable=True, index=True)
    list_category = Column(Enum(ListCategory), nullable=False, default=ListCategory.WHITE)
    on_payment_plan = Column(String, nullable=True)          # "Y" / "N" / None
    outstanding_balance = Column(Float, nullable=False, default=0)
    customer_status = Column(String, nullable=True)          # Zoho contact status
    street_name = Column(EncryptedStr, nullable=True)        # PII, from cf_street_name
    zoho_synced_at = Column(Integer, nullable=True)          # epoch of last Zoho cache
    cached_invoices = relationship(
        "CachedInvoice", back_populates="resident",
        cascade="all, delete-orphan", lazy="select")
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        return {
            "id": str(self.id),
            "lot_no": self.lot_no,
            "status": self.status.value,  # Use .value to get the enum value
            "delinquency_status": self.delinquency_status.value,  # Use .value to get the enum value
            "list_category": self.list_category.value if self.list_category else "WHITE",
            "outstanding_balance": self.outstanding_balance or 0,
            "on_payment_plan": self.on_payment_plan,
            "user_id": str(self.user_id),
            # "user": self.user.to_dict() if self.user else None,  # Include user details
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class CachedInvoice(Base):
    """A locally-cached copy of a Zoho invoice (one row per invoice)."""
    __tablename__ = "cached_invoices"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    resident_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("residents.id"), index=True)
    invoice_id = Column(String, index=True)  # Zoho invoice id
    invoice_number = Column(String, nullable=True)
    status = Column(String, nullable=True)
    total = Column(Float, nullable=False, default=0)
    balance = Column(Float, nullable=False, default=0)
    due_date = Column(String, nullable=True)
    date = Column(String, nullable=True)
    last_payment_date = Column(String, nullable=True)
    currency_code = Column(String, nullable=True)
    company_name = Column(String, nullable=True)
    invoice_url = Column(String, nullable=True)
    synced_at = Column(Integer, nullable=False, default=time.time)
    resident = relationship("Resident", back_populates="cached_invoices")

    def to_dict(self):
        return {
            "invoice_id": self.invoice_id,
            "invoice_number": self.invoice_number,
            "status": self.status,
            "total": self.total or 0,
            "balance": self.balance or 0,
            "due_date": self.due_date,
            "date": self.date,
            "last_payment_date": self.last_payment_date,
            "currency_code": self.currency_code,
            "company_name": self.company_name,
            "invoice_url": self.invoice_url,
        }


class AllowList(Base):
    __tablename__ = "allowList"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    email = Column(EncryptedStr, unique=True, index=True)
    phone_number = Column(EncryptedStr, unique=True, index=True)
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


class Announcement(Base):
    __tablename__ = "announcements"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    title = Column(String, nullable=False, index=True)
    body = Column(String, nullable=False)
    # Free-text category used for UI badges: info | event | maintenance | urgent
    category = Column(String, nullable=False, default="info")
    published_at = Column(Integer, nullable=True, index=True)  # NULL = draft
    expires_at = Column(Integer, nullable=True)  # NULL = never expires
    created_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        return {
            "id": str(self.id),
            "title": self.title,
            "body": self.body,
            "category": self.category,
            "published_at": self.published_at,
            "expires_at": self.expires_at,
            "created_by": str(self.created_by) if self.created_by else None,
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
    name = Column(EncryptedStr, nullable=False)
    relationship_type = Column(String, nullable=False)
    # Lifecycle: one-time passes are consumed on first gate entry; permanent
    # visitors are reusable. valid_from / valid_until (epoch seconds, nullable)
    # bound an optional validity window; null valid_until = no expiry.
    visit_type = Column(Enum(VisitType), nullable=False, default=VisitType.ONE_TIME)
    status = Column(Enum(VisitorStatus), nullable=False, default=VisitorStatus.ACTIVE)
    valid_from = Column(Integer, nullable=True)
    valid_until = Column(Integer, nullable=True)
    phone = Column(EncryptedStr, nullable=True)
    vehicle_plate = Column(EncryptedStr, nullable=True)
    date_created = Column(Integer, default=time.time)
    created_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("residents.id"))
    created_by_user = relationship("Resident", back_populates="visitors", lazy="joined")
    gate_entries = relationship("GateEntry", back_populates="visitor")

    def is_enterable(self, now=None):
        """Return (ok, reason). Evaluates the live validity of this pass."""
        now = now if now is not None else int(time.time())
        if self.status == VisitorStatus.REVOKED:
            return False, "Visitor pass has been revoked."
        if self.status == VisitorStatus.USED:
            return False, "One-time pass has already been used."
        if self.valid_until is not None and now > self.valid_until:
            return False, "Visitor pass has expired."
        if self.valid_from is not None and now < self.valid_from:
            return False, "Visitor pass is not yet valid."
        return True, None

    def effective_status(self, now=None):
        """Status reflecting expiry without requiring a DB write."""
        now = now if now is not None else int(time.time())
        if self.status == VisitorStatus.ACTIVE and self.valid_until is not None and now > self.valid_until:
            return VisitorStatus.EXPIRED
        return self.status

    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "relationship_type": self.relationship_type,
            "visit_type": self.visit_type.value if self.visit_type else None,
            "status": self.effective_status().value,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "phone": self.phone,
            "vehicle_plate": self.vehicle_plate,
            "date_created": self.date_created,
            "created_by": str(self.created_by),
            "created_by_user": self.created_by_user.to_dict() if self.created_by_user else None,  # Include user details
        }


class GateEntry(Base):
    """An audited record of a visitor arriving at / leaving the gate."""
    __tablename__ = "gate_entries"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    visitor_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("visitors.id"), index=True)
    resident_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("residents.id"), index=True)
    lot_no = Column(EncryptedStr, nullable=True)  # snapshot at time of entry
    logged_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"))  # the guard
    entry_time = Column(Integer, nullable=False, default=time.time, index=True)
    exit_time = Column(Integer, nullable=True)
    notes = Column(String, nullable=True)

    visitor = relationship("Visitor", back_populates="gate_entries", lazy="joined")
    resident = relationship("Resident", lazy="joined")
    guard = relationship("User", lazy="joined")

    def to_dict(self):
        return {
            "id": str(self.id),
            "visitor_id": str(self.visitor_id) if self.visitor_id else None,
            "visitor_name": self.visitor.name if self.visitor else None,
            "relationship_type": self.visitor.relationship_type if self.visitor else None,
            "visit_type": self.visitor.visit_type.value if self.visitor and self.visitor.visit_type else None,
            "resident_id": str(self.resident_id) if self.resident_id else None,
            "lot_no": self.lot_no,
            "logged_by": str(self.logged_by) if self.logged_by else None,
            "logged_by_email": self.guard.email if self.guard else None,
            "entry_time": self.entry_time,
            "exit_time": self.exit_time,
            "is_on_site": self.exit_time is None,
            "notes": self.notes,
        }