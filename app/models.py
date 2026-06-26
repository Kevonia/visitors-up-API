# app/models.py
from sqlalchemy import Column, Integer, String, Float, Boolean, UUID as SQLAlchemyUUID, Enum, ForeignKey, Table
from sqlalchemy.orm import relationship
from .database import Base
import time
import uuid
from .enums import StatusEnum, DelinquencyEnum, VisitType, VisitorStatus, ListCategory, GateDriver
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
    # Epoch seconds of the most recent successful login (NULL = never logged in).
    last_login_at = Column(Integer, nullable=True)
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        user_dict = {
            "id": str(self.id),
            "email": self.email,
            "phone_number": self.phone_number,
            "role_id": str(self.role_id),
            "last_login_at": self.last_login_at,
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
    name = Column(EncryptedStr, nullable=True)  # resident/contact name (PII)
    lot_no = Column(EncryptedStr, index=True)   # actual lot number (not unique: co-owners share)
    status = Column(Enum(StatusEnum), default=StatusEnum.ACTIVE)
    delinquency_status = Column(Enum(DelinquencyEnum), default=DelinquencyEnum.INACTIVE)
    user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), unique=True)
    number_of_children = Column(Integer, nullable=True, default=0)  # legacy field (ported from old master)
      # One-to-one relationship with User
    user = relationship("User", back_populates="resident")
    visitors = relationship("Visitor", back_populates="created_by_user", lazy="joined")
    tenants = relationship("Tenant", back_populates="resident", lazy="joined")
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
            "name": self.name,
            "lot_no": self.lot_no,
            "status": self.status.value,  # Use .value to get the enum value
            "delinquency_status": self.delinquency_status.value,  # Use .value to get the enum value
            "list_category": self.list_category.value if self.list_category else "WHITE",
            "outstanding_balance": self.outstanding_balance or 0,
            "on_payment_plan": self.on_payment_plan,
            "number_of_children": self.number_of_children,
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
    # Recurring schedule (e.g. a domestic helper): days as "MON,TUE,…" plus a
    # daily window in minutes-from-midnight (local time). When schedule_days is
    # set, the pass only enters on those days within [schedule_start, schedule_end].
    schedule_days = Column(String, nullable=True)
    schedule_start = Column(Integer, nullable=True)
    schedule_end = Column(Integer, nullable=True)
    # Public share token for a pre-registration link (guest needs no app).
    share_token = Column(String, nullable=True, unique=True, index=True)
    date_created = Column(Integer, default=time.time)
    created_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("residents.id"))
    created_by_user = relationship("Resident", back_populates="visitors", lazy="joined")
    gate_entries = relationship("GateEntry", back_populates="visitor")

    _DAYS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]

    def _within_schedule(self, now):
        """For a scheduled (recurring) pass, whether `now` falls inside the
        allowed day-of-week + daily time window. Jamaica is UTC-5 year-round."""
        local = time.gmtime(now - 5 * 3600)
        allowed = {d.strip().upper()
                   for d in (self.schedule_days or "").split(",") if d.strip()}
        if allowed and self._DAYS[local.tm_wday] not in allowed:
            return False, "This pass is not valid today."
        minutes = local.tm_hour * 60 + local.tm_min
        if self.schedule_start is not None and minutes < self.schedule_start:
            return False, "This pass is not valid at this time of day."
        if self.schedule_end is not None and minutes > self.schedule_end:
            return False, "This pass is not valid at this time of day."
        return True, None

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
        if self.schedule_days:
            ok, reason = self._within_schedule(now)
            if not ok:
                return False, reason
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
            "schedule_days": self.schedule_days,
            "schedule_start": self.schedule_start,
            "schedule_end": self.schedule_end,
            "share_token": self.share_token,
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


class Tenant(Base):
    """A resident's tenant. Legacy model ported from the old master line.

    Half-built upstream (model + schemas + table, no router); kept so the
    `tenants` table and `residents.number_of_children` column survive the
    revamp. PII columns are plain strings here to match the original schema.
    """
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

    def to_dict(self):
        return {
            "id": str(self.id),
            "name": self.name,
            "email": self.email,
            "phone_number": self.phone_number,
            "number_of_children": self.number_of_children,
            "resident_id": str(self.resident_id) if self.resident_id else None,
            "resident": self.resident.to_dict() if self.resident else None,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class AuditLog(Base):
    """Append-only security audit trail.

    One row per security-relevant action (logins, logouts, visitor and gate
    activity). Rows are written best-effort by app/audit.py and never mutated.

    user_id is the acting account when known (NULL for failed logins where no
    account matched). actor_email is the email/attempted-username, encrypted at
    rest like other PII; it stays readable even if the user is later deleted.
    """
    __tablename__ = "audit_logs"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    actor_email = Column(EncryptedStr, nullable=True)   # PII, encrypted at rest
    action = Column(String, nullable=False, index=True)  # e.g. "login.success"
    status = Column(String, nullable=False, default="success")  # success | failure
    ip = Column(String, nullable=True)
    user_agent = Column(String, nullable=True)
    detail = Column(String, nullable=True)  # short free-text / context
    created_at = Column(Integer, nullable=False, default=time.time, index=True)

    def to_dict(self):
        return {
            "id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "actor_email": self.actor_email,
            "action": self.action,
            "status": self.status,
            "ip": self.ip,
            "user_agent": self.user_agent,
            "detail": self.detail,
            "created_at": self.created_at,
        }


class MaintenanceRequest(Base):
    """A resident-reported maintenance/issue request, tracked to resolution."""
    __tablename__ = "maintenance_requests"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    resident_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("residents.id"), nullable=True, index=True)
    reporter_user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    lot_no = Column(EncryptedStr, nullable=True)   # PII, snapshot at report time
    category = Column(String, nullable=False, default="general")  # plumbing|electrical|landscaping|security|general
    title = Column(String, nullable=False)
    description = Column(String, nullable=True)
    priority = Column(String, nullable=False, default="normal")   # low|normal|high
    status = Column(String, nullable=False, default="OPEN", index=True)  # OPEN|IN_PROGRESS|RESOLVED|CLOSED
    created_at = Column(Integer, nullable=False, default=time.time, index=True)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        return {
            "id": str(self.id),
            "resident_id": str(self.resident_id) if self.resident_id else None,
            "lot_no": self.lot_no,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "priority": self.priority,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class Incident(Base):
    """A panic/SOS or safety incident raised from an app. Guards/admins are
    alerted live (FCM + SSE), acknowledge it, then resolve it."""
    __tablename__ = "incidents"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    reported_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    reporter_role = Column(String, nullable=True)
    reporter_name = Column(EncryptedStr, nullable=True)  # PII
    lot_no = Column(EncryptedStr, nullable=True)          # PII, snapshot at report time
    kind = Column(String, nullable=False, default="panic")   # panic|medical|fire|security|other
    status = Column(String, nullable=False, default="OPEN", index=True)  # OPEN|ACKNOWLEDGED|RESOLVED
    note = Column(String, nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    acknowledged_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(Integer, nullable=True)
    resolved_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    resolved_at = Column(Integer, nullable=True)
    created_at = Column(Integer, nullable=False, default=time.time, index=True)

    def to_dict(self):
        return {
            "id": str(self.id),
            "reported_by": str(self.reported_by) if self.reported_by else None,
            "reporter_role": self.reporter_role,
            "reporter_name": self.reporter_name,
            "lot_no": self.lot_no,
            "kind": self.kind,
            "status": self.status,
            "note": self.note,
            "latitude": self.latitude,
            "longitude": self.longitude,
            "acknowledged_by": str(self.acknowledged_by) if self.acknowledged_by else None,
            "acknowledged_at": self.acknowledged_at,
            "resolved_by": str(self.resolved_by) if self.resolved_by else None,
            "resolved_at": self.resolved_at,
            "created_at": self.created_at,
        }


class DeviceToken(Base):
    """An FCM registration token for push notifications.

    One row per (user, device). Tokens are upserted when an app registers after
    login and removed on logout; the push sender prunes any token the FCM API
    reports as unregistered/invalid.
    """
    __tablename__ = "device_tokens"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    user_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    platform = Column(String, nullable=True)  # "android" | "ios"
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def to_dict(self):
        return {
            "id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "token": self.token,
            "platform": self.platform,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class Gate(Base):
    """A physical gate the security app can open.

    `driver` selects how the open command reaches the hardware; `config` holds
    the driver's settings (e.g. the relay URL) as a JSON string and is encrypted
    at rest because it can contain credentials/tokens.
    """
    __tablename__ = "gates"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    name = Column(String, nullable=False)                     # "North Gate"
    location = Column(String, nullable=True)                  # free-text description
    driver = Column(Enum(GateDriver), nullable=False, default=GateDriver.MANUAL)
    config = Column(EncryptedStr, nullable=True)              # JSON string of driver settings (may hold secrets)
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(Integer, nullable=False, default=time.time)
    updated_at = Column(Integer, nullable=False, default=time.time)

    def config_dict(self) -> dict:
        import json
        if not self.config:
            return {}
        try:
            data = json.loads(self.config)
            return data if isinstance(data, dict) else {}
        except (ValueError, TypeError):
            return {}

    def to_dict(self, include_config: bool = True):
        d = {
            "id": str(self.id),
            "name": self.name,
            "location": self.location,
            "driver": self.driver.value if self.driver else GateDriver.MANUAL.value,
            "enabled": bool(self.enabled),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }
        if include_config:
            d["config"] = self.config_dict()
        return d


class GateOpenEvent(Base):
    """An audited record of an 'open gate' command (or a test trigger).

    Mirrors the accountability of GateEntry: who opened which gate, when, why,
    and whether the hardware reported success. Optionally linked to the visitor
    and gate entry it was opened for.
    """
    __tablename__ = "gate_open_events"
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, index=True, default=uuid.uuid4)
    gate_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("gates.id"), nullable=True, index=True)
    opened_by = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("users.id"), nullable=True)  # the guard/admin
    visitor_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("visitors.id"), nullable=True)
    entry_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("gate_entries.id"), nullable=True)
    reason = Column(String, nullable=True)        # visitor|delivery|resident|emergency|...
    source = Column(String, nullable=False, default="app")   # app | auto | test
    success = Column(Boolean, nullable=False, default=False)
    detail = Column(String, nullable=True)        # driver message / error
    created_at = Column(Integer, nullable=False, default=time.time, index=True)

    gate = relationship("Gate", lazy="joined")
    opener = relationship("User", lazy="joined")

    def to_dict(self):
        return {
            "id": str(self.id),
            "gate_id": str(self.gate_id) if self.gate_id else None,
            "gate_name": self.gate.name if self.gate else None,
            "opened_by": str(self.opened_by) if self.opened_by else None,
            "opened_by_email": self.opener.email if self.opener else None,
            "visitor_id": str(self.visitor_id) if self.visitor_id else None,
            "entry_id": str(self.entry_id) if self.entry_id else None,
            "reason": self.reason,
            "source": self.source,
            "success": bool(self.success),
            "detail": self.detail,
            "created_at": self.created_at,
        }