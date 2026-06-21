# app/schemas.py
import re
from pydantic import BaseModel, field_validator
from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID  # Import UUID


def validate_password_strength(v: str) -> str:
    """Minimum password policy for account creation: >= 8 chars, with at least
    one letter and one digit. Raises ValueError (-> 422) on a weak password."""
    if v is None:
        return v
    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not re.search(r"[A-Za-z]", v) or not re.search(r"\d", v):
        raise ValueError("Password must contain at least one letter and one number")
    return v



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
# Resident schemas
class ResidentBase(BaseModel):
    name: Optional[str] = None
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
    list_category: str = "WHITE"          # WHITE | YELLOW | RED
    outstanding_balance: float = 0
    on_payment_plan: Optional[str] = None
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
    phone_number: Optional[str] = None  # contacts may have no phone

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
    # created_by is optional on input: the /user/visitors route fills it from
    # the authenticated resident. Admin routes may pass it explicitly.
    created_by: Optional[str] = None
    visit_type: Optional[str] = "ONE_TIME"
    valid_from: Optional[int] = None
    valid_until: Optional[int] = None
    phone: Optional[str] = None
    vehicle_plate: Optional[str] = None
    # Recurring schedule (e.g. a helper): days "MON,TUE,…" + a daily window in
    # minutes-from-midnight (local time).
    schedule_days: Optional[str] = None
    schedule_start: Optional[int] = None
    schedule_end: Optional[int] = None
    created_by_user: Optional[Resident] = None

class VisitorCreate(VisitorBase):
    pass

class VisitorUpdate(BaseModel):
    name: Optional[str] = None
    relationship_type: Optional[str] = None
    created_by: Optional[str] = None
    visit_type: Optional[str] = None
    status: Optional[str] = None
    valid_from: Optional[int] = None
    valid_until: Optional[int] = None
    phone: Optional[str] = None
    vehicle_plate: Optional[str] = None
    schedule_days: Optional[str] = None
    schedule_start: Optional[int] = None
    schedule_end: Optional[int] = None


class Visitor(VisitorBase):
    id: str  # Ensure this is a string
    status: Optional[str] = None
    share_token: Optional[str] = None
    date_created: datetime

    class Config:
        orm_mode = True
        json_encoders = {
            UUID: lambda v: str(v),  # Convert UUID to string
        }


# Gate / visit-log schemas
class GateEntryCreate(BaseModel):
    visitor_id: str
    notes: Optional[str] = None


class GateEntry(BaseModel):
    id: str
    visitor_id: Optional[str] = None
    visitor_name: Optional[str] = None
    relationship_type: Optional[str] = None
    visit_type: Optional[str] = None
    resident_id: Optional[str] = None
    lot_no: Optional[str] = None
    logged_by: Optional[str] = None
    logged_by_email: Optional[str] = None
    entry_time: int
    exit_time: Optional[int] = None
    is_on_site: bool
    notes: Optional[str] = None


class GateVisitorSearchResult(BaseModel):
    id: str
    name: str
    relationship_type: str
    visit_type: Optional[str] = None
    status: Optional[str] = None
    valid_from: Optional[int] = None
    valid_until: Optional[int] = None
    phone: Optional[str] = None
    vehicle_plate: Optional[str] = None
    lot_no: Optional[str] = None
    resident_id: Optional[str] = None
    on_site: bool = False
    open_entry_id: Optional[str] = None
    resident_list_category: Optional[str] = None  # WHITE | YELLOW | RED
    resident_name: Optional[str] = None


# Pre-registration: public (no-auth) view of a pass shared via link.
class PublicPass(BaseModel):
    id: str
    name: str
    relationship_type: Optional[str] = None
    visit_type: Optional[str] = None
    status: Optional[str] = None
    lot_no: Optional[str] = None
    resident_name: Optional[str] = None
    valid_from: Optional[int] = None
    valid_until: Optional[int] = None


# Incident / SOS schemas
class IncidentCreate(BaseModel):
    kind: Optional[str] = "panic"   # panic | medical | fire | security | other
    note: Optional[str] = None
    lot_no: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None


class IncidentOut(BaseModel):
    id: str
    reported_by: Optional[str] = None
    reporter_role: Optional[str] = None
    reporter_name: Optional[str] = None
    lot_no: Optional[str] = None
    kind: str
    status: str
    note: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[int] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[int] = None
    created_at: int


# Maintenance / "Report Issue" schemas
class MaintenanceCreate(BaseModel):
    title: str
    description: Optional[str] = None
    category: Optional[str] = "general"   # plumbing|electrical|landscaping|security|general
    priority: Optional[str] = "normal"    # low|normal|high


class MaintenanceStatusUpdate(BaseModel):
    status: str   # OPEN|IN_PROGRESS|RESOLVED|CLOSED


class MaintenanceOut(BaseModel):
    id: str
    resident_id: Optional[str] = None
    lot_no: Optional[str] = None
    category: str
    title: str
    description: Optional[str] = None
    priority: str
    status: str
    created_at: int
    updated_at: int


# Guard account schemas
class GuardCreate(BaseModel):
    email: str
    phone_number: str
    password: str

    @field_validator("password")
    @classmethod
    def _password_strength(cls, v):
        return validate_password_strength(v)


class Guard(BaseModel):
    id: str
    email: str
    phone_number: str
    role: Optional[str] = None
    created_at: datetime
# User schemas
class UserBase(BaseModel):
    email: str
    phone_number: str
    role_id: Optional[str]  = None

class UserCreate(UserBase):
    password: str

    @field_validator("password")
    @classmethod
    def _password_strength(cls, v):
        return validate_password_strength(v)

class UserUpdate(BaseModel):
    email: Optional[str] = None
    phone_number: Optional[str] = None
    role_id: Optional[str] = None
    password: Optional[str] = None

class User(UserBase):
    id: str
    role:Optional[Role] =None
    resident:Optional[Resident] =None
    last_login_at: Optional[int] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True
        json_encoders = {
            UUID: lambda v: str(v),  # Convert UUID to string
        }

class Address(BaseModel):
    address_id: Optional[int] = None
    attention: Optional[str] = None
    address: Optional[str]  = None
    street2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zip: Optional[str] = None
    country: Optional[str] = None
    fax: Optional[str] = None
    phone: Optional[str] = None
    
    
class Invoice(BaseModel):
    ach_payment_initiated: bool
    invoice_id: str
    zcrm_potential_id: str
    customer_id: str
    zcrm_potential_name: str
    customer_name: str
    company_name: str
    status: str
    invoice_number: str
    reference_number: str
    date: str
    due_date: str
    due_days: str
    email: str
    project_name: str
    billing_address: Address
    shipping_address: Address
    country: str
    phone: str
    created_by: str
    total: float
    balance: float
    payment_expected_date: str
    custom_fields: List = []
    custom_field_hash: Dict = {}
    salesperson_name: str
    shipping_charge: float
    adjustment: float
    created_time: str
    last_modified_time: str
    updated_time: str
    is_viewed_by_client: bool
    has_attachment: bool
    client_viewed_time: str
    is_emailed: bool
    color_code: str
    current_sub_status_id: str
    current_sub_status: str
    currency_id: str
    schedule_time: str
    currency_code: str
    currency_symbol: str
    template_type: str
    no_of_copies: int
    show_no_of_copies: bool
    invoice_url: str
    transaction_type: str
    reminders_sent: int
    last_reminder_sent_date: str
    last_payment_date: str
    template_id: str
    documents: str
    salesperson_id: str
    write_off_amount: float
    exchange_rate: float
    unprocessed_payment_amount: float
    
class Contact(BaseModel):
    contact_id: str
    contact_name: str
    customer_name: str
    vendor_name: str
    company_name: str
    website: str = ""
    language_code: str = ""
    language_code_formatted: str = ""
    contact_type: str 
    contact_type_formatted: str
    status: str 
    customer_sub_type: str 
    source: str
    is_linked_with_zohocrm: bool
    payment_terms: int
    payment_terms_label: str
    currency_id: str
    twitter: str = ""
    facebook: str = ""
    currency_code: str
    outstanding_receivable_amount: float
    outstanding_receivable_amount_bcy: float
    unused_credits_receivable_amount: float
    unused_credits_receivable_amount_bcy: float
    first_name: str
    last_name: str
    email: str
    phone: str
    mobile: str
    portal_status: str  # Could use Literal["enabled", "disabled"]
    portal_status_formatted: str
    created_time: datetime
    created_time_formatted: str
    last_modified_time: datetime
    last_modified_time_formatted: str
    custom_fields: List[Dict] = []
    custom_field_hash: Dict = {}
    ach_supported: bool
    has_attachment: bool
    address:Address
    invoices: List[Dict] = []  # full Zoho or cached-subset invoice dicts
    user_id: UUID = None
    delinquency_status: str  # Could use Literal["active", "inactive"]
    list_category: str = "WHITE"  # WHITE | YELLOW | RED

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        
class Token(BaseModel):
    """Token response schema"""
    access_token: str
    refresh_token: str
    token_type: str
    expires_in:  Optional[int] = None
class TokenData(BaseModel):
    """Token data schema"""
    email: str 
class TokenRefresh(BaseModel):
    refresh_token: str
    token_type: str = "Bearer"

class LogoutRequest(BaseModel):
    # Optional: pass the refresh token so it is revoked alongside the access token.
    refresh_token: Optional[str] = None


# Announcement schemas
class AnnouncementBase(BaseModel):
    title: str
    body: str
    category: str = "info"  # info | event | maintenance | urgent
    published_at: Optional[int] = None
    expires_at: Optional[int] = None


class AnnouncementCreate(AnnouncementBase):
    pass


class AnnouncementUpdate(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    category: Optional[str] = None
    published_at: Optional[int] = None
    expires_at: Optional[int] = None


class Announcement(AnnouncementBase):
    id: str
    created_by: Optional[str] = None
    created_at: int
    updated_at: int


# Tenant schemas (legacy, ported from old master; no router yet) ----------------
class TenantCreate(BaseModel):
    name: str
    email: str
    phone_number: str
    number_of_children: Optional[int] = 0
    # Optional: admin sets it explicitly; resident-facing routes infer it from
    # the logged-in user, so the app doesn't have to send it.
    resident_id: Optional[str] = None


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    phone_number: Optional[str] = None
    number_of_children: Optional[int] = None
    resident_id: Optional[str] = None


class TenantOut(BaseModel):
    id: str
    name: str
    email: str
    phone_number: str
    number_of_children: Optional[int] = 0
    resident_id: Optional[str] = None
    resident: Optional[ResidentBase] = None
    created_at: int
    updated_at: int

    class Config:
        orm_mode = True
        json_encoders = {
            UUID: lambda v: str(v),
        }