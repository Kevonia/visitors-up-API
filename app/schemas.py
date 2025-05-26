# app/schemas.py
from pydantic import BaseModel
from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID  # Import UUID



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
    created_by: str
    created_by_user: Optional[Resident] = None# Ensure this is a string

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
# User schemas
class UserBase(BaseModel):
    email: str
    phone_number: str
    role_id: Optional[str]  = None

class UserCreate(UserBase):
    password: str

class UserUpdate(BaseModel):
    email: Optional[str] = None
    phone_number: Optional[str] = None
    role_id: Optional[str] = None
    password: Optional[str] = None

class User(UserBase):
    id: str
    role:Optional[Role] =None
    resident:Optional[Resident] =None
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
    # customer_name: str
    # vendor_name: str
    # company_name: str
    # website: str = ""
    # language_code: str = ""
    # language_code_formatted: str = ""
    # contact_type: str 
    # contact_type_formatted: str
    status: str 
    # customer_sub_type: str 
    # source: str
    # is_linked_with_zohocrm: bool
    # payment_terms: int
    # payment_terms_label: str
    # currency_id: str
    # twitter: str = ""
    # facebook: str = ""
    # currency_code: str
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
    # portal_status_formatted: str
    # created_time: datetime
    # created_time_formatted: str
    # last_modified_time: datetime
    # last_modified_time_formatted: str
    # custom_fields: List[Dict] = []
    # custom_field_hash: Dict = {}
    # ach_supported: bool
    # has_attachment: bool
    address:Address
    invoices: List[Invoice] = []
    user_id: UUID = None
    delinquency_status: str  # Could use Literal["active", "inactive"]
    cf_lot_number: Optional[str] = None
    cf_street_name: Optional[str] = None
    role: Optional[str] = None

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