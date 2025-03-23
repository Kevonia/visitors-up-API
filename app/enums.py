# app/enums.py
from enum import Enum

class StatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    PENDING = "PENDING"

class DelinquencyEnum(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"

# # Optional: Predefined roles and permissions
# class RoleEnum(str, Enum):
#     ADMIN = "ADMIN"
#     MANAGER = "MANAGER"
#     USER = "USER"
#     SECURITYOFFICER = "SECURITYOFFICER"

# class PermissionEnum(str, Enum):
#     CREATE = "CREATE"
#     READ = "READ"
#     UPDATE = "UPDATE"
#     DELETE = "DELETE"ddd