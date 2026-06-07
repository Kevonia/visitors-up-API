# app/enums.py
from enum import Enum

class StatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


class DelinquencyEnum(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"


# Resident payment standing, derived from the Zoho contact:
#   YELLOW  -> "On Payment Plan" == "Y"
#   RED     -> not on a plan AND outstanding balance over the threshold (delinquent)
#   WHITE   -> everyone else (good standing)
class ListCategory(str, Enum):
    WHITE = "WHITE"
    YELLOW = "YELLOW"
    RED = "RED"


# Predefined roles. RESIDENT is an alias used in newer code; "USER" is kept
# for backwards compatibility with existing seeded data and default signups.
class RoleEnum(str, Enum):
    ADMIN = "ADMIN"
    MANAGER = "MANAGER"
    USER = "USER"
    SECURITY = "SECURITY"


# Visitor lifecycle ---------------------------------------------------------
class VisitType(str, Enum):
    ONE_TIME = "ONE_TIME"      # single authorised entry, then consumed
    PERMANENT = "PERMANENT"    # reusable indefinitely (e.g. household help)


class VisitorStatus(str, Enum):
    ACTIVE = "ACTIVE"          # may enter
    USED = "USED"              # one-time pass already consumed
    EXPIRED = "EXPIRED"        # past valid_until
    REVOKED = "REVOKED"        # resident/admin cancelled