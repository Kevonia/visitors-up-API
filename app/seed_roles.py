# app/seed_roles.py
from sqlalchemy.orm import Session
from .database import SessionLocal, engine
from .models import Role  # Import the Role model
from .enums import RoleEnum  # Import the RoleEnum

def seed_roles():
    db = SessionLocal()

    try:
        # Define the roles to seed (idempotent: only inserts missing ones)
        roles_to_seed = [
            {"name": RoleEnum.ADMIN.value, "description": "Administrator role"},
            {"name": RoleEnum.MANAGER.value, "description": "Manager role"},
            {"name": RoleEnum.USER.value, "description": "Resident / regular user role"},
            {"name": RoleEnum.SECURITY.value, "description": "Security guard role"},
        ]

        created = 0
        for role_data in roles_to_seed:
            exists = db.query(Role).filter(Role.name == role_data["name"]).first()
            if not exists:
                db.add(Role(**role_data))
                created += 1

        # Commit the changes to the database
        db.commit()
        print(f"Roles seeded successfully ({created} new).")
    except Exception as e:
        print(f"Error seeding roles: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    seed_roles()