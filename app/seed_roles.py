# app/seed_roles.py
from sqlalchemy.orm import Session
from .database import SessionLocal, engine
from .models import Role  # Import the Role model
from .enums import RoleEnum  # Import the RoleEnum

def seed_roles():
    db = SessionLocal()

    try:
        # Check if roles already exist
        existing_roles = db.query(Role).count()
        if existing_roles > 0:
            print("Roles already seeded. Skipping.")
            return

        # Define the roles to seed
        roles_to_seed = [
            {"name": RoleEnum.ADMIN, "description": "Administrator role"},
            {"name": RoleEnum.MANAGER, "description": "Manager role"},
            {"name": RoleEnum.USER, "description": "Regular user role"},
        ]

        # Create Role objects and add them to the session
        for role_data in roles_to_seed:
            role = Role(**role_data)
            db.add(role)

        # Commit the changes to the database
        db.commit()
        print("Roles seeded successfully.")
    except Exception as e:
        print(f"Error seeding roles: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    seed_roles()