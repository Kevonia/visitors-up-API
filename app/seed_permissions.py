# app/seed_permissions.py
from sqlalchemy.orm import Session
from .database import SessionLocal
from .models import Permission  # Import the Permission model
from .enums import PermissionEnum  # Import the PermissionEnum

def seed_permissions():
    db = SessionLocal()

    try:
        # Check if permissions already exist
        existing_permissions = db.query(Permission).count()
        if existing_permissions > 0:
            print("Permissions already seeded. Skipping.")
            return

        # Define the permissions to seed
        permissions_to_seed = [
            {"name": PermissionEnum.CREATE, "description": "Create permission"},
            {"name": PermissionEnum.READ, "description": "Read permission"},
            {"name": PermissionEnum.UPDATE, "description": "Update permission"},
            {"name": PermissionEnum.DELETE, "description": "Delete permission"},
        ]

        # Create Permission objects and add them to the session
        for permission_data in permissions_to_seed:
            permission = Permission(**permission_data)
            db.add(permission)

        # Commit the changes to the database
        db.commit()
        print("Permissions seeded successfully.")
    except Exception as e:
        print(f"Error seeding permissions: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    seed_permissions()