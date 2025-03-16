import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.crud import create_user, get_user, update_user, delete_user
from app.models import Base, User, AllowList
from app.schemas import UserCreate, UserUpdate
from fastapi import HTTPException

# Setup the test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create the database schema
Base.metadata.create_all(bind=engine)

# Fixture to provide a clean database session for each test
@pytest.fixture(scope="function")
def db_session():
    connection = engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    yield session
    session.close()
    transaction.rollback()
    connection.close()

# Test data
test_user_data = {
    "email": "test@example.com",
    "phone_number": "1234567890",
    "role_id": 1,
    "hashed_password": "hashedpassword123"
}

test_allowlist_data = {
    "email": "test@example.com",
    "phone_number": "1234567890"
}

# Test create_user
def test_create_user(db_session):
    # Add the phone number to the AllowList first
    db_allowlist = AllowList(**test_allowlist_data)
    db_session.add(db_allowlist)
    db_session.commit()

    # Create the user
    user = UserCreate(**test_user_data)
    created_user = create_user(db_session, user)

    assert created_user["email"] == test_user_data["email"]
    assert created_user["phone_number"] == test_user_data["phone_number"]
    assert created_user["role_id"] == test_user_data["role_id"]

    # Test that creating a user with a non-existent phone number raises an exception
    invalid_user_data = test_user_data.copy()
    invalid_user_data["phone_number"] = "0000000000"
    invalid_user = UserCreate(**invalid_user_data)

    with pytest.raises(HTTPException) as exc_info:
        create_user(db_session, invalid_user)
    assert exc_info.value.status_code == 400
    assert "Phone number not found in AllowList" in str(exc_info.value.detail)

# Test get_user
def test_get_user(db_session):
    # Add the phone number to the AllowList first
    db_allowlist = AllowList(**test_allowlist_data)
    db_session.add(db_allowlist)
    db_session.commit()

    # Create the user
    user = UserCreate(**test_user_data)
    created_user = create_user(db_session, user)

    # Fetch the user
    fetched_user = get_user(db_session, created_user["id"])
    assert fetched_user["email"] == test_user_data["email"]
    assert fetched_user["phone_number"] == test_user_data["phone_number"]
    assert fetched_user["role_id"] == test_user_data["role_id"]

    # Test fetching a non-existent user
    non_existent_user = get_user(db_session, "non-existent-id")
    assert non_existent_user is None

# Test update_user
def test_update_user(db_session):
    # Add the phone number to the AllowList first
    db_allowlist = AllowList(**test_allowlist_data)
    db_session.add(db_allowlist)
    db_session.commit()

    # Create the user
    user = UserCreate(**test_user_data)
    created_user = create_user(db_session, user)

    # Update the user
    updated_data = {"email": "updated@example.com", "phone_number": "0987654321"}
    updated_user = update_user(db_session, created_user["id"], UserUpdate(**updated_data))

    assert updated_user["email"] == updated_data["email"]
    assert updated_user["phone_number"] == updated_data["phone_number"]

    # Test updating a non-existent user
    non_existent_user = update_user(db_session, "non-existent-id", UserUpdate(**updated_data))
    assert non_existent_user is None

# Test delete_user
def test_delete_user(db_session):
    # Add the phone number to the AllowList first
    db_allowlist = AllowList(**test_allowlist_data)
    db_session.add(db_allowlist)
    db_session.commit()

    # Create the user
    user = UserCreate(**test_user_data)
    created_user = create_user(db_session, user)

    # Delete the user
    deleted_user = delete_user(db_session, created_user["id"])
    assert deleted_user["id"] == created_user["id"]

    # Verify the user is deleted
    fetched_user = get_user(db_session, created_user["id"])
    assert fetched_user is None

    # Test deleting a non-existent user
    non_existent_user = delete_user(db_session, "non-existent-id")
    assert non_existent_user is None