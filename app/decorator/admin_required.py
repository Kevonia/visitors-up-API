from fastapi import HTTPException, status
from functools import wraps

def admin_required(func):
    """
    Decorator to ensure the user has the 'Admin' role.
    Returns a 404 Not Found response if the user is not an Admin.
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Extract the current user from the kwargs (assuming it's passed as `current_user`)
        current_user = kwargs.get("current_user")

        # Check if the user's role is 'Admin'
        if current_user.role != "Admin":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Not Found",
            )

        # If the user is an Admin, call the original function
        return await func(*args, **kwargs)

    return wrapper