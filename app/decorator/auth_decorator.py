from fastapi import HTTPException, status
from functools import wraps

def admin_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        current_user = kwargs.get("current_user")
        print(current_user)
        # if current_user.role != "Admin":
        #     raise HTTPException(
        #         status_code=status.HTTP_403_FORBIDDEN,
        #         detail="You do not have permission to access this resource.",
        #     )

        return await func(*args, **kwargs)

    return wrapper