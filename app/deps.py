"""Authentication dependencies for route protection."""

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError

from .config import SECRET_KEY, ALGORITHM

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Decode a JWT token and return the current user payload.

    Raises:
        HTTPException: 401 if the token is invalid or missing the subject claim.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid Token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        username: str | None = payload.get("sub")
        role: str | None = payload.get("role")

        if username is None:
            raise credentials_exception

        return {
            "username": username,
            "role": role,
        }

    except JWTError:
        raise credentials_exception


def admin_required(user: dict = Depends(get_current_user)) -> dict:
    """Dependency that restricts access to admin users only.

    Raises:
        HTTPException: 403 if the authenticated user is not an admin.
    """
    if user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admins only",
        )
    return user