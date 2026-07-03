from fastapi import Depends,HTTPException,status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt,JWTError

from .config import *

oauth2_scheme=OAuth2PasswordBearer(
    tokenUrl="/login"
)

def get_current_user(token:str=Depends(oauth2_scheme)):

    credentials_exception=HTTPException(
        status_code=401,
        detail="Invalid Token"
    )

    try:

        payload=jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        username=payload.get("sub")
        role=payload.get("role")

        if username is None:
            raise credentials_exception

        return {
            "username":username,
            "role":role
        }

    except JWTError:
        raise credentials_exception

def admin_required(user=Depends(get_current_user)):
    if user["role"]!="admin":
        raise HTTPException(
            status_code=403,
            detail="Admins only"
        )
    return user