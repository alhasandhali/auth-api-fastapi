from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm

from ..database import users_collection
from ..schemas import UserCreate
from ..auth import hash_password, verify_password, create_access_token
from ..deps import get_current_user, admin_required

router = APIRouter()

@router.post("/register")
async def register(user: UserCreate):

    existing_user = await users_collection.find_one(
        {"username": user.username}
    )

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    await users_collection.insert_one(
        {
            "username": user.username,
            "email": user.email,
            "password": hash_password(user.password),
            "role": "user",
        }
    )

    return {"message": "User created successfully"}


@router.post("/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
):

    user = await users_collection.find_one(
        {"username": form_data.username}
    )

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    if not verify_password(
        form_data.password,
        user["password"],
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    token = create_access_token(
        {
            "sub": user["username"],
            "role": user["role"],
        }
    )

    return {
        "access_token": token,
        "token_type": "bearer",
    }


@router.get("/profile")
async def profile(
    user=Depends(get_current_user),
):
    return user


@router.get("/admin")
async def admin(
    user=Depends(admin_required),
):
    return {
        "message": "Welcome Admin"
    }