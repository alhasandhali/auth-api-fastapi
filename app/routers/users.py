"""User authentication routes: register, login, profile, and admin."""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from ..database import users_collection
from ..schemas import UserCreate, Token, UserUpdate
from ..auth import hash_password, verify_password, create_access_token
from ..deps import get_current_user, admin_required

router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate) -> dict:
    """Register a new user account.

    Checks for duplicate username and email before creating the user.
    """
    # Check duplicate username
    existing_user = await users_collection.find_one(
        {"username": user.username}
    )
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists",
        )

    # Check duplicate email
    existing_email = await users_collection.find_one(
        {"email": user.email}
    )
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
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


@router.post("/login", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> dict:
    """Authenticate a user and return a JWT access token."""
    user = await users_collection.find_one(
        {"username": form_data.username}
    )

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not verify_password(
        form_data.password,
        user["password"],
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
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
    user: dict = Depends(get_current_user),
) -> dict:
    """Return the authenticated user's profile information."""
    db_user = await users_collection.find_one({"username": user["username"]}, {"_id": 0, "password": 0})
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@router.put("/profile")
async def update_profile(
    update_data: UserUpdate,
    user: dict = Depends(get_current_user),
) -> dict:
    """Update user profile."""
    update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
    if not update_dict:
        return {"message": "No changes provided"}
        
    await users_collection.update_one(
        {"username": user["username"]},
        {"$set": update_dict}
    )
    return {"message": "Profile updated successfully"}


@router.get("/admin")
async def admin(
    user: dict = Depends(admin_required),
) -> dict:
    """Admin-only endpoint. Returns a welcome message for admins."""
    return {
        "message": "Welcome Admin",
    }