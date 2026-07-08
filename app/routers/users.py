"""User authentication routes: register, login, profile, and admin."""

from fastapi import APIRouter, Depends, HTTPException, status, Response, Request
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt, JWTError

from ..database import users_collection
from ..schemas import UserCreate, Token, UserUpdate, PasswordUpdate
from ..auth import hash_password, verify_password, create_access_token, create_refresh_token
from ..deps import get_current_user, admin_required
from ..config import SECRET_KEY, ALGORITHM, REFRESH_TOKEN_EXPIRE_DAYS

router = APIRouter()


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate) -> dict:
    """Register a new user account."""
    existing_user = await users_collection.find_one({"username": user.username})
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists")

    existing_email = await users_collection.find_one({"email": user.email})
    if existing_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    await users_collection.insert_one({
        "username": user.username,
        "email": user.email,
        "password": hash_password(user.password),
        "full_name": user.full_name,
        "role": "user",
    })

    return {"message": "User created successfully"}


@router.post("/login", response_model=Token)
async def login(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> dict:
    """Authenticate a user and return a JWT access token."""
    user = await users_collection.find_one({
        "$or": [{"username": form_data.username}, {"email": form_data.username}]
    })

    if not user or not verify_password(form_data.password, user["password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    access_token = create_access_token({"sub": user["username"], "role": user["role"]})
    refresh_token = create_refresh_token({"sub": user["username"], "role": user["role"]})
    
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
    )

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/refresh", response_model=Token)
async def refresh(request: Request, response: Response) -> dict:
    """Refresh the access token using a valid refresh token from cookies."""
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing refresh token")
    
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")
            
        username = payload.get("sub")
        role = payload.get("role")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
            
        new_access_token = create_access_token({"sub": username, "role": role})
        new_refresh_token = create_refresh_token({"sub": username, "role": role})
        
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token,
            httponly=True,
            secure=True,
            samesite="lax",
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60
        )
        
        return {"access_token": new_access_token, "token_type": "bearer"}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")


@router.post("/logout")
async def logout(response: Response) -> dict:
    """Log out by clearing the refresh token cookie."""
    response.delete_cookie(key="refresh_token", httponly=True, secure=True, samesite="lax")
    return {"message": "Logged out successfully"}


@router.get("/profile")
async def profile(user: dict = Depends(get_current_user)) -> dict:
    db_user = await users_collection.find_one({"username": user["username"]}, {"_id": 0, "password": 0})
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user

@router.put("/profile")
async def update_profile(update_data: UserUpdate, user: dict = Depends(get_current_user)) -> dict:
    update_dict = {k: v for k, v in update_data.model_dump().items() if v is not None}
    if not update_dict:
        return {"message": "No changes provided"}
        
    await users_collection.update_one({"username": user["username"]}, {"$set": update_dict})
    return {"message": "Profile updated successfully"}


@router.put("/profile/password")
async def update_password(password_data: PasswordUpdate, user: dict = Depends(get_current_user)) -> dict:
    db_user = await users_collection.find_one({"username": user["username"]})
    if not db_user or not verify_password(password_data.current_password, db_user["password"]):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect current password")
        
    await users_collection.update_one(
        {"username": user["username"]},
        {"$set": {"password": hash_password(password_data.new_password)}}
    )
    return {"message": "Password updated successfully"}


@router.delete("/profile")
async def delete_profile(user: dict = Depends(get_current_user)) -> dict:
    result = await users_collection.delete_one({"username": user["username"]})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "Profile deleted successfully"}


@router.get("/admin")
async def admin(user: dict = Depends(admin_required)) -> dict:
    return {"message": "Welcome Admin"}
