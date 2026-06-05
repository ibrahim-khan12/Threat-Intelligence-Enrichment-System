from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.core.security import create_access_token, hash_password, verify_password
from app.db.postgres import get_db
from app.models.api_key import APIKey
from app.models.user import User
from app.schemas.auth import APIKeyCreate, APIKeyResponse, LoginRequest, TokenResponse, UserCreate
from app.services.api_keys import generate_api_key, hash_api_key, key_prefix

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username exists")
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    token = create_access_token(user.username, user.role)
    return TokenResponse(access_token=token, role=user.role)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(user.username, user.role)
    return TokenResponse(access_token=token, role=user.role)


@router.post("/api-keys", response_model=APIKeyResponse)
def create_api_key(
    payload: APIKeyCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_roles("admin", "analyst")),
):
    raw_key = generate_api_key()
    record = APIKey(
        user_id=user.id,
        name=payload.name,
        key_hash=hash_api_key(raw_key),
        key_prefix=key_prefix(raw_key),
        role=user.role,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return APIKeyResponse(
        id=record.id,
        name=record.name,
        key_prefix=record.key_prefix,
        created_at=record.created_at.isoformat(),
        api_key=raw_key,
    )


@router.get("/me")
def whoami(user: User = Depends(get_current_user)):
    return {"username": user.username, "email": user.email, "role": user.role}
