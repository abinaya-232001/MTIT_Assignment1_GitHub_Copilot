from datetime import datetime, timedelta
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core import security
from ..database import get_db
from ..config import settings

router = APIRouter(prefix="/auth", tags=["auth"])


# helper to check password strength(placeholder, could be more complex)
def _validate_password_strength(password: str):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password too short")
    # add more checks (digits, symbols, upper/lowercase, etc.)


@router.post("/register", response_model=schemas.Token)
def register(user_in: schemas.UserCreate, db: Session = Depends(get_db)):
    # validate password
    _validate_password_strength(user_in.password)
    # ensure uniqueness
    if db.query(models.User).filter((models.User.username == user_in.username) | (models.User.email == user_in.email)).first():
        raise HTTPException(status_code=400, detail="Username or email already registered")
    hashed = security.hash_password(user_in.password)
    user = models.User(
        username=user_in.username,
        email=user_in.email,
        hashed_password=hashed,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    access = security.create_access_token({"user_id": user.id, "role": user.role})
    jti = str(uuid.uuid4())
    refresh = security.create_refresh_token(jti)
    token_hash = security.hash_token(refresh)
    expires = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    rt = models.RefreshToken(
        token_hash=token_hash,
        jti=jti,
        user_id=user.id,
        expires_at=expires,
    )
    db.add(rt)
    db.commit()

    return {"access_token": access, "refresh_token": refresh}


@router.post("/login", response_model=schemas.Token)
def login(user_in: schemas.UserCreate, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == user_in.username).first()
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # check lock
    if user.lock_until and user.lock_until > datetime.utcnow():
        raise HTTPException(status_code=423, detail="Account locked, try later")

    if not security.verify_password(user_in.password, user.hashed_password):
        # failed attempt
        user.failed_attempts += 1
        if user.failed_attempts >= settings.MAX_FAILED_LOGINS:
            user.lock_until = datetime.utcnow() + timedelta(minutes=settings.LOCK_TIME_MINUTES)
            user.failed_attempts = 0
        db.commit()
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # successful login: reset counters
    user.failed_attempts = 0
    user.lock_until = None
    db.commit()

    access = security.create_access_token({"user_id": user.id, "role": user.role})
    jti = str(uuid.uuid4())
    refresh = security.create_refresh_token(jti)
    token_hash = security.hash_token(refresh)
    expires = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    # revoke existing tokens if reuse prevention is desired? we keep multiple
    rt = models.RefreshToken(
        token_hash=token_hash,
        jti=jti,
        user_id=user.id,
        expires_at=expires,
    )
    db.add(rt)
    db.commit()

    return {"access_token": access, "refresh_token": refresh}


@router.post("/refresh", response_model=schemas.Token)
def refresh(token_in: schemas.TokenRefresh, db: Session = Depends(get_db)):
    # decode and verify
    payload = security.decode_token(token_in.refresh_token)
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=400, detail="Invalid token")
    # hash incoming token and search
    token_hash = security.hash_token(token_in.refresh_token)
    stored = db.query(models.RefreshToken).filter(models.RefreshToken.token_hash == token_hash).first()
    if not stored or stored.revoked or stored.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token invalid or expired")

    # generate new tokens
    user = db.query(models.User).filter(models.User.id == stored.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    # revoke old token (rotation)
    stored.revoked = True
    db.commit()

    access = security.create_access_token({"user_id": user.id, "role": user.role})
    new_jti = str(uuid.uuid4())
    new_refresh = security.create_refresh_token(new_jti)
    new_hash = security.hash_token(new_refresh)
    expires = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    rt = models.RefreshToken(
        token_hash=new_hash,
        jti=new_jti,
        user_id=user.id,
        expires_at=expires,
    )
    db.add(rt)
    db.commit()

    return {"access_token": access, "refresh_token": new_refresh}
