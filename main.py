from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from model import User
from schema import UserCreate, TokenVerification
from db import database
from security import get_password_hash, create_verification_token, decode_token

app = FastAPI()


@app.post("/register")
def register(user: UserCreate, db: Session = Depends(database)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = get_password_hash(user.password)
    verification_token = create_verification_token(user.email)

    new_user = User(
        email=user.email,
        hashed_password=hashed_password,
        verification_token=verification_token,
        is_verified=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"msg": "User registered successfully, verify your email", "verification_token": verification_token}

@app.post("/verify-email")
def verify_email(token_data: TokenVerification, db: Session = Depends(database)):
    try:
        payload = decode_token(token_data.token)
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token")
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token is invalid or expired")

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    if user.is_verified:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already verified")

    user.is_verified = True
    user.verification_token = None
    db.commit()
    return {"msg": "Email verified successfully"}
