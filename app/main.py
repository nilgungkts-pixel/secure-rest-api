from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Optional
import jwt
import bcrypt
import uuid

# ─── Rate Limiting İçin Yeni Eklemer ──────────────────────────────────────────
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Kullanıcının IP adresine göre istekleri sınırlandıracak limiter ayarı
limiter = Limiter(key_func=get_remote_address)

# ─── Config ────────────────────────────────────────────────────────────────────
SECRET_KEY = "change-this-in-production"   # → os.environ["SECRET_KEY"]
ALGORITHM  = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES  = 30
REFRESH_TOKEN_EXPIRE_DAYS    = 7

app = FastAPI(
    title="Secure REST API",
    description="JWT authentication with access & refresh tokens and Rate Limiting",
    version="1.0.0",
)

# SlowAPI'yi uygulamaya entegre ediyoruz
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ─── Fake DB (swap with SQLAlchemy in production) ──────────────────────────────
fake_users_db: dict[str, dict] = {}
revoked_tokens: set[str] = set()


# ─── Models ────────────────────────────────────────────────────────────────────
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserOut(BaseModel):
    id: str
    username: str
    email: str
    created_at: str

class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token: str


# ─── JWT Helpers ───────────────────────────────────────────────────────────────
def create_token(data: dict, expires_delta: timedelta) -> str:
    payload = data.copy()
    payload.update({"exp": datetime.utcnow() + expires_delta, "jti": str(uuid.uuid4())})
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("jti") in revoked_tokens:
            raise HTTPException(status_code=401, detail="Token has been revoked")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    payload = decode_token(token)
    user = fake_users_db.get(payload.get("sub"))
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ─── Routes ────────────────────────────────────────────────────────────────────

# KORUMA: Kayıt sayfasına dakikada en fazla 5 istek atılabilir (Bot engelleme)
@app.post("/auth/register", response_model=UserOut, status_code=201,
          summary="Register a new user")
@limiter.limit("5/minute")
def register(request: Request, body: UserRegister):
    if body.username in fake_users_db:
        raise HTTPException(status_code=409, detail="Username already taken")

    hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt()).decode()
    user = {
        "id": str(uuid.uuid4()),
        "username": body.username,
        "email": body.email,
        "hashed_password": hashed,
        "created_at": datetime.utcnow().isoformat(),
    }
    fake_users_db[body.username] = user
    return UserOut(**{k: v for k, v in user.items() if k != "hashed_password"})


# KORUMA: Giriş sayfasına dakikada en fazla 5 istek atılabilir (Brute Force engelleme)
@app.post("/auth/login", response_model=TokenPair,
          summary="Login and receive access + refresh tokens")
@limiter.limit("5/minute")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form.username)
    if not user or not bcrypt.checkpw(form.password.encode(), user["hashed_password"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return TokenPair(
        access_token=create_token(
            {"sub": user["username"], "type": "access"},
            timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        ),
        refresh_token=create_token(
            {"sub": user["username"], "type": "refresh"},
            timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        ),
    )


@app.post("/auth/refresh", response_model=TokenPair,
          summary="Use a refresh token to get a new access token")
def refresh(body: RefreshRequest):
    payload = decode_token(body.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Not a refresh token")

    # Rotate: revoke old refresh token
    revoked_tokens.add(payload["jti"])

    return TokenPair(
        access_token=create_token(
            {"sub": payload["sub"], "type": "access"},
            timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        ),
        refresh_token=create_token(
            {"sub": payload["sub"], "type": "refresh"},
            timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        ),
    )


@app.post("/auth/logout", summary="Revoke the current access token")
def logout(token: str = Depends(oauth2_scheme)):
    payload = decode_token(token)
    revoked_tokens.add(payload["jti"])
    return {"message": "Logged out successfully"}


@app.get("/users/me", response_model=UserOut, summary="Get current user profile")
def me(current_user: dict = Depends(get_current_user)):
    return UserOut(**{k: v for k, v in current_user.items() if k != "hashed_password"})


@app.get("/health", summary="Health check")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}
