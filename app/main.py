import json
import re
import secrets
from fastapi import HTTPException, status
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from fastapi.middleware.cors import CORSMiddleware
import os
import resend

resend.api_key = os.getenv("RESEND_API_KEY", "").strip()

print("RESEND KEY LOADED:", bool(resend.api_key))

from app.db import Base, engine, get_db
from app.models import User, HistoryItem
from app.schemas import (
    RegisterRequest,
    SolveRequest,
    SolveResponse,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    ChangeExpiredPasswordRequest,
)

from app.security import (
    hash_password,
    verify_password,
    create_access_token,
    SECRET_KEY,
    ALGORITHM,
)

from app.solver import (
    build_equation_pretty,
    solve_roots_durand_kerner,
    auto_fit_y,
    roots_to_json,
    roots_from_json,
)

from sqlalchemy import text


app = FastAPI(title="Polynomial Solver API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://poly-solver-flutter.vercel.app"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"status": "ok"}


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


# =========================
# AUTH HELPERS
# =========================

def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")

    return user


def require_admin(user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def validate_password_policy(password: str):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one capital letter")
    if not re.search(r"[0-9]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one number")
    if not re.search(r"[!@#\$&*~^%+=_\-]", password):
        raise HTTPException(status_code=400, detail="Password must contain at least one special character")


# =========================
# REGISTER
# =========================

@app.post("/register")
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    existing_email = db.query(User).filter(User.email == payload.email).first()
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already exists")

    validate_password_policy(payload.password)

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role="user",
        is_active=True,
        password_changed_at=datetime.utcnow(),
        password_expires_at=datetime.utcnow() + timedelta(days=90),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return {"message": "User registered successfully"}


# =========================
# FORGOT PASSWORD
# =========================

def send_password_reset_email(to_email: str, token: str):
    reset_link = f"https://poly-solver-flutter.vercel.app/reset-password?token={token}&email={to_email}"

    try:
        resend.Emails.send({
            "from": "Polynomial Solver <onboarding@resend.dev>",
            "to": [to_email],
            "subject": "Reset your password",
            "html": f"""
                <p>You requested a password reset.</p>
                <p><a href="{reset_link}">Reset Password</a></p>
                <p>This link expires in 15 minutes.</p>
            """
        })
        print("EMAIL SENT SUCCESSFULLY")

    except Exception as e:
        print("RESEND ERROR:", repr(e))
        raise


@app.post("/forgot-password")
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    print("FORGOT PASSWORD REQUEST FOR:", payload.email)

    response_msg = {"message": "If the email exists, recovery instructions have been sent."}

    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not user.is_active:
        print("NO USER FOUND OR USER INACTIVE")
        return response_msg

    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_password(raw_token)

    user.reset_token = token_hash
    user.reset_token_expires_at = datetime.utcnow() + timedelta(minutes=15)

    db.commit()

    print("SENDING EMAIL TO:", user.email)
    send_password_reset_email(user.email, raw_token)

    return response_msg



# =========================
# RESET PASSWORD
# =========================

@app.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()
    if not user or not user.reset_token or not user.reset_token_expires_at:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    if user.reset_token_expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Token expired")

    if not verify_password(payload.token, user.reset_token):
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    validate_password_policy(payload.new_password)

    user.password_hash = hash_password(payload.new_password)
    user.password_changed_at = datetime.utcnow()
    user.password_expires_at = datetime.utcnow() + timedelta(days=90)
    user.reset_token = None
    user.reset_token_expires_at = None

    db.commit()

    return {"message": "Password reset successful. Please log in."}


# =========================
# LOGIN
# =========================

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()

    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    if user.password_expires_at < datetime.utcnow():
        raise HTTPException(status_code=403, detail="PASSWORD_EXPIRED")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


# =========================
# CHANGE EXPIRED PASSWORD
# =========================

@app.post("/change-expired-password")
def change_expired_password(payload: ChangeExpiredPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(payload.old_password, user.password_hash):
        raise HTTPException(status_code=401, detail="Old password is incorrect")

    validate_password_policy(payload.new_password)

    user.password_hash = hash_password(payload.new_password)
    user.password_changed_at = datetime.utcnow()
    user.password_expires_at = datetime.utcnow() + timedelta(days=90)

    db.commit()
    return {"message": "Password changed successfully. Please log in."}


# =========================
# USER HISTORY
# =========================

@app.get("/history")
def history(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    items = (
        db.query(HistoryItem)
        .filter(HistoryItem.user_id == current_user.id)
        .order_by(HistoryItem.created_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "equation": h.polynomial,
            "created_at": h.created_at.isoformat(),
            "roots": json.loads(h.roots),
        }
        for h in items
    ]


# =========================
# ADMIN
# =========================

@app.get("/admin/users")
def admin_all_users(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).order_by(User.id.asc()).all()
    return {
        "users": [
            {
                "username": u.username,
                "role": u.role,
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
            for u in users
        ]
    }


@app.get("/admin/history")
def admin_all_history(admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    items = db.query(HistoryItem).order_by(HistoryItem.id.desc()).all()
    return {
        "items": [
            {
                "username": h.user.username,
                "equation": h.polynomial,
                "created_at": h.created_at.isoformat(),
            }
            for h in items
        ]
    }


@app.delete("/admin/users/{username}")
def delete_user(username: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(user)
    db.commit()
    return {"message": "User deleted"}


@app.post("/admin/users/{username}/disable")
def disable_user(username: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.role == "admin":
        raise HTTPException(status_code=400, detail="Cannot disable admin user")

    user.is_active = False
    db.commit()
    return {"message": f"{username} has been disabled"}


@app.post("/admin/users/{username}/enable")
def enable_user(username: str, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = True
    db.commit()
    return {"message": f"{username} has been enabled"}


# =========================
# SOLVE
# =========================

@app.post("/solve", response_model=SolveResponse)
def solve_polynomial(
    payload: SolveRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    equation = build_equation_pretty(payload.degree, payload.coeffs)
    roots_complex = solve_roots_durand_kerner(payload.coeffs)
    roots_json = roots_to_json(roots_complex)
    roots = roots_from_json(roots_json)
    y_min, y_max = auto_fit_y(payload.coeffs, payload.x_min, payload.x_max)

    history_item = HistoryItem(
        user_id=current_user.id,
        polynomial=equation,
        coeffs_csv=",".join(str(c) for c in payload.coeffs),
        roots=roots_json,
        x_min=payload.x_min,
        x_max=payload.x_max,
        y_min=y_min,
        y_max=y_max,
    )

    db.add(history_item)
    db.commit()

    return {
        "equation": equation,
        "roots": roots,
        "x_min": payload.x_min,
        "x_max": payload.x_max,
        "y_min": y_min,
        "y_max": y_max,
    }


@app.get("/test-db")
def test_db():
    with engine.connect() as conn:
        conn.execute(text("select 1"))
    return {"status": "connected to supabase"}


@app.get("/db-info")
def db_info(db: Session = Depends(get_db)):
    result = db.execute(text("""
        SELECT
            current_database() AS database,
            inet_server_addr() AS server_ip,
            version() AS version
    """)).mappings().first()
    return dict(result)
