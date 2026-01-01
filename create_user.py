from app.db import SessionLocal
from app.models import User
from app.security import hash_password

def create_user(username, password, role="user"):
    db = SessionLocal()

    existing = db.query(User).filter(User.username == username).first()
    if existing:
        print(f"User '{username}' already exists")
        db.close()
        return

    user = User(
        username=username,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
    )

    db.add(user)
    db.commit()
    db.close()

    print(f"User '{username}' created successfully with role '{role}'")


if __name__ == "__main__":
    # CHANGE THESE VALUES ONLY
    create_user(
        username="Clement",
        password="asdf1234",
        role="user",   # change to "user" if needed
    )
