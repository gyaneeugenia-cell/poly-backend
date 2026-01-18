import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

Base = declarative_base()

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set")

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)

from sqlalchemy import text   # add this import at the top


def get_db():
    db = SessionLocal()

    # 🔍 TEMP DEBUG: identify which database FastAPI is using
    result = db.execute(
        text("select current_database(), inet_server_addr(), inet_server_port();")
    ).fetchone()
    print("FASTAPI DB CHECK:", result)

    try:
        yield db
    finally:
        db.close()
