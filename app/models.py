from sqlalchemy import (
    String,
    DateTime,
    ForeignKey,
    Text,
    Integer,
    Float,
    Boolean,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime, timedelta

from .db import Base


def utcnow():
    return datetime.utcnow()


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )

    username: Mapped[str] = mapped_column(
        String(80), unique=True, index=True, nullable=False
    )

    # ✅ NEW: email for recovery and identity
    email: Mapped[str | None] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=True,
    )

    password_hash: Mapped[str] = mapped_column(
        String(255), nullable=False
    )

    role: Mapped[str] = mapped_column(
        String(20), nullable=False, default="user"
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )

    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=utcnow,
    )

    password_expires_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=lambda: utcnow() + timedelta(days=90),
    )

    # ✅ NEW: password recovery fields
    reset_token: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    reset_token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    history: Mapped[list["HistoryItem"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan"
    )


class HistoryItem(Base):
    __tablename__ = "history"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, autoincrement=True
    )

    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False
    )

    polynomial: Mapped[str] = mapped_column(
        Text, nullable=False
    )

    roots: Mapped[str] = mapped_column(
        Text, nullable=False
    )

    coeffs_csv: Mapped[str] = mapped_column(
        Text, nullable=False
    )

    x_min: Mapped[float] = mapped_column(
        Float, nullable=False, default=-10.0
    )

    x_max: Mapped[float] = mapped_column(
        Float, nullable=False, default=10.0
    )

    y_min: Mapped[float] = mapped_column(
        Float, nullable=False, default=-10.0
    )

    y_max: Mapped[float] = mapped_column(
        Float, nullable=False, default=10.0
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=utcnow, nullable=False
    )

    user: Mapped[User] = relationship(
        back_populates="history"
    )
