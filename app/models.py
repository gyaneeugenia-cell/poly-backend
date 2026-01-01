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
from datetime import datetime
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

    equation: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    coeffs_csv: Mapped[str] = mapped_column(
        Text, nullable=False
    )
    roots_json: Mapped[str] = mapped_column(
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
