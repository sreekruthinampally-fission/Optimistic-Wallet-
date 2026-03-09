from datetime import datetime
from decimal import Decimal
from enum import Enum

from sqlalchemy import CheckConstraint, DateTime, Enum as SqlEnum, ForeignKey, Numeric, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    """Application user with one-to-one wallet relationship."""

    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    wallet = relationship("Wallet", back_populates="user", uselist=False)


class Wallet(Base):
    """Wallet owned by a single user, with running balance."""

    __tablename__ = "wallets"
    __table_args__ = (
        CheckConstraint("balance >= 0", name="ck_wallets_balance_non_negative"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    balance: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False, default=Decimal("0.00"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    ledger_entries = relationship("LedgerEntry", back_populates="wallet", cascade="all,delete-orphan")
    user = relationship("User", back_populates="wallet")


class EntryType(str, Enum):
    """Allowed ledger entry directions."""

    CREDIT = "credit"
    DEBIT = "debit"


class LedgerEntry(Base):
    """Immutable transaction record for wallet credit/debit operations."""

    __tablename__ = "ledger_entries"
    __table_args__ = (
        CheckConstraint("amount > 0", name="ck_ledger_entries_amount_positive"),
        CheckConstraint("balance_after >= 0", name="ck_ledger_entries_balance_after_non_negative"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    wallet_id: Mapped[int] = mapped_column(ForeignKey("wallets.id", ondelete="CASCADE"), nullable=False, index=True)
    entry_type: Mapped[EntryType] = mapped_column(
        SqlEnum(
            EntryType,
            name="entry_type",
            values_callable=lambda enum_cls: [item.value for item in enum_cls],
            validate_strings=True,
        ),
        nullable=False,
    )
    amount: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False)
    balance_after: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False)
    reference: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    wallet = relationship("Wallet", back_populates="ledger_entries")
