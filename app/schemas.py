from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models import EntryType


class CreateUserRequest(BaseModel):
    """Base payload for user-identifying requests."""

    email: str = Field(min_length=5, max_length=255, examples=["alice@example.com"])

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        """Apply lightweight email normalization and shape checks."""
        email = value.strip().lower()
        if "@" not in email or email.count("@") != 1:
            raise ValueError("Invalid email format")
        local, domain = email.split("@")
        if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
            raise ValueError("Invalid email format")
        return email


class RegisterRequest(CreateUserRequest):
    """Payload for user registration."""

    password: str = Field(min_length=8, max_length=128, examples=["StrongPass123!"])


class LoginRequest(CreateUserRequest):
    """Payload for user login."""

    password: str = Field(min_length=8, max_length=128, examples=["StrongPass123!"])


class UserResponse(BaseModel):
    """Response model for user records."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    created_at: datetime


class TokenResponse(BaseModel):
    """Bearer token response returned from login."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int


class AmountRequest(BaseModel):
    """Payload for wallet credit/debit operations."""

    amount: Decimal = Field(gt=0, examples=["100.00"])
    reference: str | None = Field(default=None, max_length=128, examples=["salary-credit"])

    @field_validator("amount")
    @classmethod
    def validate_amount_precision(cls, value: Decimal) -> Decimal:
        """Restrict amount precision to two decimal places."""
        if value.as_tuple().exponent < -2:
            raise ValueError("Amount supports at most 2 decimal places")
        return value.quantize(Decimal("0.01"))

    @field_validator("reference")
    @classmethod
    def normalize_reference(cls, value: str | None) -> str | None:
        """Trim optional reference and convert blank strings to null."""
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class WalletResponse(BaseModel):
    """Response model for wallet state."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: str
    balance: Decimal
    created_at: datetime
    updated_at: datetime


class BalanceResponse(BaseModel):
    """Response model for wallet balance endpoint."""

    user_id: str
    balance: Decimal


class LedgerEntryResponse(BaseModel):
    """Response model for one ledger row."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    wallet_id: int
    entry_type: EntryType
    amount: Decimal
    balance_after: Decimal
    reference: str | None
    created_at: datetime


class LedgerListResponse(BaseModel):
    """Paginated list response for wallet ledger endpoint."""

    items: list[LedgerEntryResponse]
    total: int
    limit: int
    offset: int
