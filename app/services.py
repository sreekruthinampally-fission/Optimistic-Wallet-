from datetime import datetime, timedelta, timezone
from decimal import Decimal
import hashlib
import hmac
import logging
import secrets
from uuid import uuid4

from jose import JWTError, jwt
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import settings
from app.exceptions import (
    InsufficientFundsError,
    InvalidCredentialsError,
    UserAlreadyExistsError,
    UserNotFoundError,
    WalletAlreadyExistsError,
    WalletNotFoundError,
)
from app.models import EntryType, LedgerEntry, User, Wallet

logger = logging.getLogger(__name__)


def hash_password(password: str) -> str:
    """Hash a plaintext password using PBKDF2 with per-password random salt."""
    logger.debug("Hashing password with PBKDF2 iterations=%s", settings.password_hash_iterations)
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        settings.password_hash_iterations,
    )
    return f"pbkdf2_sha256${settings.password_hash_iterations}${salt}${digest.hex()}"


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify plaintext password against stored hash (supports legacy hash format)."""
    try:
        parts = password_hash.split("$")
        if len(parts) == 3:
            # Backward compatibility for legacy hashes: pbkdf2_sha256$salt$hash
            scheme, salt, stored_hash = parts
            iterations = 120_000
        elif len(parts) == 4:
            scheme, iterations_raw, salt, stored_hash = parts
            iterations = int(iterations_raw)
        else:
            logger.warning("Password verification failed due to invalid hash format")
            return False
        if scheme != "pbkdf2_sha256":
            logger.warning("Password verification failed due to unsupported scheme=%s", scheme)
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        ).hex()
        return hmac.compare_digest(digest, stored_hash)
    except Exception:
        logger.exception("Password verification failed due to unexpected error")
        return False


def create_access_token(user_id: str, email: str) -> tuple[str, int]:
    """Create a signed JWT access token and return token with TTL seconds."""
    expires_in = settings.jwt_access_token_expire_minutes * 60
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
    payload = {"sub": user_id, "email": email, "exp": expires_at}
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    logger.info("Issued access token user_id=%s expires_in_seconds=%s", user_id, expires_in)
    return token, expires_in


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        logger.debug("Access token decoded for user_id=%s", payload.get("sub"))
        return payload
    except JWTError:
        logger.info("Access token decode failed")
        raise


class UserService:
    """User-focused business operations."""

    @staticmethod
    def create_user(db: Session, email: str, password: str) -> User:
        """Create a unique user record with a hashed password."""
        normalized_email = email.strip().lower()
        logger.info("User create requested email=%s", normalized_email)
        user = User(id=str(uuid4()), email=normalized_email, password_hash=hash_password(password))
        try:
            existing = db.execute(select(User).where(User.email == normalized_email)).scalar_one_or_none()
            if existing:
                logger.warning("User registration conflict for email=%s", normalized_email)
                raise UserAlreadyExistsError(f"User already exists for email '{normalized_email}'")
            db.add(user)
            db.commit()
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Database error while creating user email=%s", normalized_email)
            raise
        db.refresh(user)
        logger.info("User created id=%s email=%s", user.id, user.email)
        return user

    @staticmethod
    def authenticate_user(db: Session, email: str, password: str) -> User:
        """Authenticate a user by email/password."""
        normalized_email = email.strip().lower()
        logger.info("Authentication requested email=%s", normalized_email)
        user = db.execute(select(User).where(User.email == normalized_email)).scalar_one_or_none()
        if not user or not verify_password(password, user.password_hash):
            logger.warning("Authentication failed for email=%s", normalized_email)
            raise InvalidCredentialsError("Invalid email or password")
        logger.info("Authentication succeeded for user_id=%s", user.id)
        return user

    @staticmethod
    def get_user_by_id(db: Session, user_id: str) -> User:
        """Fetch user by ID or raise domain-level not found error."""
        logger.debug("User lookup requested user_id=%s", user_id)
        try:
            user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Database error while fetching user user_id=%s", user_id)
            raise
        if not user:
            logger.warning("User lookup miss user_id=%s", user_id)
            raise UserNotFoundError(f"User not found for id '{user_id}'")
        logger.debug("User lookup succeeded user_id=%s", user_id)
        return user


class WalletService:
    """Wallet and ledger business operations."""

    @staticmethod
    def _normalize_amount(amount: Decimal) -> Decimal:
        """Normalize monetary value to two decimal places."""
        return amount.quantize(Decimal("0.01"))

    @staticmethod
    def _get_wallet_for_update(db: Session, user_id: str) -> Wallet:
        """Fetch wallet with row-level lock for atomic balance updates."""
        wallet = db.execute(select(Wallet).where(Wallet.user_id == user_id).with_for_update()).scalar_one_or_none()
        if not wallet:
            logger.warning("Wallet operation failed because wallet not found user_id=%s", user_id)
            raise WalletNotFoundError(f"Wallet not found for user '{user_id}'")
        return wallet

    @staticmethod
    def _append_ledger_entry(
        db: Session,
        wallet_id: int,
        entry_type: EntryType,
        amount: Decimal,
        balance_after: Decimal,
        reference: str | None,
    ) -> None:
        """Append immutable ledger entry inside the current transaction."""
        db.add(
            LedgerEntry(
                wallet_id=wallet_id,
                entry_type=entry_type,
                amount=amount,
                balance_after=balance_after,
                reference=reference,
            )
        )

    @staticmethod
    def _commit_and_refresh_wallet(db: Session, wallet: Wallet) -> Wallet:
        """Commit transaction and refresh wallet state from database."""
        db.commit()
        db.refresh(wallet)
        return wallet

    @staticmethod
    def create_wallet(db: Session, user_id: str) -> Wallet:
        """Create wallet for user if one does not already exist."""
        logger.info("Wallet create requested user_id=%s", user_id)
        try:
            user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
            if not user:
                logger.warning("Wallet create failed because user not found user_id=%s", user_id)
                raise UserNotFoundError(f"User not found for id '{user_id}'")

            existing = db.execute(select(Wallet).where(Wallet.user_id == user_id)).scalar_one_or_none()
            if existing:
                logger.warning("Wallet create conflict for user_id=%s", user_id)
                raise WalletAlreadyExistsError(f"Wallet already exists for user '{user_id}'")

            wallet = Wallet(user_id=user_id, balance=Decimal("0.00"))
            db.add(wallet)
            wallet = WalletService._commit_and_refresh_wallet(db, wallet)
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Database error while creating wallet user_id=%s", user_id)
            raise
        logger.info("Wallet created wallet_id=%s user_id=%s", wallet.id, wallet.user_id)
        return wallet

    @staticmethod
    def get_wallet_by_user_id(db: Session, user_id: str) -> Wallet:
        """Fetch wallet by owner user ID or raise domain-level not found error."""
        logger.debug("Wallet lookup requested user_id=%s", user_id)
        try:
            wallet = db.execute(select(Wallet).where(Wallet.user_id == user_id)).scalar_one_or_none()
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Database error while fetching wallet user_id=%s", user_id)
            raise
        if not wallet:
            logger.warning("Wallet lookup miss user_id=%s", user_id)
            raise WalletNotFoundError(f"Wallet not found for user '{user_id}'")
        logger.debug("Wallet lookup succeeded user_id=%s wallet_id=%s", user_id, wallet.id)
        return wallet

    @staticmethod
    def credit(db: Session, user_id: str, amount: Decimal, reference: str | None = None) -> Wallet:
        """Credit wallet balance and append matching ledger record."""
        normalized_amount = WalletService._normalize_amount(amount)
        logger.info("Wallet credit requested user_id=%s amount=%s reference=%s", user_id, normalized_amount, reference)
        try:
            # Row-level lock serializes concurrent updates for the same wallet.
            wallet = WalletService._get_wallet_for_update(db, user_id)

            wallet.balance += normalized_amount
            WalletService._append_ledger_entry(
                db,
                wallet.id,
                EntryType.CREDIT,
                normalized_amount,
                wallet.balance,
                reference,
            )
            wallet = WalletService._commit_and_refresh_wallet(db, wallet)
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Database error while crediting wallet user_id=%s amount=%s", user_id, normalized_amount)
            raise
        logger.info(
            "Wallet credited user_id=%s amount=%s balance=%s reference=%s",
            user_id,
            normalized_amount,
            wallet.balance,
            reference,
        )
        return wallet

    @staticmethod
    def debit(db: Session, user_id: str, amount: Decimal, reference: str | None = None) -> Wallet:
        """Debit wallet balance atomically when sufficient funds are available."""
        normalized_amount = WalletService._normalize_amount(amount)
        logger.info("Wallet debit requested user_id=%s amount=%s reference=%s", user_id, normalized_amount, reference)
        try:
            # Row-level lock serializes concurrent updates for the same wallet.
            wallet = WalletService._get_wallet_for_update(db, user_id)
            if wallet.balance < normalized_amount:
                logger.warning(
                    "Debit rejected for insufficient funds user_id=%s amount=%s current_balance=%s",
                    user_id,
                    normalized_amount,
                    wallet.balance,
                )
                raise InsufficientFundsError("Insufficient funds")

            wallet.balance -= normalized_amount
            WalletService._append_ledger_entry(
                db,
                wallet.id,
                EntryType.DEBIT,
                normalized_amount,
                wallet.balance,
                reference,
            )
            wallet = WalletService._commit_and_refresh_wallet(db, wallet)
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Database error while debiting wallet user_id=%s amount=%s", user_id, normalized_amount)
            raise
        logger.info(
            "Wallet debited user_id=%s amount=%s balance=%s reference=%s",
            user_id,
            normalized_amount,
            wallet.balance,
            reference,
        )
        return wallet

    @staticmethod
    def get_ledger(db: Session, user_id: str, limit: int, offset: int) -> tuple[list[LedgerEntry], int]:
        """Return paginated ledger entries and total row count."""
        logger.info("Wallet ledger requested user_id=%s limit=%s offset=%s", user_id, limit, offset)
        try:
            wallet = WalletService.get_wallet_by_user_id(db, user_id)
            total = db.execute(select(func.count(LedgerEntry.id)).where(LedgerEntry.wallet_id == wallet.id)).scalar_one()
            items = (
                db.execute(
                    select(LedgerEntry)
                    .where(LedgerEntry.wallet_id == wallet.id)
                    .order_by(LedgerEntry.created_at.desc(), LedgerEntry.id.desc())
                    .limit(limit)
                    .offset(offset)
                )
                .scalars()
                .all()
            )
        except SQLAlchemyError:
            db.rollback()
            logger.exception("Database error while fetching ledger user_id=%s", user_id)
            raise
        logger.info(
            "Wallet ledger fetched user_id=%s wallet_id=%s returned_items=%s total_items=%s",
            user_id,
            wallet.id,
            len(items),
            total,
        )
        return items, total
