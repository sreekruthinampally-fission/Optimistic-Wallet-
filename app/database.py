import logging

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""

    pass


engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_timeout=settings.db_pool_timeout,
    pool_recycle=settings.db_pool_recycle,
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def _ensure_users_password_hash_column() -> None:
    """Backfill legacy `users.password_hash` column when running against older schemas."""
    inspector = inspect(engine)
    if "users" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("users")}
    if "password_hash" in columns:
        return

    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE users ADD COLUMN password_hash VARCHAR(255) NOT NULL DEFAULT ''"))


def _ensure_wallets_version_column() -> None:
    """Backfill `wallets.version` column for optimistic concurrency control."""
    inspector = inspect(engine)
    if "wallets" not in inspector.get_table_names():
        return

    columns = {column["name"] for column in inspector.get_columns("wallets")}
    if "version" in columns:
        return

    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE wallets ADD COLUMN version INTEGER NOT NULL DEFAULT 0"))


def _apply_postgres_constraints_and_indexes() -> None:
    """Apply idempotent hardening DDL for constraints and query-performance indexes."""
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM pg_constraint
                        WHERE conname = 'ck_wallets_balance_non_negative'
                    ) THEN
                        ALTER TABLE wallets
                        ADD CONSTRAINT ck_wallets_balance_non_negative CHECK (balance >= 0);
                    END IF;
                END $$;
                """
            )
        )
        connection.execute(
            text(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM pg_constraint
                        WHERE conname = 'ck_ledger_entries_amount_positive'
                    ) THEN
                        ALTER TABLE ledger_entries
                        ADD CONSTRAINT ck_ledger_entries_amount_positive CHECK (amount > 0);
                    END IF;
                END $$;
                """
            )
        )
        connection.execute(
            text(
                """
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM pg_constraint
                        WHERE conname = 'ck_ledger_entries_balance_after_non_negative'
                    ) THEN
                        ALTER TABLE ledger_entries
                        ADD CONSTRAINT ck_ledger_entries_balance_after_non_negative CHECK (balance_after >= 0);
                    END IF;
                END $$;
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE INDEX IF NOT EXISTS ix_ledger_entries_wallet_id_created_at
                ON ledger_entries(wallet_id, created_at DESC, id DESC);
                """
            )
        )


def get_db() -> Session:
    """Yield a request-scoped database session with automatic rollback/close."""
    db = SessionLocal()
    logger.debug("Database session opened")
    try:
        yield db
    except Exception:
        logger.exception("Database session rollback triggered due to request failure")
        db.rollback()
        raise
    finally:
        db.close()
        logger.debug("Database session closed")


def init_db() -> None:
    """Create tables and apply safety constraints/indexes for existing databases."""
    logger.info("Starting database schema initialization")
    try:
        # Import models before create_all so metadata is fully registered.
        from app import models  # noqa: F401

        Base.metadata.create_all(bind=engine)
        _ensure_users_password_hash_column()
        _ensure_wallets_version_column()
        _apply_postgres_constraints_and_indexes()
        logger.info("Database schema initialization finished")
    except SQLAlchemyError:
        logger.exception("Database initialization failed")
        raise


def check_db_connection() -> bool:
    """Return True when database responds to a lightweight probe query."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError:
        logger.exception("Database connectivity check failed")
        return False
