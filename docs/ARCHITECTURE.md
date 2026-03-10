# Architecture

## Layers
- `app/routes.py`: HTTP routing only (request parsing, response mapping, status codes)
- `app/services.py`: business rules and transaction orchestration
- `app/exceptions.py`: domain/business exceptions shared across layers
- `app/models.py`: SQLAlchemy ORM entities
- `app/schemas.py`: Pydantic request/response contracts
- `app/database.py`: SQLAlchemy base/session/engine setup
- `app/config.py`: app configuration and environment settings
- `app/main.py`: startup wiring, middleware, and global exception handlers

## Request Flow
1. Request hits route in `app/routes.py`
2. Route calls service in `app/services.py`
3. Service reads/writes ORM models through SQLAlchemy session
4. Route returns response schema

## Runtime Behavior
- App startup can initialize schema via `AUTO_INIT_DB=true` (recommended for dev/test only).
- Production should use managed migrations and set `AUTO_INIT_DB=false`.
- `/healthz` performs a lightweight DB connectivity check.

## Conventions
- Routes should not contain business logic.
- Services should not return raw dictionaries; return ORM/domain objects.
- Money uses `Decimal` + Postgres `NUMERIC(18,2)`.
- Ledger writes happen in the same transaction as balance updates.
- Wallet balance updates use optimistic concurrency via a version column.
