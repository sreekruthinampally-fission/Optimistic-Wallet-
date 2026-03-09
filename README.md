# Wallet API (Phase 1)

Backend wallet service using Python, FastAPI, and PostgreSQL.

## Features
- Register/login users with JWT auth.
- Create one wallet per user.
- Credit money to wallet.
- Debit money from wallet (never allows negative balance).
- Get wallet balance.
- Get transaction history (ledger with pagination).
- Every credit/debit creates a ledger entry.
- Data persisted in PostgreSQL.
- Wallet APIs require JWT and enforce owner-only access.
- Strict amount validation (positive, max 2 decimal places).
- Transaction-safe balance + ledger updates.
- Request ID + structured request/error logging.

## Tech Stack
- FastAPI
- SQLAlchemy 2.x
- PostgreSQL
- Pytest

## Project Structure
```text
app/
  config.py
  database.py
  models.py
  schemas.py
  services.py
  routes.py
  init_db.py
  main.py
docs/
  ARCHITECTURE.md
tests/
```

## Quick Start (Local)
1. Create PostgreSQL DB and user:
- DB: `wallet_db`
- User: `wallet`
- Password: `wallet`

2. Install deps:
```bash
pip install -r requirements.txt
```

3. Configure env:
```bash
copy .env.example .env
```

4. Initialize database schema:
```bash
python -m app.init_db
```

5. Start server:
```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

6. API docs:
```text
http://localhost:8000/docs
```

## API Endpoints
- `POST /auth/register`
  - Body: `{"email":"alice@example.com","password":"StrongPass123!"}`
- `POST /auth/login`
  - Body: `{"email":"alice@example.com","password":"StrongPass123!"}`
- `POST /wallets`
- `POST /wallets/credit`
  - Body: `{"amount":"100.00","reference":"salary"}`
- `POST /wallets/debit`
  - Body: `{"amount":"10.00","reference":"payment"}`
- `GET /wallets/balance`
- `GET /wallets/ledger?limit=50&offset=0`
- `GET /healthz`

## Example cURL
```bash
curl -X POST http://localhost:8000/auth/register -H "Content-Type: application/json" -d "{\"email\":\"alice@example.com\",\"password\":\"StrongPass123!\"}"
curl -X POST http://localhost:8000/auth/login -H "Content-Type: application/json" -d "{\"email\":\"alice@example.com\",\"password\":\"StrongPass123!\"}"
# Use returned access_token as TOKEN.
curl -X POST http://localhost:8000/wallets -H "Authorization: Bearer {TOKEN}"
curl -X POST http://localhost:8000/wallets/credit -H "Authorization: Bearer {TOKEN}" -H "Content-Type: application/json" -d "{\"amount\":\"100.00\"}"
curl -X POST http://localhost:8000/wallets/debit -H "Authorization: Bearer {TOKEN}" -H "Content-Type: application/json" -d "{\"amount\":\"40.00\"}"
curl http://localhost:8000/wallets/balance -H "Authorization: Bearer {TOKEN}"
curl http://localhost:8000/wallets/ledger -H "Authorization: Bearer {TOKEN}"
```

## Run Tests
Tests expect a reachable PostgreSQL database via `TEST_DATABASE_URL` (or `DATABASE_URL`).
```bash
pytest -q
```

## Config (Environment Variables)
- `APP_NAME`
- `ENVIRONMENT`
- `DEBUG`
- `LOG_LEVEL`
- `AUTO_INIT_DB` (set `false` in production)
- `DATABASE_URL`
- `DB_POOL_SIZE`
- `DB_MAX_OVERFLOW`
- `DB_POOL_TIMEOUT`
- `DB_POOL_RECYCLE`
- `JWT_SECRET_KEY`
- `JWT_ALGORITHM`
- `JWT_ACCESS_TOKEN_EXPIRE_MINUTES`
- `PASSWORD_HASH_ITERATIONS`

## Notes
- Credit/debit are wrapped in DB transactions.
- Wallet row is locked during update (`SELECT ... FOR UPDATE`) to prepare for concurrent safety in next phase.
- `/healthz` verifies database connectivity and returns `503` when DB is unavailable.
