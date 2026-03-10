from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal

from sqlalchemy.orm import sessionmaker

from app.database import engine
from app.services import InsufficientFundsError, WalletService


def register_user(client, email: str = "user1@example.com", password: str = "StrongPass123!") -> str:
    response = client.post("/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201
    return response.json()["id"]


def login_user(client, email: str = "user1@example.com", password: str = "StrongPass123!") -> str:
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_create_wallet(client):
    user_id = register_user(client)
    token = login_user(client)
    response = client.post("/wallets", headers=auth_headers(token))
    assert response.status_code == 201
    body = response.json()
    assert body["user_id"] == user_id
    assert Decimal(body["balance"]) == Decimal("0.00")


def test_credit_updates_balance_and_ledger(client):
    register_user(client)
    token = login_user(client)
    client.post("/wallets", headers=auth_headers(token))
    credit = client.post(
        "/wallets/credit",
        json={"amount": "50.00", "reference": "salary"},
        headers=auth_headers(token),
    )
    assert credit.status_code == 200
    assert Decimal(credit.json()["balance"]) == Decimal("50.00")

    ledger = client.get("/wallets/ledger", headers=auth_headers(token))
    assert ledger.status_code == 200
    items = ledger.json()["items"]
    assert len(items) == 1
    assert items[0]["entry_type"] == "credit"
    assert Decimal(items[0]["amount"]) == Decimal("50.00")
    assert Decimal(items[0]["balance_after"]) == Decimal("50.00")


def test_debit_success(client):
    register_user(client)
    token = login_user(client)
    client.post("/wallets", headers=auth_headers(token))
    client.post("/wallets/credit", json={"amount": "100.00"}, headers=auth_headers(token))
    debit = client.post("/wallets/debit", json={"amount": "40.00"}, headers=auth_headers(token))
    assert debit.status_code == 200
    assert Decimal(debit.json()["balance"]) == Decimal("60.00")

    balance = client.get("/wallets/balance", headers=auth_headers(token))
    assert balance.status_code == 200
    assert Decimal(balance.json()["balance"]) == Decimal("60.00")


def test_debit_insufficient_funds_has_no_ledger_row(client):
    register_user(client)
    token = login_user(client)
    client.post("/wallets", headers=auth_headers(token))
    client.post("/wallets/credit", json={"amount": "20.00"}, headers=auth_headers(token))
    failed = client.post("/wallets/debit", json={"amount": "50.00"}, headers=auth_headers(token))
    assert failed.status_code == 409

    ledger = client.get("/wallets/ledger", headers=auth_headers(token))
    items = ledger.json()["items"]
    assert len(items) == 1
    assert items[0]["entry_type"] == "credit"


def test_ledger_pagination(client):
    register_user(client)
    token = login_user(client)
    client.post("/wallets", headers=auth_headers(token))
    for value in ["10.00", "20.00", "30.00"]:
        client.post("/wallets/credit", json={"amount": value}, headers=auth_headers(token))

    first_page = client.get("/wallets/ledger?limit=2&offset=0", headers=auth_headers(token))
    second_page = client.get("/wallets/ledger?limit=2&offset=2", headers=auth_headers(token))
    assert first_page.status_code == 200
    assert second_page.status_code == 200
    assert len(first_page.json()["items"]) == 2
    assert len(second_page.json()["items"]) == 1


def test_wallet_operations_fail_if_wallet_not_created(client):
    register_user(client, "owner@example.com")
    token = login_user(client, "owner@example.com")
    response = client.post("/wallets/credit", json={"amount": "10.00"}, headers=auth_headers(token))
    assert response.status_code == 404


def test_wallet_apis_require_jwt(client):
    user_id = register_user(client, "auth-required@example.com")
    assert user_id
    response = client.post("/wallets")
    assert response.status_code == 401


def test_wallet_access_is_scoped_to_token_owner(client):
    register_user(client, "owner2@example.com")
    register_user(client, "attacker@example.com")
    owner_token = login_user(client, "owner2@example.com")
    attacker_token = login_user(client, "attacker@example.com")

    create_wallet_resp = client.post("/wallets", headers=auth_headers(owner_token))
    assert create_wallet_resp.status_code == 201
    client.post("/wallets/credit", json={"amount": "50.00"}, headers=auth_headers(owner_token))

    attacker_balance = client.get("/wallets/balance", headers=auth_headers(attacker_token))
    assert attacker_balance.status_code == 404
    owner_balance = client.get("/wallets/balance", headers=auth_headers(owner_token))
    assert owner_balance.status_code == 200
    assert Decimal(owner_balance.json()["balance"]) == Decimal("50.00")


def test_login_fails_for_invalid_password(client):
    register_user(client, "login-fail@example.com", "StrongPass123!")
    response = client.post("/auth/login", json={"email": "login-fail@example.com", "password": "WrongPass123!"})
    assert response.status_code == 401


def test_register_duplicate_email_returns_conflict(client):
    register_user(client, "dup@example.com", "StrongPass123!")
    response = client.post("/auth/register", json={"email": "dup@example.com", "password": "StrongPass123!"})
    assert response.status_code == 409


def test_credit_rejects_more_than_two_decimal_places(client):
    register_user(client, "precision@example.com")
    token = login_user(client, "precision@example.com")
    client.post("/wallets", headers=auth_headers(token))
    response = client.post("/wallets/credit", json={"amount": "10.999"}, headers=auth_headers(token))
    assert response.status_code == 422


def test_wallet_routes_no_longer_accept_user_id_path(client):
    register_user(client, "uuid@example.com")
    token = login_user(client, "uuid@example.com")
    response = client.post("/wallets/not-a-uuid", headers=auth_headers(token))
    assert response.status_code == 404


def test_not_found_error_includes_request_metadata(client):
    response = client.get("/route-that-does-not-exist")
    assert response.status_code == 404
    body = response.json()
    assert body["path"] == "/route-that-does-not-exist"
    assert isinstance(body["request_id"], str) and body["request_id"]
    assert isinstance(body["timestamp"], str) and body["timestamp"]
    assert response.headers["X-Request-Id"] == body["request_id"]


def test_validation_error_includes_errors_and_request_metadata(client):
    response = client.post("/auth/register", json={"email": "bad-email", "password": "StrongPass123!"})
    assert response.status_code == 422
    body = response.json()
    assert body["detail"] == "Validation failed"
    assert isinstance(body["errors"], list) and body["errors"]
    assert body["path"] == "/auth/register"
    assert isinstance(body["request_id"], str) and body["request_id"]


def test_invalid_auth_scheme_is_rejected(client):
    response = client.post("/wallets", headers={"Authorization": "Basic abc123"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid authorization scheme"


def test_concurrent_debits_are_consistent(client):
    user_id = register_user(client, "concurrency@example.com")
    token = login_user(client, "concurrency@example.com")
    create_wallet_response = client.post("/wallets", headers=auth_headers(token))
    assert create_wallet_response.status_code == 201
    seed_credit = client.post(
        "/wallets/credit",
        json={"amount": "100.00"},
        headers=auth_headers(token),
    )
    assert seed_credit.status_code == 200

    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)

    def debit_once() -> tuple[bool, str | None]:
        db = SessionLocal()
        try:
            WalletService.debit(db, user_id, Decimal("10.00"))
            return True, None
        except InsufficientFundsError:
            db.rollback()
            return False, "Insufficient balance"
        finally:
            db.close()

    results = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(debit_once) for _ in range(50)]
        for future in as_completed(futures):
            results.append(future.result())

    successful_debits = sum(1 for success, _ in results if success)
    failed_debits = sum(1 for success, _ in results if not success)
    assert successful_debits == 10
    assert failed_debits == 40

    balance_response = client.get("/wallets/balance", headers=auth_headers(token))
    assert balance_response.status_code == 200
    assert Decimal(balance_response.json()["balance"]) == Decimal("0.00")

    ledger_response = client.get("/wallets/ledger?limit=200&offset=0", headers=auth_headers(token))
    assert ledger_response.status_code == 200
    items = ledger_response.json()["items"]

    credit_entries = [entry for entry in items if entry["entry_type"] == "credit"]
    debit_entries = [entry for entry in items if entry["entry_type"] == "debit"]
    assert len(credit_entries) == 1
    assert len(debit_entries) == 10

    failure_reasons: dict[str, int] = {}
    for success, reason in results:
        if not success and reason:
            failure_reasons[reason] = failure_reasons.get(reason, 0) + 1

    final_balance = Decimal(balance_response.json()["balance"]).quantize(Decimal("0.00"))
    print("CONCURRENCY_CHECK: PASS")
    print(
        "successes="
        f"{successful_debits} failures={failed_debits} final_balance={final_balance} "
        f"debit_ledger_entries={len(debit_entries)} failure_reasons={failure_reasons}"
    )
