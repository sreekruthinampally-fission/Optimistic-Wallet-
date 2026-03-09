import logging
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.database import get_db
from app.exceptions import (
    InsufficientFundsError,
    InvalidCredentialsError,
    UserAlreadyExistsError,
    UserNotFoundError,
    WalletAlreadyExistsError,
    WalletNotFoundError,
)
from app.models import User
from app.schemas import (
    AmountRequest,
    BalanceResponse,
    LedgerListResponse,
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    WalletResponse,
)
from app.services import UserService, WalletService, create_access_token, decode_access_token

router = APIRouter()
# `auto_error=False` lets us control 401 payload shape/logging ourselves.
security = HTTPBearer(auto_error=False)
logger = logging.getLogger(__name__)
AUTH_RESPONSES = {
    401: {"description": "Unauthorized"},
}


def _request_id(request: Request) -> str | None:
    """Extract request ID injected by middleware, if available."""
    return getattr(request.state, "request_id", None)


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    """Resolve authenticated user from JWT bearer token."""
    request_id = _request_id(request)
    if credentials is None:
        raw_auth = request.headers.get("Authorization", "")
        if raw_auth:
            logger.info("Rejected request with unsupported authorization scheme request_id=%s", request_id)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization scheme")
        logger.info("Rejected request without authorization token request_id=%s", request_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing authorization token")
    if credentials.scheme.lower() != "bearer" or not credentials.credentials:
        logger.info("Rejected request with unsupported or empty authorization scheme request_id=%s", request_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authorization scheme")
    try:
        payload = decode_access_token(credentials.credentials)
    except JWTError as exc:
        logger.info("Rejected request with invalid/expired JWT request_id=%s", request_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from exc

    user_id = payload.get("sub")
    if not user_id:
        logger.info("Rejected request with JWT missing sub claim request_id=%s", request_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    try:
        logger.debug("Resolving current user from token user_id=%s request_id=%s", user_id, request_id)
        return UserService.get_user_by_id(db, user_id)
    except UserNotFoundError as exc:
        logger.info("Rejected request for deleted user_id=%s request_id=%s", user_id, request_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User from token no longer exists") from exc


CurrentUser = Annotated[User, Depends(get_current_user)]
DbSession = Annotated[Session, Depends(get_db)]


@router.post(
    "/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["auth"],
    responses={409: {"description": "Conflict"}},
)
def register(payload: RegisterRequest, db: DbSession) -> UserResponse:
    """Register a new user account."""
    normalized_email = payload.email.strip().lower()
    logger.info("Register request received email=%s", normalized_email)
    try:
        user = UserService.create_user(db, payload.email, payload.password)
        logger.info("Register request succeeded user_id=%s email=%s", user.id, user.email)
        return user
    except UserAlreadyExistsError as exc:
        logger.warning("Register conflict for email=%s", normalized_email)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post(
    "/auth/login",
    response_model=TokenResponse,
    tags=["auth"],
    responses={401: {"description": "Unauthorized"}},
)
def login(payload: LoginRequest, db: DbSession) -> TokenResponse:
    """Authenticate a user and issue a bearer token."""
    normalized_email = payload.email.strip().lower()
    logger.info("Login request received email=%s", normalized_email)
    try:
        user = UserService.authenticate_user(db, payload.email, payload.password)
        token, expires_in = create_access_token(user.id, user.email)
        logger.info("Login request succeeded user_id=%s expires_in_seconds=%s", user.id, expires_in)
        return TokenResponse(access_token=token, expires_in=expires_in)
    except InvalidCredentialsError as exc:
        logger.warning("Invalid login attempt for email=%s", normalized_email)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc


@router.post(
    "/wallets",
    response_model=WalletResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["wallets"],
    responses={**AUTH_RESPONSES, 404: {"description": "Not Found"}, 409: {"description": "Conflict"}},
)
def create_wallet(
    request: Request,
    current_user: CurrentUser,
    db: DbSession,
) -> WalletResponse:
    """Create one wallet for the authenticated user."""
    request_id = _request_id(request)
    logger.info("Create wallet request received user_id=%s request_id=%s", current_user.id, request_id)
    try:
        wallet = WalletService.create_wallet(db, current_user.id)
        logger.info("Create wallet request succeeded user_id=%s wallet_id=%s request_id=%s", current_user.id, wallet.id, request_id)
        return wallet
    except UserNotFoundError as exc:
        logger.warning("Create wallet failed user missing user_id=%s request_id=%s", current_user.id, request_id)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except WalletAlreadyExistsError as exc:
        logger.warning("Wallet create conflict for user_id=%s request_id=%s", current_user.id, request_id)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post(
    "/wallets/credit",
    response_model=WalletResponse,
    tags=["wallets"],
    responses={**AUTH_RESPONSES, 404: {"description": "Not Found"}, 422: {"description": "Validation failed"}},
)
def credit_wallet(
    request: Request,
    current_user: CurrentUser,
    db: DbSession,
    payload: AmountRequest = Body(...),
) -> WalletResponse:
    """Credit authenticated user's wallet and append a ledger entry."""
    request_id = _request_id(request)
    logger.info(
        "Credit request received user_id=%s amount=%s reference=%s request_id=%s",
        current_user.id,
        payload.amount,
        payload.reference,
        request_id,
    )
    try:
        wallet = WalletService.credit(db, current_user.id, payload.amount, payload.reference)
        logger.info(
            "Credit request succeeded user_id=%s balance=%s request_id=%s",
            current_user.id,
            wallet.balance,
            request_id,
        )
        return wallet
    except WalletNotFoundError as exc:
        logger.warning("Credit attempted without wallet user_id=%s request_id=%s", current_user.id, request_id)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post(
    "/wallets/debit",
    response_model=WalletResponse,
    tags=["wallets"],
    responses={
        **AUTH_RESPONSES,
        404: {"description": "Not Found"},
        409: {"description": "Conflict"},
        422: {"description": "Validation failed"},
    },
)
def debit_wallet(
    request: Request,
    current_user: CurrentUser,
    db: DbSession,
    payload: AmountRequest = Body(...),
) -> WalletResponse:
    """Debit authenticated user's wallet if sufficient balance exists."""
    request_id = _request_id(request)
    logger.info(
        "Debit request received user_id=%s amount=%s reference=%s request_id=%s",
        current_user.id,
        payload.amount,
        payload.reference,
        request_id,
    )
    try:
        wallet = WalletService.debit(db, current_user.id, payload.amount, payload.reference)
        logger.info(
            "Debit request succeeded user_id=%s balance=%s request_id=%s",
            current_user.id,
            wallet.balance,
            request_id,
        )
        return wallet
    except WalletNotFoundError as exc:
        logger.warning("Debit attempted without wallet user_id=%s request_id=%s", current_user.id, request_id)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InsufficientFundsError as exc:
        logger.warning(
            "Debit rejected for insufficient funds user_id=%s amount=%s request_id=%s",
            current_user.id,
            payload.amount,
            request_id,
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.get(
    "/wallets/balance",
    response_model=BalanceResponse,
    tags=["wallets"],
    responses={**AUTH_RESPONSES, 404: {"description": "Not Found"}},
)
def get_wallet_balance(
    request: Request,
    current_user: CurrentUser,
    db: DbSession,
) -> BalanceResponse:
    """Return current balance for the authenticated user's wallet."""
    request_id = _request_id(request)
    logger.debug("Balance request received user_id=%s request_id=%s", current_user.id, request_id)
    try:
        wallet = WalletService.get_wallet_by_user_id(db, current_user.id)
        logger.debug("Balance request succeeded user_id=%s balance=%s request_id=%s", current_user.id, wallet.balance, request_id)
        return BalanceResponse(user_id=wallet.user_id, balance=wallet.balance)
    except WalletNotFoundError as exc:
        logger.warning("Balance request failed wallet missing user_id=%s request_id=%s", current_user.id, request_id)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get(
    "/wallets/ledger",
    response_model=LedgerListResponse,
    tags=["wallets"],
    responses={**AUTH_RESPONSES, 404: {"description": "Not Found"}, 422: {"description": "Validation failed"}},
)
def get_wallet_ledger(
    request: Request,
    current_user: CurrentUser,
    db: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> LedgerListResponse:
    """Return paginated ledger entries for the authenticated user's wallet."""
    request_id = _request_id(request)
    logger.debug(
        "Ledger request received user_id=%s limit=%s offset=%s request_id=%s",
        current_user.id,
        limit,
        offset,
        request_id,
    )
    try:
        items, total = WalletService.get_ledger(db, user_id=current_user.id, limit=limit, offset=offset)
        logger.debug(
            "Ledger request succeeded user_id=%s returned_items=%s total=%s request_id=%s",
            current_user.id,
            len(items),
            total,
            request_id,
        )
        return LedgerListResponse(items=items, total=total, limit=limit, offset=offset)
    except WalletNotFoundError as exc:
        logger.warning("Ledger request failed wallet missing user_id=%s request_id=%s", current_user.id, request_id)
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
