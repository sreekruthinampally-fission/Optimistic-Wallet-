class UserAlreadyExistsError(Exception):
    """Raised when trying to create a user with an existing email."""

    pass


class UserNotFoundError(Exception):
    """Raised when requested user does not exist."""

    pass


class WalletAlreadyExistsError(Exception):
    """Raised when a user already has a wallet."""

    pass


class WalletNotFoundError(Exception):
    """Raised when wallet lookup fails for a user."""

    pass


class InsufficientFundsError(Exception):
    """Raised when debit amount exceeds wallet balance."""

    pass


class InvalidCredentialsError(Exception):
    """Raised when login credentials are invalid."""

    pass


class ConcurrencyConflictError(Exception):
    """Raised when optimistic concurrency retries are exhausted."""

    pass
