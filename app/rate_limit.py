from __future__ import annotations

import threading
import time
from dataclasses import dataclass

from app.config import settings


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_after_seconds: float


class RateLimiter:
    """In-memory fixed-window rate limiter (process-local only)."""

    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self._max_attempts = max_attempts
        self._window_seconds = float(window_seconds)
        self._lock = threading.Lock()
        self._buckets: dict[str, tuple[int, float]] = {}

    def allow(self, key: str) -> RateLimitResult:
        now = time.monotonic()
        with self._lock:
            count, reset_at = self._buckets.get(key, (0, now + self._window_seconds))
            if now >= reset_at:
                count = 0
                reset_at = now + self._window_seconds
            if count >= self._max_attempts:
                return RateLimitResult(False, 0, max(0.0, reset_at - now))
            count += 1
            self._buckets[key] = (count, reset_at)
            remaining = max(0, self._max_attempts - count)
            return RateLimitResult(True, remaining, max(0.0, reset_at - now))


auth_rate_limiter = RateLimiter(
    max_attempts=settings.auth_rate_limit_max_attempts,
    window_seconds=settings.auth_rate_limit_window_seconds,
)
