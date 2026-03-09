import pytest
from pydantic import ValidationError

from app.config import Settings


def test_auto_init_db_must_be_disabled_in_production(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("DEBUG", "false")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("AUTO_INIT_DB", "true")

    with pytest.raises(ValidationError) as exc:
        Settings()

    assert "AUTO_INIT_DB must be false in production" in str(exc.value)


def test_log_level_must_be_valid(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LOG_LEVEL", "NOT_A_LEVEL")

    with pytest.raises(ValidationError) as exc:
        Settings()

    assert "LOG_LEVEL 'NOT_A_LEVEL' is not valid" in str(exc.value)
