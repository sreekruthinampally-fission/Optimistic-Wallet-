import json
import logging

audit_logger = logging.getLogger("audit")


def log_event(logger: logging.Logger, level: str, event: str, **fields) -> None:
    """Emit a structured log line with stable event + key/value pairs."""
    payload = " ".join(f"{key}={json.dumps(value, default=str)}" for key, value in fields.items())
    message = f"event={event}" if not payload else f"event={event} {payload}"
    log_fn = getattr(logger, level, logger.info)
    log_fn(message)
