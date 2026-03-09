import logging
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError, ResponseValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DisconnectionError, IntegrityError, OperationalError, SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import settings
from app.database import check_db_connection, init_db
from app.routes import router

logging.basicConfig(
    level=getattr(logging, settings.log_level, logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger(__name__)


def build_error_response(
    request: Request,
    *,
    status_code: int,
    detail,
    errors: list[dict] | None = None,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Create a consistent JSON error payload for all exception handlers."""
    request_id = getattr(request.state, "request_id", None)
    content: dict = {
        "detail": jsonable_encoder(detail),
        "request_id": request_id,
        "path": request.url.path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    if errors is not None:
        content["errors"] = errors
    return JSONResponse(status_code=status_code, content=content, headers=headers)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Run startup and shutdown hooks for the application lifecycle."""
    try:
        logger.info(
            "Application startup initiated app_name=%s environment=%s debug=%s auto_init_db=%s",
            settings.app_name,
            settings.environment,
            settings.debug,
            settings.auto_init_db,
        )
        if settings.auto_init_db:
            init_db()
            logger.info("Database schema initialization completed")
        else:
            logger.info("Database schema initialization skipped because AUTO_INIT_DB=false")
        yield
        logger.info("Application shutdown completed")
    except SQLAlchemyError:
        logger.exception("Application startup failed due to database initialization error")
        raise


app = FastAPI(title=settings.app_name, debug=settings.debug, lifespan=lifespan)
app.include_router(router)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Attach request IDs and log every request with execution time."""
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    start = time.perf_counter()
    response = None
    try:
        response = await call_next(request)
        return response
    finally:
        duration_ms = (time.perf_counter() - start) * 1000
        status_code = response.status_code if response is not None else 500
        if response is not None:
            response.headers["X-Request-Id"] = request_id
        # Always log the request, including unhandled failures.
        request_logger = logger.info
        if status_code >= 500:
            request_logger = logger.error
        elif status_code >= 400:
            request_logger = logger.warning
        request_logger(
            "request_id=%s method=%s path=%s status=%s duration_ms=%.2f",
            request_id,
            request.method,
            request.url.path,
            status_code,
            duration_ms,
        )


@app.exception_handler(HTTPException)
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle explicit HTTP errors raised by routes and framework routing."""
    logger.info(
        "HTTP error status=%s path=%s detail=%s request_id=%s",
        exc.status_code,
        request.url.path,
        exc.detail,
        getattr(request.state, "request_id", None),
    )
    return build_error_response(
        request,
        status_code=exc.status_code,
        detail=exc.detail,
        headers=exc.headers,
    )


@app.exception_handler(IntegrityError)
async def integrity_error_handler(request: Request, exc: IntegrityError):
    """Map DB constraint violations to HTTP 409."""
    logger.exception("Database integrity error path=%s", request.url.path)
    return build_error_response(request, status_code=409, detail="Database integrity conflict")


@app.exception_handler(OperationalError)
@app.exception_handler(DisconnectionError)
async def database_unavailable_handler(request: Request, exc: SQLAlchemyError):
    """Map transient database outages to HTTP 503."""
    logger.exception("Database unavailable path=%s", request.url.path)
    return build_error_response(request, status_code=503, detail="Database unavailable")


@app.exception_handler(SQLAlchemyError)
async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError):
    """Handle non-transient database errors as server failures."""
    logger.exception("Database error path=%s", request.url.path)
    return build_error_response(request, status_code=500, detail="Database operation failed")


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return normalized request validation details."""
    errors = jsonable_encoder(exc.errors())
    logger.warning("Request validation error path=%s errors=%s", request.url.path, errors)
    return build_error_response(
        request,
        status_code=422,
        detail="Validation failed",
        errors=errors,
    )


@app.exception_handler(ResponseValidationError)
async def response_validation_exception_handler(request: Request, exc: ResponseValidationError):
    """Catch server-side response schema mismatches."""
    errors = jsonable_encoder(exc.errors())
    logger.exception("Response validation error path=%s errors=%s", request.url.path, errors)
    return build_error_response(request, status_code=500, detail="Response validation failed", errors=errors)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Fallback handler for unexpected exceptions."""
    logger.exception("Unhandled server error path=%s", request.url.path)
    return build_error_response(request, status_code=500, detail="Internal server error")


@app.get("/healthz", tags=["health"])
def healthz():
    """Readiness probe endpoint for orchestration and uptime checks."""
    logger.debug("Health check requested")
    if not check_db_connection():
        raise HTTPException(status_code=503, detail="Database unavailable")
    return {"status": "ok", "environment": settings.environment}
