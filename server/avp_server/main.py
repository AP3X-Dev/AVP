from __future__ import annotations

import logging
import os
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from .config import settings
from .db import run_migrations
from .crypto import validate_key_provider, is_using_ephemeral_key, KeyProviderError
from .routes.control import router as control_router
from .routes.avp import router as avp_router
from .error_utils import generate_correlation_id, avp_error_response

logger = logging.getLogger(__name__)


# Aliases for internal use
_generate_correlation_id = generate_correlation_id
_avp_error_response = avp_error_response

app = FastAPI(title="AVP Server", version="1.0.0")

app.include_router(control_router)
app.include_router(avp_router)


@app.on_event("startup")
def _startup():
    # Validate encryption key configuration FIRST
    # This will raise KeyProviderError if invalid, preventing startup
    try:
        validate_key_provider()
    except KeyProviderError as e:
        logger.critical(f"AVP startup failed: {e}")
        raise SystemExit(f"AVP startup failed: {e}")

    # Log warning if using ephemeral key
    if is_using_ephemeral_key():
        logger.warning(
            "AVP is running with EPHEMERAL encryption key. "
            "All secrets will be LOST when the server restarts. "
            "This is only acceptable for development."
        )

    # Run database migrations
    run_migrations()

    # Log startup info
    mode = "DEVELOPMENT" if settings.dev_mode else "PRODUCTION"
    logger.info(f"AVP Server starting in {mode} mode")


@app.get("/healthz")
def healthz():
    return {"ok": True}


_DASHBOARD_PATH = os.path.join(os.path.dirname(__file__), "static", "dashboard.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard():
    """Vault console: sessions, audit trail, secrets, agents, tokens.

    Static single-file UI; authenticates client-side with the principal token
    against the same-origin control API, so no CORS and no server session.
    """
    with open(_DASHBOARD_PATH, encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Handle HTTP exceptions with AVP error envelope format."""
    # If detail is already an AVP error dict, add correlation_id and return
    if isinstance(exc.detail, dict) and exc.detail.get("type") == "error" and exc.detail.get("avp_version") == "1.0":
        # Add correlation_id if not present
        if "correlation_id" not in exc.detail.get("details", {}):
            correlation_id = _generate_correlation_id()
            exc.detail.setdefault("details", {})["correlation_id"] = correlation_id
        return JSONResponse(status_code=exc.status_code, content=exc.detail)

    # Convert non-AVP errors to AVP format
    correlation_id = _generate_correlation_id()
    return JSONResponse(
        status_code=exc.status_code,
        content=_avp_error_response(
            code="http_error",
            message=str(exc.detail) if isinstance(exc.detail, str) else "request failed",
            correlation_id=correlation_id
        )
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle validation errors with AVP error envelope format."""
    correlation_id = _generate_correlation_id()
    # In production, simplify error details to avoid leaking internal info
    if settings.dev_mode:
        details = {"errors": exc.errors(), "correlation_id": correlation_id}
    else:
        # Simplified errors for production - just field names and error types
        simplified_errors = [
            {"field": ".".join(str(loc) for loc in e.get("loc", [])), "type": e.get("type", "unknown")}
            for e in exc.errors()
        ]
        details = {"errors": simplified_errors, "correlation_id": correlation_id}

    return JSONResponse(
        status_code=422,
        content=_avp_error_response(
            code="validation_error",
            message="request validation failed",
            details=details
        )
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions with AVP error envelope format.

    Logs full exception server-side but only returns correlation_id to client.
    In dev mode, includes exception message for debugging.
    """
    correlation_id = _generate_correlation_id()

    # Log the full exception server-side for debugging
    logger.exception(f"Unhandled exception [correlation_id={correlation_id}]: {exc}")

    # In dev mode, include exception message for easier debugging
    if settings.dev_mode:
        details = {"correlation_id": correlation_id, "exception": str(exc)}
        message = f"internal error: {type(exc).__name__}"
    else:
        details = {"correlation_id": correlation_id}
        message = "internal error"

    return JSONResponse(
        status_code=500,
        content=_avp_error_response(
            code="internal_error",
            message=message,
            details=details
        )
    )


if __name__ == "__main__":
    uvicorn.run("server.avp_server.main:app", host=settings.host, port=settings.port, reload=False)
