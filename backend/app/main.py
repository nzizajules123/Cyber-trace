import logging

from fastapi import Depends, FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError, OperationalError, SQLAlchemyError
from sqlalchemy import text
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1.api import api_router
from app.core.config import get_settings
from app.db.session import get_db

logger = logging.getLogger(__name__)

app = FastAPI(
    title="CyberTrace API",
    description="Defensive digital forensics and cyber investigation platform.",
    version="0.1.0",
)

cors_origins = get_settings().cors_origin_list
if cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

app.include_router(api_router, prefix="/api/v1")


@app.exception_handler(StarletteHTTPException)
async def handle_http_error(_, exc: StarletteHTTPException) -> JSONResponse:
    if exc.status_code == 404:
        code = "not_found"
    elif exc.status_code == 503:
        code = "service_unavailable"
    else:
        code = "http_error"
    message = exc.detail if isinstance(exc.detail, str) else "The request could not be completed."
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": code, "message": message}},
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def handle_validation_error(_, exc: RequestValidationError) -> JSONResponse:
    details = [
        {
            "location": [str(part) for part in error["loc"]],
            "message": error["msg"],
            "type": error["type"],
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "validation_error",
                "message": "Request validation failed.",
                "details": details,
            }
        },
    )


@app.exception_handler(IntegrityError)
async def handle_database_conflict(_, exc: IntegrityError) -> JSONResponse:
    logger.info("Database constraint rejected a request: %s", exc.orig)
    return JSONResponse(
        status_code=409,
        content={
            "error": {
                "code": "database_conflict",
                "message": "The request conflicts with an existing database record.",
            }
        },
    )


@app.exception_handler(OperationalError)
async def handle_database_unavailable(_, exc: OperationalError) -> JSONResponse:
    logger.error("Database operation failed: %s", exc.orig)
    return JSONResponse(
        status_code=503,
        content={
            "error": {
                "code": "database_unavailable",
                "message": "The case database is currently unavailable.",
            }
        },
    )


@app.exception_handler(SQLAlchemyError)
async def handle_database_error(_, exc: SQLAlchemyError) -> JSONResponse:
    logger.exception("Database request failed", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "database_error",
                "message": "The database request could not be completed.",
            }
        },
    )


@app.get("/health", tags=["health"])
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready", tags=["health"])
def readiness_check(db: Session = Depends(get_db)) -> dict[str, str]:
    db.execute(text("SELECT 1"))
    return {"status": "ready", "database": "connected"}
