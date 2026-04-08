"""
Cloud Compliance Platform — FastAPI Application Entry Point
Implements security middleware, CORS, rate limiting, and all routers.
"""

import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import structlog
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator

from app.api import alerts, audit_logs, cloud_accounts, compliance, dspm, orgs, reports, scans, terraform, threat_intel, users, violations, workflows
from app.auth.router import router as auth_router
from app.config import get_settings
from app.models.database import init_db
from app.models import user, compliance as compliance_models, org, audit_log, violations as violations_models, dspm as dspm_models  # noqa: F401 — registers models
from app.models import score as score_models, workflow as workflow_models  # noqa: F401 — registers models
from app.core.seeder import seed_default_users
from app.core.violations_engine import seed_violation_rules, run_violations_engine
from app.core.dspm_engine import run_dspm_engine
from app.core.correlator import run_correlator
from app.ws.router import router as ws_router
from app.utils.logger import configure_logging

settings = get_settings()
logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application startup and shutdown lifecycle."""
    configure_logging(settings.log_level, settings.log_format)
    logger.info("Starting Cloud Compliance Platform", env=settings.app_env)
    await init_db()
    logger.info("Database initialized")
    # Seed default users (idempotent — skips if already exist)
    from app.models.database import AsyncSessionLocal
    async with AsyncSessionLocal() as db:
        async with db.begin():
            await seed_default_users(db)
    logger.info("Default users seeded")
    # Seed and run violations engine + DSPM engine + correlator
    async with AsyncSessionLocal() as db:
        async with db.begin():
            await seed_violation_rules(db)
            await run_violations_engine(db)
            await run_dspm_engine(db)
            await run_correlator(db)
    logger.info("Violations + DSPM engines initialised")

    # Start WebSocket Redis listener as background task
    import asyncio
    ws_listener_task = None
    try:
        from app.ws.connection_manager import start_redis_listener
        ws_listener_task = asyncio.create_task(
            start_redis_listener(settings.redis_url)
        )
        logger.info("WebSocket Redis listener started")
    except Exception as e:
        logger.warning("WebSocket Redis listener not started", error=str(e))

    yield

    if ws_listener_task:
        ws_listener_task.cancel()
    logger.info("Shutting down Cloud Compliance Platform")


app = FastAPI(
    title="Cloud Compliance Platform",
    description="Multi-cloud compliance monitoring: PCI-DSS, HIPAA, GDPR, SOC 2",
    version="1.0.0",
    docs_url="/api/docs" if settings.app_env != "production" else None,
    redoc_url="/api/redoc" if settings.app_env != "production" else None,
    openapi_url="/api/openapi.json" if settings.app_env != "production" else None,
    lifespan=lifespan,
)

# ---- Middleware ----

# CORS — restrict to allowed origins only
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# GZip compression
app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next) -> Response:
    """Add security headers and request timing to every response."""
    start = time.perf_counter()
    response: Response = await call_next(request)
    duration = time.perf_counter() - start

    # Security headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Process-Time"] = str(round(duration * 1000, 2))

    return response


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next) -> Response:
    """Structured request logging."""
    request_id = request.headers.get("X-Request-ID", "")
    log = logger.bind(
        request_id=request_id,
        method=request.method,
        path=request.url.path,
        client_ip=request.client.host if request.client else "unknown",
    )
    log.info("Request received")
    response = await call_next(request)
    log.info("Request completed", status_code=response.status_code)
    return response


# ---- Prometheus metrics ----
Instrumentator().instrument(app).expose(app, endpoint="/metrics")

# ---- Routers ----
API_PREFIX = "/api/v1"

app.include_router(auth_router, prefix=f"{API_PREFIX}/auth", tags=["Authentication"])
app.include_router(compliance.router, prefix=f"{API_PREFIX}/compliance", tags=["Compliance"])
app.include_router(scans.router, prefix=f"{API_PREFIX}/scans", tags=["Scanning"])
app.include_router(reports.router, prefix=f"{API_PREFIX}/reports", tags=["Reports"])
app.include_router(alerts.router, prefix=f"{API_PREFIX}/alerts", tags=["Alerts"])
app.include_router(cloud_accounts.router, prefix=f"{API_PREFIX}/cloud-accounts", tags=["Cloud Accounts"])
app.include_router(users.router, prefix=f"{API_PREFIX}/users", tags=["User Management"])
app.include_router(orgs.router,          prefix=f"{API_PREFIX}/orgs",        tags=["Organizations"])
app.include_router(audit_logs.router,    prefix=f"{API_PREFIX}/audit-logs", tags=["Audit Logs"])
app.include_router(violations.router,    prefix=f"{API_PREFIX}/violations",  tags=["Violations"])
app.include_router(dspm.router,          prefix=f"{API_PREFIX}/dspm",        tags=["DSPM"])
app.include_router(terraform.router,     prefix=f"{API_PREFIX}/terraform",   tags=["Terraform"])
app.include_router(threat_intel.router,  prefix=f"{API_PREFIX}/threat-intel", tags=["Threat Intelligence"])
app.include_router(workflows.router,     prefix=f"{API_PREFIX}/workflows",    tags=["Approval Workflows"])
app.include_router(ws_router,            prefix=f"{API_PREFIX}/ws",           tags=["WebSocket"])


# ---- Health / Readiness ----

@app.get("/health", tags=["Health"], include_in_schema=False)
async def health_check() -> dict:
    return {"status": "healthy", "version": "1.0.0"}


@app.get("/ready", tags=["Health"], include_in_schema=False)
async def readiness_check() -> dict:
    return {"status": "ready"}


# ---- Global Exception Handler ----

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled exception", exc_info=exc, path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please try again later."},
    )
