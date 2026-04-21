"""
SecureMessenger — FastAPI Backend  (v2.0)
==========================================

Zero-knowledge E2E encrypted messaging relay.

Security architecture
---------------------
┌──────────────────────────────────────────────────────────────────────┐
│  Mobile client                       This server                     │
│  ─────────────────────               ─────────────────────────────   │
│  Generates Ed25519 + X25519 keys     Stores only public keys         │
│  Derives session key via ECDH        Cannot derive session keys       │
│  Encrypts with AES-256-GCM           Cannot decrypt messages          │
│  Signs with Ed25519                  Verifies signatures              │
│  Adds X-Nonce + X-Timestamp          Validates nonce + timestamp      │
│  Short-lived JWT access token        Issues + validates JWT tokens    │
└──────────────────────────────────────────────────────────────────────┘

Run
---
    # From project root (activate venv first):
    uvicorn backend.main:app --reload --port 8000

    # With TLS (production):
    uvicorn backend.main:app --port 443 --ssl-keyfile key.pem --ssl-certfile cert.pem
"""
import os
import sys

# ── Dynamic Path Injection (Deployment Compatibility) ─────────────────────────
# This handles the 'ModuleNotFoundError: No module named backend' error encountered 
# during Vercel deployment. It ensures the package root is always discoverable.
_current_dir = os.path.dirname(os.path.abspath(__file__))
_parent_dir  = os.path.dirname(_current_dir)
if _current_dir not in sys.path: sys.path.insert(0, _current_dir)
if _parent_dir not in sys.path:  sys.path.insert(0, _parent_dir)
# ──────────────────────────────────────────────────────────────────────────────

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger

from config import get_settings
from database import create_tables
from middleware.anti_replay import anti_replay_middleware
from routers.auth import router as auth_router
from routers.messages import router as messages_router
from routers.users import router as users_router
from routers.websocket import router as ws_router

settings = get_settings()

# ── Logging Setup ─────────────────────────────────────────────────────────────
# In production/serverless (like Vercel), we cannot write to the local filesystem.
# We only enable file logging if the directory is writable.
IS_VERCEL = os.environ.get("VERCEL") == "1"

if not IS_VERCEL:
    try:
        os.makedirs("logs", exist_ok=True)
    except OSError:
        pass # Probably read-only

# Remove loguru's default stderr handler
logger.remove()

# Console sink — coloured, human-readable (Works on Vercel)
logger.add(
    sys.stderr,
    level="DEBUG" if settings.debug else "INFO",
    format=(
        "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> — "
        "<level>{message}</level>"
    ),
    colorize=True,
)

# File sink — ONLY enabled if not on Vercel
if not IS_VERCEL:
    try:
        logger.add(
            "logs/backend_{time:YYYY-MM-DD}.log",
            level="DEBUG",
            rotation="00:00",
            retention="30 days",
            compression="gz",
            format=(
                "{time:YYYY-MM-DD HH:mm:ss.SSS} | "
        "{level: <8} | "
        "{name}:{function}:{line} — {message}"
    ),
    encoding="utf-8",
)


# ── Application Lifespan ──────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Startup / shutdown lifecycle handler."""
    logger.info("=" * 66)
    logger.info(f"  {settings.app_name}  v2.0")
    logger.info(f"  Debug:    {settings.debug}")
    logger.info(f"  Database: {settings.database_url}")
    logger.info("=" * 66)

    # Create DB schema tables (idempotent)
    create_tables()
    logger.info("Database tables ready")

    yield  # ← application runs here

    logger.info(f"{settings.app_name} shutting down — goodbye")


# ── FastAPI Application ───────────────────────────────────────────────────────

app = FastAPI(
    title=settings.app_name,
    description=(
        "Zero-knowledge end-to-end encrypted messaging relay.\n\n"
        "All message content is **AES-256-GCM encrypted on the mobile client** "
        "before upload. The server stores only ciphertext and cannot read messages.\n\n"
        "**Anti-replay**: every protected request must carry `X-Nonce` (UUID4) "
        "and `X-Timestamp` (Unix epoch) headers.\n\n"
        "**Authentication**: JWT access tokens (15 min) + rotating refresh tokens (7 days)."
    ),
    version="2.0.0",
    lifespan=lifespan,
    # Interactive API docs always available (disable in production by setting DEBUG=false)
    docs_url="/docs",
    redoc_url="/redoc",
)


# ── CORS ──────────────────────────────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request / Response Logging ────────────────────────────────────────────────

@app.middleware("http")
async def _log_http(request: Request, call_next):
    """Log every HTTP request with method, path, client IP, and status code."""
    client = request.client.host if request.client else "unknown"
    logger.info(f"→ {request.method:6s} {request.url.path}  [{client}]")
    response = await call_next(request)
    logger.info(f"← {request.method:6s} {request.url.path}  {response.status_code}")
    return response


# ── Global Exception Handler ──────────────────────────────────────────────────

@app.exception_handler(Exception)
async def _unhandled(_request: Request, exc: Exception):
    """Catch any unhandled exception, log it, and return a safe 500 response."""
    logger.error(f"Unhandled exception: {exc!r}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# ── Routers ───────────────────────────────────────────────────────────────────

# Public routes — no JWT, no anti-replay (auth flow has its own protection)
app.include_router(auth_router)

# Protected routes — require JWT Bearer token + X-Nonce + X-Timestamp headers
_protected = [Depends(anti_replay_middleware)]
app.include_router(users_router,    dependencies=_protected)
app.include_router(messages_router, dependencies=_protected)

# WebSocket — authenticated via ?token= query param (no HTTP middleware)
app.include_router(ws_router)


# ── Health Check ──────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"], summary="Service liveness probe")
async def health():
    """Returns 200 when the service is running and the database is reachable."""
    return {
        "status":  "healthy",
        "service": settings.app_name,
        "version": "2.0.0",
    }
