"""
Anti-replay request middleware.

Every API request to protected endpoints MUST include two headers:

    X-Nonce:     A UUID4 string — globally unique, single-use
    X-Timestamp: Current Unix epoch in seconds (float or int)

The server rejects a request when:
  1. X-Timestamp is more than ±5 minutes from server time — prevents use of
     stale captured requests even without nonce tracking.
  2. X-Nonce was already seen within the past 10 minutes — prevents exact
     replay of a legitimately signed request.

Together these two checks mean that intercepting a valid encrypted request
in transit and retransmitting it will be detected and rejected.

Exempt paths (login / register / health) skip the check because they either
have their own replay resistance (Argon2id password verification) or are
stateless probes.

Multi-process note
------------------
The nonce cache is in-process memory.  For a multi-worker deployment
(e.g. gunicorn --workers 4) replace _nonce_cache with a Redis SET with TTL.
"""
import threading
import time
from typing import Dict

from fastapi import HTTPException, Request, status
from loguru import logger

from config import get_settings

settings = get_settings()

# ── Nonce Cache ───────────────────────────────────────────────────────────────
# Maps nonce_string → expiry Unix timestamp (float)
_nonce_cache: Dict[str, float] = {}
_cache_lock = threading.Lock()

# Paths that skip anti-replay validation
_EXEMPT_PATHS = frozenset({
    "/auth/register",
    "/auth/login",
    "/auth/refresh",
    "/health",
    "/docs",
    "/redoc",
    "/openapi.json",
})


def _purge_expired(now: float) -> None:
    """Remove stale entries from the nonce cache (must be called under lock)."""
    stale = [n for n, exp in _nonce_cache.items() if exp < now]
    for key in stale:
        del _nonce_cache[key]
    if stale:
        logger.debug(f"Purged {len(stale)} expired nonces  cache_size={len(_nonce_cache)}")


def enforce_anti_replay(nonce: str, timestamp_str: str) -> None:
    """
    Validate nonce + timestamp for replay protection.

    Raises HTTPException (400 or 409) on failure.
    """
    # ── Parse timestamp ───────────────────────────────────────────────────────
    try:
        req_time = float(timestamp_str)
    except (ValueError, TypeError):
        logger.warning(f"Malformed X-Timestamp: {timestamp_str!r}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Timestamp must be a Unix epoch value (e.g. 1718000000)",
        )

    # ── Clock-skew check ─────────────────────────────────────────────────────
    server_time = time.time()
    delta = abs(server_time - req_time)
    if delta > settings.timestamp_tolerance_seconds:
        logger.warning(
            f"Timestamp rejected  delta={delta:.0f}s  "
            f"server={server_time:.0f}  request={req_time:.0f}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Request timestamp out of range: "
                f"Δ={delta:.0f}s exceeds max {settings.timestamp_tolerance_seconds}s"
            ),
        )

    # ── Nonce length sanity ───────────────────────────────────────────────────
    if len(nonce) < 16:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-Nonce too short (minimum 16 characters)",
        )

    # ── Uniqueness check ──────────────────────────────────────────────────────
    nonce_expiry = server_time + settings.nonce_ttl_seconds

    with _cache_lock:
        _purge_expired(server_time)

        if nonce in _nonce_cache:
            logger.warning(f"[REPLAY PROTECT] !!! REPLAY DETECTED !!! nonce={nonce[:12]}...")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Replay detected: this nonce has already been used",
            )

        _nonce_cache[nonce] = nonce_expiry
        logger.info(
            f"[REPLAY PROTECT] Nonce verified (Accepted) context='{nonce[:8]}...' "
            f"cache_size={len(_nonce_cache)}"
        )


async def anti_replay_middleware(request: Request) -> None:
    """
    FastAPI dependency enforcing anti-replay on protected routes.

    Attach via:
        app.include_router(router, dependencies=[Depends(anti_replay_middleware)])
    """
    if request.url.path in _EXEMPT_PATHS:
        return  # Public endpoints are exempt

    nonce     = request.headers.get("X-Nonce",     "")
    timestamp = request.headers.get("X-Timestamp", "")

    if not nonce or not timestamp:
        missing = [h for h, v in [("X-Nonce", nonce), ("X-Timestamp", timestamp)] if not v]
        logger.warning(
            f"Missing anti-replay headers on {request.url.path}: {missing}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Missing required headers: {', '.join(missing)}",
        )

    enforce_anti_replay(nonce, timestamp)
