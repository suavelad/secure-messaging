"""
JWT token lifecycle and Argon2id password hashing.

Token strategy
--------------
Access token  — short-lived (15 min default), used for every API call.
Refresh token — long-lived (7 days default), used ONLY to obtain a new
                access token.  Stored in DB as a SHA-256 hash for revocation.

Token rotation
--------------
Every call to /auth/refresh issues a new refresh token AND revokes the old
one.  If a stolen refresh token is used before the legitimate client rotates
it, the second rotation attempt will see the old token already revoked and
can deny the request, limiting the attack window.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import JWTError, jwt
from loguru import logger
from passlib.context import CryptContext

from config import get_settings

settings = get_settings()

# ── Password Hashing (Argon2id) ───────────────────────────────────────────────
# Argon2id is OWASP-recommended for new applications.
# Memory-hard design defeats GPU/ASIC brute-force attacks.
# These parameters are the OWASP minimums for interactive logins.
_pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__memory_cost=65536,   # 64 MiB RAM per hash
    argon2__time_cost=3,         # 3 iterations
    argon2__parallelism=4,       # 4 parallel threads
    argon2__hash_len=32,         # 256-bit output
)


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id. Returns the full hash string."""
    hashed = _pwd_context.hash(password)
    logger.debug("Password hashed successfully (Argon2id)")
    return hashed


def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify a plaintext password against an Argon2id hash.

    Uses constant-time comparison internally to prevent timing side-channels.
    """
    return _pwd_context.verify(plain, hashed)


# ── JWT Tokens ────────────────────────────────────────────────────────────────

def create_access_token(user_id: str, username: str, sid: str, did: str) -> str:
    """
    Issue a short-lived JWT access token.

    Claims: sub (user_id), username, sid (session_id), did (device_id), type="access", iat, exp
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.access_token_expire_minutes)
    payload = {
        "sub":      user_id,
        "username": username,
        "sid":      sid,
        "did":      did,
        "type":     "access",
        "iat":      now,
        "exp":      expire,
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)
    logger.debug(
        f"Access token issued: user={username!r}  sid={sid!r}  did={did!r}  expires={expire.isoformat()}"
    )
    return token


def create_refresh_token(user_id: str, username: str) -> tuple[str, datetime]:
    """
    Issue a long-lived JWT refresh token.

    Returns (token_string, expiry_datetime).  A random jti (JWT ID) is
    embedded so individual tokens can be tracked and revoked in the database.
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=settings.refresh_token_expire_days)
    payload = {
        "sub":      user_id,
        "username": username,
        "type":     "refresh",
        "jti":      secrets.token_hex(16),  # Unique token identifier
        "iat":      now,
        "exp":      expire,
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)
    return token, expire


def verify_access_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT access token.

    Returns the decoded payload dict on success, or None if the token is
    missing, malformed, expired, or has the wrong type.
    """
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=[settings.algorithm]
        )
        if payload.get("type") != "access":
            logger.warning("JWT type mismatch: expected 'access'")
            return None
        logger.info(f"[AUTH VERIFIED] Token validated for u/{payload.get('username')}")
        return payload
    except JWTError as exc:
        logger.debug(f"Access token rejected: {exc}")
        return None


def verify_refresh_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT refresh token.

    Returns the decoded payload dict on success, or None on failure.
    """
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=[settings.algorithm]
        )
        if payload.get("type") != "refresh":
            return None
        return payload
    except JWTError as exc:
        logger.debug(f"Refresh token rejected: {exc}")
        return None


def hash_token(token: str) -> str:
    """
    SHA-256 hash a token string for safe storage in the database.

    Storing the hash means a database dump does not expose live bearer tokens.
    """
    return hashlib.sha256(token.encode()).hexdigest()
