"""
Application configuration loaded from environment variables.

Settings are read once at startup and cached.  Override any value by setting
the corresponding environment variable or by providing a .env file.
"""
import secrets
from functools import lru_cache
from typing import List

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Application ───────────────────────────────────────────────────────────
    app_name: str = "SecureMessenger API"
    debug: bool = False

    # ── Security / JWT ────────────────────────────────────────────────────────
    # IMPORTANT: Override SECRET_KEY in production via environment variable.
    # A default is generated at import time so dev works out-of-the-box, but
    # it changes on every restart — set a stable value in .env.
    secret_key: str = Field(
        default_factory=lambda: secrets.token_hex(32),
        description="HMAC secret for JWT signing — set a stable value in .env",
    )
    algorithm: str = "HS256"
    # Short-lived access tokens: limit blast radius of token theft
    access_token_expire_minutes: int = 15
    # Longer-lived refresh tokens: support offline use without re-login
    refresh_token_expire_days: int = 7

    # ── Anti-Replay ───────────────────────────────────────────────────────────
    # Every protected request must include X-Nonce (UUID4) + X-Timestamp.
    # nonce_ttl_seconds: how long a used nonce is remembered (reject reuse)
    nonce_ttl_seconds: int = 600              # 10 minutes
    # timestamp_tolerance_seconds: max allowed clock skew ±
    timestamp_tolerance_seconds: int = 300    # ±5 minutes

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = "sqlite:///./secure_messenger.db"

    # ── CORS ──────────────────────────────────────────────────────────────────
    # Restrict to your mobile app origin in production (e.g. ["https://myapp.com"])
    allowed_origins: List[str] = ["*"]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
    }


@lru_cache()
def get_settings() -> Settings:
    """Return a cached singleton of Settings.  Thread-safe after first call."""
    return Settings()
