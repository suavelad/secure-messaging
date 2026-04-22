"""
SQLAlchemy database models and session management.

Tables
------
users          — user accounts with hashed password + public keys
messages       — encrypted message queue (zero-knowledge relay)
refresh_tokens — JWT refresh token revocation list (stores SHA-256 hashes only)

Key design choices
------------------
- Public keys are stored as base64-encoded raw 32-byte values (not PEM) to
  simplify mobile-client integration.
- SQLite WAL mode is enabled for better concurrent read performance under
  FastAPI's async handlers.
- Messages are deleted by the recipient after successful decryption; the
  server never accumulates long-term ciphertext.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Integer, String, Text, event, create_engine,
)
from sqlalchemy.orm import declarative_base, sessionmaker

from config import get_settings

settings = get_settings()

# ── Engine ────────────────────────────────────────────────────────────────────

# Select database URL based on ENV (local uses sqlite, dev uses postgres)
_db_url = settings.database_url
if settings.env.lower() == "dev":
    if not settings.postgres_url:
        raise ValueError("ENV=dev set but POSTGRES_URL is missing in configuration.")
    _db_url = settings.postgres_url

engine = create_engine(
    _db_url,
    # SQLite requires this for multi-threaded use (FastAPI async event loop)
    connect_args={"check_same_thread": False} if "sqlite" in _db_url else {},
    echo=settings.debug,
)

# Enable SQLite WAL mode, foreign-key enforcement, and NORMAL sync for perf
if "sqlite" in _db_url:
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── Models ────────────────────────────────────────────────────────────────────

class DBUser(Base):
    """
    User account row.

    Public keys stored as base64-encoded raw 32-byte strings:
      identity_key_pub — Ed25519 public key  (for verifying message signatures)
      pre_key_pub      — X25519 public key   (for ECDH session-key derivation)

    Private keys live exclusively on the user's device (zero-knowledge server).
    """
    __tablename__ = "users"

    user_id          = Column(String(36),  primary_key=True,
                               default=lambda: str(uuid.uuid4()))
    username         = Column(String(64),  unique=True, nullable=False, index=True)
    # Argon2id hash — never stored in plain text
    password_hash    = Column(String(256), nullable=False)
    # Ed25519 public key — base64 raw 32 bytes
    identity_key_pub = Column(String(64),  nullable=False)
    # X25519 public key — base64 raw 32 bytes
    pre_key_pub      = Column(String(64),  nullable=False)

    created_at = Column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    is_active = Column(Boolean, nullable=False, default=True)
    # Track current active session ID to enforce single-device logout on any request.
    current_session_id = Column(String(36), nullable=True)
    # Track current active device ID to detect cross-device session takeover.
    current_device_id = Column(String(36), nullable=True)
    # Track when the user was last seen interacting with the API.
    last_active_at = Column(
        DateTime(timezone=True), nullable=True,
    )


class DBMessage(Base):
    """
    Encrypted message stored for delivery.

    The server is a zero-knowledge relay — it stores only ciphertext blobs.
    Without the recipient's private X25519 prekey, these cannot be decrypted
    even if the database is fully compromised.

    ciphertext    — hex-encoded AES-256-GCM ciphertext + 16-byte GCM auth tag
    nonce         — hex-encoded 12-byte AES-GCM nonce (24 hex chars)
    signature     — hex-encoded Ed25519 signature over
                    (ciphertext_hex || nonce_hex || unix_timestamp_str)
    msg_timestamp — sender-supplied timestamp (validated to be recent on upload)
    received_at   — server-side receipt timestamp
    """
    __tablename__ = "messages"

    id            = Column(Integer,  primary_key=True, autoincrement=True, index=True)
    sender_id     = Column(String(36), nullable=False, index=True)
    recipient_id  = Column(String(36), nullable=False, index=True)
    ciphertext    = Column(Text,       nullable=False)
    nonce         = Column(String(24), nullable=False)
    signature     = Column(Text,       nullable=False)
    msg_timestamp = Column(DateTime(timezone=True), nullable=False)
    received_at   = Column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    delivered_at  = Column(DateTime(timezone=True), nullable=True)
    read_at       = Column(DateTime(timezone=True), nullable=True)


class DBRefreshToken(Base):
    """
    JWT refresh token revocation list.

    Stores only the SHA-256 hash of each token so that a database breach
    does not expose live bearer tokens.
    """
    __tablename__ = "refresh_tokens"

    id         = Column(Integer,  primary_key=True, autoincrement=True)
    user_id    = Column(String(36), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True)  # SHA-256 hex
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked    = Column(Boolean, nullable=False, default=False)
    created_at = Column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


# ── Session Dependency ────────────────────────────────────────────────────────

def get_db():
    """FastAPI dependency: yield a DB session, guaranteed to close on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_tables() -> None:
    """Create all tables (idempotent — safe to call on every startup)."""
    Base.metadata.create_all(bind=engine)
