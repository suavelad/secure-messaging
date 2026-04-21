"""
Pydantic request / response schemas.

All public-key fields are base64-encoded raw 32-byte values (not PEM).
This keeps the mobile client simple: extract raw bytes → base64-encode → send.
"""
from datetime import datetime
from pydantic import BaseModel, Field, field_validator


# ─── Auth ─────────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    # Username: alphanumeric + underscore/hyphen, 3–32 chars
    username: str = Field(..., min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    # Base64-encoded raw 32-byte Ed25519 public key (for signature verification)
    identity_key_pub: str = Field(..., description="Ed25519 public key — base64-encoded 32 bytes")
    # Base64-encoded raw 32-byte X25519 public key (for ECDH key exchange)
    pre_key_pub: str = Field(..., description="X25519 public key — base64-encoded 32 bytes")
    # Persistent device identifier for session pinning
    device_id: str = Field(..., description="Persistent UUID for this device installation")


class LoginRequest(BaseModel):
    username: str
    password: str
    device_id: str = Field(..., description="Persistent UUID for this device installation")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int          # Seconds until the access token expires
    user_id: str
    username: str
    identity_key_pub: str
    pre_key_pub: str


class RefreshRequest(BaseModel):
    refresh_token: str


# ─── Users ────────────────────────────────────────────────────────────────────

class UserListItem(BaseModel):
    user_id: str
    username: str
    is_online: bool = False


class UserPublicKeys(BaseModel):
    """Public profile returned when another user fetches your keys for E2E."""
    user_id: str
    username: str
    # Base64-encoded raw Ed25519 public key
    identity_key_pub: str
    # Base64-encoded raw X25519 public key
    pre_key_pub: str


# ─── Messages ─────────────────────────────────────────────────────────────────

class SendMessageRequest(BaseModel):
    recipient_id: str

    # AES-256-GCM ciphertext + 16-byte GCM auth tag — hex-encoded
    ciphertext: str

    # 12-byte AES-GCM nonce — hex-encoded (exactly 24 hex characters)
    nonce: str = Field(..., min_length=24, max_length=24)

    # Ed25519 signature over (ciphertext_hex || nonce_hex || unix_timestamp_str)
    # This binds the signature to a specific encrypted message at a specific time.
    signature: str

    # Sender-supplied ISO 8601 timestamp — validated to be within ±5 min of server
    timestamp: datetime

    @field_validator("nonce")
    @classmethod
    def _validate_nonce_is_hex(cls, v: str) -> str:
        try:
            bytes.fromhex(v)
        except ValueError:
            raise ValueError("nonce must be a valid hex string")
        return v.lower()


class MessageResponse(BaseModel):
    id: int
    sender_id: str
    recipient_id: str
    sender_username: str
    ciphertext: str
    nonce: str
    signature: str
    timestamp: datetime
    received_at: datetime
    delivered_at: datetime | None = None
    read_at: datetime | None = None


class AckResponse(BaseModel):
    deleted: bool
    message_id: int
