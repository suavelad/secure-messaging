"""
Authentication routes: register, login, token refresh.

Security notes
--------------
- Passwords are hashed with Argon2id (64 MiB / 3 iterations / 4 threads).
- JWT access tokens expire in 15 minutes; refresh tokens expire in 7 days.
- Token rotation: each /refresh call revokes the old refresh token and issues
  a new pair, limiting the window of a stolen refresh token.
- Login uses constant-time Argon2id verification even when the user is not
  found, to prevent username enumeration via timing differences.
"""
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger
from sqlalchemy.orm import Session

from backend.auth import (
    create_access_token,
    create_refresh_token,
    hash_password,
    hash_token,
    verify_password,
    verify_refresh_token,
)
from backend.database import DBRefreshToken, DBUser, get_db
from backend.schemas import LoginRequest, RefreshRequest, RegisterRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new account and receive JWT tokens",
)
async def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    """
    Create a new user account.

    The client generates Ed25519 (identity) and X25519 (prekey) key pairs
    **on-device** and uploads only the public halves.  Private keys never
    leave the device (zero-knowledge server design).

    On success returns an access token + refresh token pair so the user
    does not have to log in again immediately after registration.
    """
    logger.info(f"Register attempt  username={payload.username!r}")

    # Reject duplicate usernames
    if db.query(DBUser).filter(DBUser.username == payload.username).first():
        logger.warning(f"Register rejected — username {payload.username!r} already taken")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    # Persist user
    user_id = str(uuid.uuid4())
    logger.info(
        f"[KEY_MGMT] Registering user {payload.username!r} with Public Keys: "
        f"identity={payload.identity_key_pub[:16]}... "
        f"prekey={payload.pre_key_pub[:16]}..."
    )
    db.add(DBUser(
        user_id=user_id,
        username=payload.username,
        password_hash=hash_password(payload.password),
        identity_key_pub=payload.identity_key_pub,
        pre_key_pub=payload.pre_key_pub,
    ))
    db.commit()
    logger.info(f"User created  user_id={user_id}  username={payload.username!r}")

    # Issue token pair
    session_id = str(uuid.uuid4())
    user = db.query(DBUser).filter(DBUser.user_id == user_id).first()
    user.current_session_id = session_id
    user.current_device_id  = payload.device_id
    db.commit()

    access_token              = create_access_token(user_id, payload.username, session_id, payload.device_id)
    refresh_token, rt_expiry  = create_refresh_token(user_id, payload.username)

    logger.info(f"[AUTH] Issuing initial token pair for {payload.username!r}")
    db.add(DBRefreshToken(
        user_id=user_id,
        token_hash=hash_token(refresh_token),
        expires_at=rt_expiry,
    ))
    db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=15 * 60,
        user_id=user_id,
        username=payload.username,
        identity_key_pub=payload.identity_key_pub,
        pre_key_pub=payload.pre_key_pub,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate and receive JWT tokens",
)
async def login(payload: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate with username + password.

    Returns:
    - **access_token** (15 min) — attach to every API request as
      `Authorization: Bearer <token>`
    - **refresh_token** (7 days) — use at `/auth/refresh` to obtain a new
      pair without requiring the user to re-enter credentials
    """
    logger.info(f"Login attempt  username={payload.username!r}")

    user = db.query(DBUser).filter(DBUser.username == payload.username).first()

    # Constant-time verification to prevent username enumeration:
    # verify_password runs Argon2id even if user is None (dummy hash check).
    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$c29tZWhhc2g"
    password_ok = verify_password(
        payload.password,
        user.password_hash if user else dummy_hash,
    )

    if not user or not password_ok:
        logger.warning(f"Login failed  username={payload.username!r}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # ── Single Device Enforcement ─────────────────────────────────────────────
    # Track a new session ID for every login to kick old device sessions.
    session_id = str(uuid.uuid4())
    user.current_session_id = session_id
    user.current_device_id  = payload.device_id

    # Revoke all existing refresh tokens for this user so that they are 
    # logged out of all other devices immediately when they attempt to refresh.
    db.query(DBRefreshToken).filter(
        DBRefreshToken.user_id == user.user_id,
        DBRefreshToken.revoked.is_(False)
    ).update({"revoked": True})
    db.commit()

    access_token             = create_access_token(user.user_id, user.username, session_id, payload.device_id)
    refresh_token, rt_expiry = create_refresh_token(user.user_id, user.username)

    db.add(DBRefreshToken(
        user_id=user.user_id,
        token_hash=hash_token(refresh_token),
        expires_at=rt_expiry,
    ))
    db.commit()

    logger.info(f"Login OK  user_id={user.user_id}  username={user.username!r}  sid={session_id}")

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=15 * 60,
        user_id=user.user_id,
        username=user.username,
        identity_key_pub=user.identity_key_pub,
        pre_key_pub=user.pre_key_pub,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Rotate refresh token and get a new access token",
)
async def refresh_tokens(payload: RefreshRequest, db: Session = Depends(get_db)):
    """
    Exchange a valid refresh token for a new access + refresh token pair.

    The submitted refresh token is immediately revoked (token rotation).
    A second attempt to use the same token will be rejected, which helps
    detect refresh-token theft.
    """
    decoded = verify_refresh_token(payload.refresh_token)
    if not decoded:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    user_id: str  = decoded["sub"]
    username: str = decoded["username"]

    # Confirm token exists in DB and has not been revoked
    stored = db.query(DBRefreshToken).filter(
        DBRefreshToken.token_hash == hash_token(payload.refresh_token),
        DBRefreshToken.revoked.is_(False),
    ).first()

    if not stored:
        logger.warning(f"Refresh token not found or revoked  user_id={user_id!r}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has been revoked",
        )

    # Revoke old token (rotation)
    stored.revoked = True

    # Fetch user to get current session ID
    user = db.query(DBUser).filter(DBUser.user_id == user_id).first()
    if not user:
        db.commit()
        raise HTTPException(status_code=401, detail="User not found")

    db.commit()
    logger.info(f"[AUTH] Revoked old refresh token for user_id={user_id!r} (Rotation START)")

    # Issue new pair
    new_access              = create_access_token(user_id, username, user.current_session_id, user.current_device_id)
    new_refresh, new_expiry = create_refresh_token(user_id, username)

    db.add(DBRefreshToken(
        user_id=user_id,
        token_hash=hash_token(new_refresh),
        expires_at=new_expiry,
    ))
    db.commit()

    logger.info(f"[AUTH] Tokens rotated successfully for user_id={user_id!r} (Rotation END)")

    # Fetch user to get public keys for TokenResponse
    user = db.query(DBUser).filter(DBUser.user_id == user_id).first()
    if not user:
         raise HTTPException(status_code=404, detail="User not found")

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=15 * 60,
        user_id=user_id,
        username=username,
        identity_key_pub=user.identity_key_pub,
        pre_key_pub=user.pre_key_pub,
    )
