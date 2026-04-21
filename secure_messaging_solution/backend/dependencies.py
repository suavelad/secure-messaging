"""
Shared FastAPI dependencies.

get_current_user — extract and validate a JWT access token, return the
authenticated DBUser.  Used as a Depends() in every protected route.
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger
from sqlalchemy.orm import Session

from auth import verify_access_token
from database import DBUser, get_db

# Parses "Authorization: Bearer <token>" from incoming requests
_bearer = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: Session = Depends(get_db),
) -> DBUser:
    """
    FastAPI dependency: authenticate the caller via JWT access token.

    Usage
    -----
    @router.get("/protected")
    async def my_endpoint(user: DBUser = Depends(get_current_user)):
        ...

    Raises HTTP 401 if the token is absent, malformed, expired, or the
    corresponding user account no longer exists / is deactivated.
    """
    payload = verify_access_token(credentials.credentials)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired access token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id: str = payload.get("sub", "")
    user = db.query(DBUser).filter(
        DBUser.user_id == user_id,
        DBUser.is_active.is_(True),
    ).first()

    if user:
        # Update heartbeat on successfully authenticated requests
        from datetime import datetime, timezone
        user.last_active_at = datetime.now(timezone.utc)
        db.commit()

    if not user:
        logger.warning(
            f"JWT valid but user not found or inactive: user_id={user_id!r}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or deactivated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # ── Session Enforcement (Single Device) ──────────────────────────────────
    # Check if the token's session ID matches the user's latest session.
    # If a new login occurred, the old tokens' sid will be stale.
    token_sid = payload.get("sid")
    token_did = payload.get("did")
    
    if token_sid != user.current_session_id or token_did != user.current_device_id:
        logger.warning(
            f"SECURITY DISCONNECT: user={user.username!r} "
            f"token_sid={token_sid!r} db_sid={user.current_session_id!r} "
            f"token_did={token_did!r} db_did={user.current_device_id!r}"
        )
        # If it's a device mismatch, we provide a more specific message
        detail = "Session has been invalidated by another login"
        if token_did != user.current_device_id:
            detail = "New device detected. You have been logged out from this device."

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user
