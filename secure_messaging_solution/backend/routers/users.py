"""
User management endpoints.

/users          — list all active users (excluding the caller)
/users/{id}/keys — fetch a user's public keys for E2E key exchange
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger
from sqlalchemy.orm import Session

from database import DBUser, get_db
from dependencies import get_current_user
from schemas import UserListItem, UserPublicKeys
from ws_manager import manager

router = APIRouter(prefix="/users", tags=["Users"])


@router.get(
    "",
    response_model=List[UserListItem],
    summary="List all registered users (excluding self)",
)
async def list_users(
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user),
):
    """
    Return every active user except the caller.

    Used by the mobile app to populate the contacts / conversation list.
    Only user_id and username are returned — no keys or sensitive data.
    """
    users = (
        db.query(DBUser)
        .filter(
            DBUser.is_active.is_(True),
            DBUser.user_id != current_user.user_id,
        )
        .all()
    )
    logger.debug(f"User {current_user.username!r} listed {len(users)} peers")
    return [
        UserListItem(
            user_id=u.user_id, 
            username=u.username,
            is_online=manager.is_online(u.user_id)
        ) for u in users
    ]


@router.get(
    "/{user_id}/keys",
    response_model=UserPublicKeys,
    summary="Fetch a user's public keys for E2E key exchange",
)
async def get_user_keys(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user),
):
    """
    Return the target user's Ed25519 identity key and X25519 prekey
    (public halves only).

    The caller uses these keys to establish an encrypted session:

    1. **ECDH**:        shared_secret = X25519(my_prekey_priv, peer_prekey_pub)
    2. **HKDF**:        session_key   = HKDF-SHA256(shared_secret, info=…)
    3. **Encryption**:  ciphertext    = AES-256-GCM(session_key, plaintext)
    4. **Signing**:     signature     = Ed25519(my_identity_priv, ct‖nonce‖ts)
    """
    user = db.query(DBUser).filter(
        DBUser.user_id == user_id,
        DBUser.is_active.is_(True),
    ).first()

    if not user:
        logger.warning(
            f"Key lookup by {current_user.username!r}: "
            f"user_id={user_id!r} not found"
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    logger.info(
        f"[KEY_MGMT] Key fetch: {current_user.username!r} requested keys for {user.username!r}"
    )
    return UserPublicKeys(
        user_id=user.user_id,
        username=user.username,
        identity_key_pub=user.identity_key_pub,
        pre_key_pub=user.pre_key_pub,
    )


@router.patch(
    "/me/keys",
    status_code=status.HTTP_200_OK,
    summary="Update public keys (Key Rotation / Device Change)",
)
async def update_keys(
    identity_key_pub: str,
    pre_key_pub: str,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user),
):
    """
    Updates the current user's public keys. 
    This should be called if the user logs in on a new device and 
    generates a fresh identity.
    """
    logger.info(f"[KEY_MGMT] Updating keys for user: {current_user.username}")
    current_user.identity_key_pub = identity_key_pub
    current_user.pre_key_pub      = pre_key_pub
    db.commit()
    return {"status": "keys updated"}
