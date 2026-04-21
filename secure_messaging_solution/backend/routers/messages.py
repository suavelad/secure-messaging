"""
Message send / receive / delete endpoints.

Zero-knowledge relay design
----------------------------
The server stores ONLY ciphertext blobs.  It verifies the Ed25519 signature
to authenticate the sender, but it cannot read message content.

Security checks on every upload
--------------------------------
1. Recipient must exist and be active.
2. Sender-supplied timestamp must be within ±5 minutes of server time
   (message-level replay protection on top of the request-level nonce check).
3. Ed25519 signature must be valid over (ciphertext‖nonce‖unix_timestamp).

Forward deletion
-----------------
The client calls DELETE after successful local decryption.  Messages are not
retained on the relay beyond delivery, minimising the exposed ciphertext
surface in the event of a server breach.
"""
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger
from sqlalchemy import or_
from sqlalchemy.orm import Session

from crypto import verify_message_signature
from database import DBMessage, DBUser, get_db
from dependencies import get_current_user
from schemas import AckResponse, MessageResponse, SendMessageRequest
from ws_manager import manager

router = APIRouter(prefix="/messages", tags=["Messages"])


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Upload an E2E-encrypted message for a recipient",
)
async def send_message(
    payload: SendMessageRequest,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user),
):
    """
    Send an encrypted message.

    The client must:
    - Encrypt the plaintext with AES-256-GCM using a session key derived via
      X25519 ECDH + HKDF-SHA256 from the recipient's public prekey.
    - Sign `ciphertext_hex + nonce_hex + unix_timestamp_str` with its
      Ed25519 identity key before uploading.

    The server verifies the signature, stores the ciphertext, and pushes a
    real-time WebSocket notification to the recipient if online.
    """
    logger.info(
        f"send_message  sender={current_user.username!r}  "
        f"recipient_id={payload.recipient_id!r}"
    )

    # ── 1. Recipient must exist ───────────────────────────────────────────────
    recipient = db.query(DBUser).filter(
        DBUser.user_id == payload.recipient_id,
        DBUser.is_active.is_(True),
    ).first()
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found",
        )

    # ── 2. Timestamp freshness (message-level replay guard) ───────────────────
    now    = datetime.now(timezone.utc)
    msg_ts = payload.timestamp.replace(tzinfo=timezone.utc) \
             if payload.timestamp.tzinfo is None else payload.timestamp
    delta  = abs((now - msg_ts).total_seconds())
    if delta > 300:
        logger.warning(
            f"Message timestamp rejected  delta={delta:.0f}s  "
            f"sender={current_user.username!r}"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Message timestamp too skewed: Δ={delta:.0f}s (max 300s)",
        )

    # ── 3. Ed25519 signature verification ────────────────────────────────────
    # Check if this exact message (same signature) has already been relayed.
    existing = db.query(DBMessage).filter(DBMessage.signature == payload.signature).first()
    if existing:
        logger.warning(f"Replay detected — signature already processed")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Replay detected: this message has already been relayed",
        )

    unix_ts_str = str(int(msg_ts.timestamp()))
    if not verify_message_signature(
        identity_key_b64=current_user.identity_key_pub,
        signature_hex=payload.signature,
        ciphertext_hex=payload.ciphertext,
        nonce_hex=payload.nonce,
        unix_timestamp_str=unix_ts_str,
    ):
        logger.warning(
            f"Invalid signature from {current_user.username!r}"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Message signature verification failed",
        )

    # ── 4. Persist encrypted message ──────────────────────────────────────────
    msg = DBMessage(
        sender_id=current_user.user_id,
        recipient_id=payload.recipient_id,
        ciphertext=payload.ciphertext,
        nonce=payload.nonce,
        signature=payload.signature,
        msg_timestamp=msg_ts,
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)

    logger.info(
        f"[NETWORK] Encrypted message arrived: "
        f"sender={current_user.username!r} (ID: {current_user.user_id}) -> "
        f"recipient={recipient.username!r} (ID: {recipient.user_id})"
    )
    logger.info(
        f"[NETWORK] Incoming Payload: "
        f"ciphertext={payload.ciphertext[:20]}... "
        f"nonce={payload.nonce} "
        f"signature={payload.signature[:20]}..."
    )
    logger.debug(
        f"[NETWORK] Payload Details | "
        f"Msg ID: {msg.id} | "
        f"Ciphertext: {msg.ciphertext[:32]}... | "
        f"Nonce: {msg.nonce} | "
        f"Signature: {msg.signature[:32]}..."
    )

    # ── 5. Real-time WebSocket push (best-effort) ─────────────────────────────
    # Prepare the exact data structure being sent to the recipient
    ws_payload = {
        "type":            "new_message",
        "id":              msg.id,
        "sender_id":       current_user.user_id,
        "recipient_id":    payload.recipient_id,
        "sender_username": current_user.username,
        "ciphertext":      msg.ciphertext,
        "nonce":           msg.nonce,
        "signature":       msg.signature,
        "timestamp":       msg_ts.isoformat(),
        "received_at":     msg.received_at.isoformat(),
        "delivered_at":    None,
        "read_at":         None,
    }

    logger.info(f"[NETWORK] WebSocket SEND to {recipient.username!r}: {ws_payload}")
    
    ws_delivered = await manager.send_to_user(payload.recipient_id, ws_payload)
    
    logger.info(
        f"[NETWORK] WebSocket relay to {recipient.username!r}: "
        f"{'SUCCESS (Delivered)' if ws_delivered else 'QUEUED (User offline)'}"
    )

    return {"message_id": msg.id, "status": "queued", "ws_delivered": ws_delivered}


@router.get(
    "",
    response_model=List[MessageResponse],
    summary="Fetch all pending encrypted messages for the caller",
)
async def get_messages(
    after_id: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user),
):
    """
    Return encrypted messages addressed to the caller.

    If [after_id] is provided, only messages with ID > after_id are returned.
    This allows the caller to sync their local history without redownloading
    past messages.
    """
    messages = (
        db.query(DBMessage)
        .filter(
            or_(
                DBMessage.recipient_id == current_user.user_id,
                DBMessage.sender_id == current_user.user_id
            ),
            DBMessage.id > after_id
        )
        .order_by(DBMessage.id.asc())
        .limit(limit)
        .all()
    )
    logger.debug(
        f"Fetched {len(messages)} messages for {current_user.username!r}"
    )

    result = []
    for m in messages:
        sender = db.query(DBUser).filter(DBUser.user_id == m.sender_id).first()
        result.append(MessageResponse(
            id=m.id,
            sender_id=m.sender_id,
            recipient_id=m.recipient_id,
            sender_username=sender.username if sender else m.sender_id,
            ciphertext=m.ciphertext,
            nonce=m.nonce,
            signature=m.signature,
            timestamp=m.msg_timestamp,
            received_at=m.received_at,
            delivered_at=m.delivered_at,
            read_at=m.read_at,
        ))
    return result


@router.patch(
    "/{message_id}/status",
    response_model=MessageResponse,
    summary="Update message status (delivered/read)",
)
async def update_message_status(
    message_id: int,
    is_read: bool = False,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user),
):
    """
    Mark a message as delivered or read.
    Recipient only.
    """
    msg = db.query(DBMessage).filter(
        DBMessage.id == message_id,
        DBMessage.recipient_id == current_user.user_id,
    ).first()

    if not msg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )

    now = datetime.now(timezone.utc)
    if not msg.delivered_at:
        msg.delivered_at = now

    if is_read and not msg.read_at:
        msg.read_at = now

    db.commit()
    db.refresh(msg)

    logger.info(
        f"[STATUS SYNC] Receipt updated: Msg {msg.id} | "
        f"Recipient ({current_user.username!r}) confirmed: "
        f"{'READ' if is_read else 'DELIVERED'}"
    )

    # Re-fetch sender for the response
    sender = db.query(DBUser).filter(DBUser.user_id == msg.sender_id).first()

    return MessageResponse(
        id=msg.id,
        sender_id=msg.sender_id,
        recipient_id=msg.recipient_id,
        sender_username=sender.username if sender else msg.sender_id,
        ciphertext=msg.ciphertext,
        nonce=msg.nonce,
        signature=msg.signature,
        timestamp=msg.msg_timestamp,
        received_at=msg.received_at,
        delivered_at=msg.delivered_at,
        read_at=msg.read_at,
    )


@router.delete(
    "/{message_id}",
    response_model=AckResponse,
    summary="Acknowledge receipt and delete a message from the relay",
)
async def delete_message(
    message_id: int,
    db: Session = Depends(get_db),
    current_user: DBUser = Depends(get_current_user),
):
    """
    Delete a message after the client has decrypted it locally.
    """
    msg = db.query(DBMessage).filter(
        DBMessage.id == message_id,
        DBMessage.recipient_id == current_user.user_id,
    ).first()

    if not msg:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Message not found",
        )

    db.delete(msg)
    db.commit()
    logger.info(f"Message {message_id} deleted by {current_user.username!r}")
    return AckResponse(deleted=True, message_id=message_id)
