"""
WebSocket endpoint for real-time message push notifications.

The mobile client connects on login and maintains a persistent WebSocket
so new messages are delivered instantly instead of requiring polling.

Connection URL
--------------
    ws(s)://server/ws/{user_id}?token=<access_token>

Server → Client frames (JSON)
------------------------------
    {"type": "connected",   "user_id": "..."}          handshake ACK
    {"type": "new_message", "id": …, "ciphertext": …}  incoming message push
    {"type": "pong"}                                    keepalive reply

Client → Server frames (text)
------------------------------
    "ping"   triggers a "pong" response to keep the connection alive

Authentication
--------------
The JWT access token is validated BEFORE the WebSocket handshake is accepted.
An invalid / expired token closes the socket with code 4001.
"""
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from loguru import logger
from sqlalchemy.orm import Session

from auth import verify_access_token
from database import DBUser, SessionLocal
from ws_manager import manager

router = APIRouter(tags=["WebSocket"])


@router.websocket("/ws/{user_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    user_id: str,
    token: str = Query(..., description="Valid JWT access token"),
):
    """
    Establish a real-time WebSocket channel for the authenticated user.

    The endpoint:
      1. Validates the JWT token (rejects before accepting the socket).
      2. Looks up the user in the database.
      3. Registers the connection in the in-process ConnectionManager.
      4. Listens for keepalive "ping" frames from the client.
      5. Cleans up the registration on disconnect or error.
    """
    # ── Step 1: Authenticate BEFORE accepting the socket ─────────────────────
    payload = verify_access_token(token)
    if not payload or payload.get("sub") != user_id:
        logger.warning(f"WS auth rejected  user_id={user_id!r}")
        await websocket.close(code=4001, reason="Unauthorized")
        return

    # ── Step 2: Verify user account exists and is active ─────────────────────
    db: Session = SessionLocal()
    try:
        user = db.query(DBUser).filter(
            DBUser.user_id == user_id,
            DBUser.is_active.is_(True),
        ).first()
    finally:
        db.close()

    if not user:
        logger.warning(f"WS rejected — user not found  user_id={user_id!r}")
        await websocket.close(code=4004, reason="User not found")
        return

    # ── Step 3: Register connection and start session ─────────────────────────
    await manager.connect(user_id, websocket)
    logger.info(f"WS session opened  user={user.username!r}")

    try:
        # Confirm successful connection to the client
        await websocket.send_json({"type": "connected", "user_id": user_id})

        # Keep the connection alive; process keepalive frames
        while True:
            text = await websocket.receive_text()
            if text.strip().lower() == "ping":
                await websocket.send_json({"type": "pong"})
                logger.debug(f"WS keepalive  user={user.username!r}")

    except WebSocketDisconnect as exc:
        logger.info(
            f"WS session closed  user={user.username!r}  code={exc.code}"
        )
    except Exception as exc:
        logger.warning(f"WS error  user={user.username!r}: {exc}")
    finally:
        # Always clean up the registry entry on exit
        manager.disconnect(user_id)
