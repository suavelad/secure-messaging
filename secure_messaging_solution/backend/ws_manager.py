"""
WebSocket connection manager.

Maintains a live registry of authenticated WebSocket connections keyed by
user_id.  When a new message arrives for an online user, the message router
calls send_to_user() to deliver it instantly without polling.

For multi-process deployments (e.g. Gunicorn with multiple workers), replace
the in-process dict with a Redis pub/sub channel so all workers share the
connection state.
"""
import asyncio
from typing import Dict

from fastapi import WebSocket
from loguru import logger


class ConnectionManager:
    """
    Thread-safe WebSocket registry.

    Lifecycle:
        1. connect(user_id, ws)      — accept socket and register user
        2. send_to_user(user_id, {}) — push JSON payload to an online user
        3. disconnect(user_id)       — unregister (called on disconnect / error)
    """

    def __init__(self) -> None:
        # user_id → active WebSocket
        self._connections: Dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()

    async def connect(self, user_id: str, websocket: WebSocket) -> None:
        """Accept and register a WebSocket connection."""
        async with self._lock:
            # Single Device Enforcement: If the user is already connected 
            # (e.g. from another device), close the old connection first.
            if user_id in self._connections:
                logger.info(f"[WS] User {user_id!r} connecting from a new session. Closing previous connection.")
                old_ws = self._connections.pop(user_id)
                try:
                    await old_ws.close(code=1008, reason="New login detected on another device")
                except:
                    pass

            await websocket.accept()
            self._connections[user_id] = websocket
        
        logger.info(
            f"WS connected   user_id={user_id!r}  "
            f"total={len(self._connections)}"
        )

    def disconnect(self, user_id: str) -> None:
        """Unregister a connection (idempotent — safe to call multiple times)."""
        self._connections.pop(user_id, None)
        logger.info(
            f"WS disconnected user_id={user_id!r}  "
            f"total={len(self._connections)}"
        )

    async def send_to_user(self, user_id: str, data: dict) -> bool:
        """
        Push a JSON payload to the user's WebSocket.

        Returns True if successfully delivered; False if the user is offline
        or if the send fails (in which case the connection is cleaned up).
        The caller should not error on False — messages are persisted to the
        database regardless and the client can poll on reconnect.
        """
        ws = self._connections.get(user_id)
        if ws is None:
            logger.debug(f"WS push skipped — {user_id!r} not connected")
            return False
        try:
            await ws.send_json(data)
            logger.debug(f"WS push delivered → {user_id!r}")
            return True
        except Exception as exc:
            logger.warning(f"WS push failed for {user_id!r}: {exc}")
            self.disconnect(user_id)
            return False

    def is_online(self, user_id: str) -> bool:
        """Check if a user is currently connected via WebSocket."""
        return user_id in self._connections

    @property
    def connected_count(self) -> int:
        """Number of currently connected users."""
        return len(self._connections)


# Module-level singleton — imported by routers that need to push messages
manager = ConnectionManager()
