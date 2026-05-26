import json
from typing import Dict

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from auth import decode_token
from database import SessionLocal
from models import Message, User

router = APIRouter()


class ConnectionManager:
    """Tracks live WebSocket connections by user_id.

    For 1:1 chat: when A sends a message addressed to B,
    if B is connected we relay; otherwise the ciphertext is stored
    in the DB for later delivery on B's next connect."""

    def __init__(self) -> None:
        self.active: Dict[int, WebSocket] = {}

    async def connect(self, user_id: int, ws: WebSocket) -> None:
        await ws.accept()
        # If the same user opens a second tab, drop the older socket.
        existing = self.active.get(user_id)
        if existing is not None:
            try:
                await existing.close()
            except Exception:
                pass
        self.active[user_id] = ws

    def disconnect(self, user_id: int, ws: WebSocket) -> None:
        if self.active.get(user_id) is ws:
            self.active.pop(user_id, None)

    async def send_to(self, user_id: int, payload: dict) -> bool:
        ws = self.active.get(user_id)
        if ws is None:
            return False
        try:
            await ws.send_text(json.dumps(payload))
            return True
        except Exception:
            self.active.pop(user_id, None)
            return False


manager = ConnectionManager()


async def _flush_pending(user: User, db: Session) -> None:
    """Send any queued (undelivered) messages to the newly-connected user."""
    pending = (
        db.query(Message)
        .filter(Message.recipient_id == user.id, Message.delivered == 0)
        .order_by(Message.created_at.asc())
        .all()
    )
    for msg in pending:
        sender = db.query(User).filter(User.id == msg.sender_id).first()
        payload = {
            "type": "message",
            "id": msg.id,
            "from": sender.username if sender else "?",
            "ciphertext": msg.ciphertext,
            "nonce": msg.nonce,
            "created_at": msg.created_at.isoformat(),
        }
        if await manager.send_to(user.id, payload):
            msg.delivered = 1
    db.commit()


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: str):
    payload = decode_token(token)
    if not payload:
        await ws.close(code=4401)
        return

    user_id = int(payload["sub"])
    db: Session = SessionLocal()
    try:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            await ws.close(code=4401)
            return

        await manager.connect(user_id, ws)
        await _flush_pending(user, db)

        try:
            while True:
                raw = await ws.receive_text()
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    await ws.send_text(json.dumps({"type": "error", "detail": "invalid json"}))
                    continue

                if data.get("type") != "message":
                    await ws.send_text(json.dumps({"type": "error", "detail": "unknown type"}))
                    continue

                to_username = data.get("to")
                ciphertext = data.get("ciphertext")
                nonce = data.get("nonce")
                if not (to_username and ciphertext and nonce):
                    await ws.send_text(
                        json.dumps({"type": "error", "detail": "missing fields"})
                    )
                    continue

                recipient = db.query(User).filter(User.username == to_username).first()
                if not recipient:
                    await ws.send_text(
                        json.dumps({"type": "error", "detail": "recipient not found"})
                    )
                    continue

                # Persist ciphertext. Server never sees plaintext.
                msg = Message(
                    sender_id=user.id,
                    recipient_id=recipient.id,
                    ciphertext=ciphertext,
                    nonce=nonce,
                )
                db.add(msg)
                db.commit()
                db.refresh(msg)

                out = {
                    "type": "message",
                    "id": msg.id,
                    "from": user.username,
                    "ciphertext": ciphertext,
                    "nonce": nonce,
                    "created_at": msg.created_at.isoformat(),
                }
                delivered = await manager.send_to(recipient.id, out)
                if delivered:
                    msg.delivered = 1
                    db.commit()

                # Echo back to sender so its UI can render its own message.
                await ws.send_text(
                    json.dumps(
                        {
                            "type": "sent",
                            "id": msg.id,
                            "to": recipient.username,
                            "created_at": msg.created_at.isoformat(),
                        }
                    )
                )
        except WebSocketDisconnect:
            pass
    finally:
        manager.disconnect(user_id, ws)
        db.close()
