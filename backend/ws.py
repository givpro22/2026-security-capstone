import json
from typing import Dict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session

from auth import decode_token
from database import SessionLocal
from models import Message, User

router = APIRouter()


class ConnectionManager:
    def __init__(self) -> None:
        self.active: Dict[int, WebSocket] = {}

    async def connect(self, user_id: int, ws: WebSocket) -> None:
        await ws.accept()
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
            "protocol": msg.protocol,
            "payload": json.loads(msg.payload),
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

                msg_type = data.get("type")
                to_username = data.get("to")
                if not to_username:
                    await ws.send_text(json.dumps({"type": "error", "detail": "missing 'to'"}))
                    continue

                recipient = db.query(User).filter(User.username == to_username).first()
                if not recipient:
                    await ws.send_text(
                        json.dumps({"type": "error", "detail": "recipient not found"})
                    )
                    continue

                if msg_type == "handshake":
                    # Live-relay only (no DB persist). Used for Noise XX.
                    relay = {
                        "type": "handshake",
                        "from": user.username,
                        "protocol": data.get("protocol"),
                        "stage": data.get("stage"),
                        "payload": data.get("payload"),
                    }
                    delivered = await manager.send_to(recipient.id, relay)
                    await ws.send_text(json.dumps({
                        "type": "handshake-ack",
                        "to": recipient.username,
                        "stage": data.get("stage"),
                        "delivered": delivered,
                    }))
                    continue

                if msg_type != "message":
                    await ws.send_text(json.dumps({"type": "error", "detail": "unknown type"}))
                    continue

                protocol = data.get("protocol", "static")
                payload_obj = data.get("payload")
                if payload_obj is None:
                    await ws.send_text(
                        json.dumps({"type": "error", "detail": "missing payload"})
                    )
                    continue

                msg = Message(
                    sender_id=user.id,
                    recipient_id=recipient.id,
                    protocol=protocol,
                    payload=json.dumps(payload_obj),
                )
                db.add(msg)
                db.commit()
                db.refresh(msg)

                out = {
                    "type": "message",
                    "id": msg.id,
                    "from": user.username,
                    "protocol": protocol,
                    "payload": payload_obj,
                    "created_at": msg.created_at.isoformat(),
                }
                delivered = await manager.send_to(recipient.id, out)
                if delivered:
                    msg.delivered = 1
                    db.commit()

                await ws.send_text(
                    json.dumps(
                        {
                            "type": "sent",
                            "id": msg.id,
                            "to": recipient.username,
                            "protocol": protocol,
                            "created_at": msg.created_at.isoformat(),
                        }
                    )
                )
        except WebSocketDisconnect:
            pass
    finally:
        manager.disconnect(user_id, ws)
        db.close()
