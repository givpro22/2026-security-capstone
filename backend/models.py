from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    # Long-term X25519 identity public key (base64). Used by all 3 protocols.
    public_key = Column(String, nullable=True)
    # Signal-only: signed prekey + signature, base64.
    signed_prekey = Column(String, nullable=True)
    signed_prekey_sig = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    messages_sent = relationship(
        "Message", foreign_keys="Message.sender_id", back_populates="sender"
    )
    messages_received = relationship(
        "Message", foreign_keys="Message.recipient_id", back_populates="recipient"
    )
    prekeys = relationship("PreKey", back_populates="owner")


class PreKey(Base):
    """Signal one-time prekey (OPK). Consumed on first fetch."""

    __tablename__ = "prekeys"

    id = Column(Integer, primary_key=True, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    key_id = Column(Integer, nullable=False)
    public_key = Column(String, nullable=False)  # base64
    consumed = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="prekeys")


class Message(Base):
    """Opaque envelope. Server stores the JSON payload but never reads it."""

    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    protocol = Column(String, nullable=False, default="static")  # static | noise | signal
    payload = Column(Text, nullable=False)  # JSON-encoded, protocol-specific
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    delivered = Column(Integer, default=0)

    sender = relationship("User", foreign_keys=[sender_id], back_populates="messages_sent")
    recipient = relationship(
        "User", foreign_keys=[recipient_id], back_populates="messages_received"
    )
