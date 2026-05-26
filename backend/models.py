from datetime import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    # X25519 public key, base64 encoded. Set after the client generates a keypair.
    public_key = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    messages_sent = relationship(
        "Message", foreign_keys="Message.sender_id", back_populates="sender"
    )
    messages_received = relationship(
        "Message", foreign_keys="Message.recipient_id", back_populates="recipient"
    )


class Message(Base):
    """Stores ciphertext only — server cannot read message contents."""

    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ciphertext = Column(Text, nullable=False)
    nonce = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    delivered = Column(Integer, default=0)

    sender = relationship("User", foreign_keys=[sender_id], back_populates="messages_sent")
    recipient = relationship(
        "User", foreign_keys=[recipient_id], back_populates="messages_received"
    )
