from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import User

router = APIRouter(prefix="/keys", tags=["keys"])


class PublicKeyUpload(BaseModel):
    # base64-encoded 32-byte X25519 public key
    public_key: str = Field(min_length=40, max_length=128)


class PublicKeyResponse(BaseModel):
    username: str
    public_key: str


@router.post("/me")
def upload_my_public_key(
    body: PublicKeyUpload,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Client uploads its X25519 public key after generating a keypair locally.
    The private key never leaves the client."""
    current.public_key = body.public_key
    db.commit()
    return {"ok": True}


@router.get("/{username}", response_model=PublicKeyResponse)
def get_public_key(
    username: str,
    _current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.public_key:
        raise HTTPException(status_code=404, detail="Public key not found")
    return PublicKeyResponse(username=user.username, public_key=user.public_key)


@router.get("")
def list_users(
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all users that have published a public key (potential chat partners)."""
    users = (
        db.query(User)
        .filter(User.public_key.isnot(None))
        .filter(User.id != current.id)
        .all()
    )
    return [{"username": u.username, "public_key": u.public_key} for u in users]
