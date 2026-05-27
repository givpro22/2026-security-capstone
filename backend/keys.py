from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models import PreKey, User

router = APIRouter(prefix="/keys", tags=["keys"])


class PublicKeyUpload(BaseModel):
    public_key: str = Field(min_length=40, max_length=128)


class PublicKeyResponse(BaseModel):
    username: str
    public_key: str


class SignedPreKeyUpload(BaseModel):
    signed_prekey: str
    signed_prekey_sig: str


class OneTimePreKey(BaseModel):
    key_id: int
    public_key: str


class PreKeyBundleUpload(BaseModel):
    one_time_prekeys: List[OneTimePreKey] = Field(default_factory=list)


class PreKeyBundleResponse(BaseModel):
    username: str
    identity_key: str
    signed_prekey: str
    signed_prekey_sig: str
    one_time_prekey: Optional[OneTimePreKey] = None


@router.post("/me")
def upload_my_public_key(
    body: PublicKeyUpload,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    current.public_key = body.public_key
    db.commit()
    return {"ok": True}


@router.post("/me/signed-prekey")
def upload_signed_prekey(
    body: SignedPreKeyUpload,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    current.signed_prekey = body.signed_prekey
    current.signed_prekey_sig = body.signed_prekey_sig
    db.commit()
    return {"ok": True}


@router.post("/me/one-time-prekeys")
def upload_one_time_prekeys(
    body: PreKeyBundleUpload,
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Replace the user's full OPK set. The client always uploads the current
    # localStorage state, so any pre-existing rows (consumed or not) are stale —
    # keeping them around would let the server hand out an OPK whose matching
    # private key the client no longer has, which then fails X3DH on the
    # responder side.
    db.query(PreKey).filter(PreKey.owner_id == current.id).delete()
    db.commit()
    for opk in body.one_time_prekeys:
        db.add(PreKey(owner_id=current.id, key_id=opk.key_id, public_key=opk.public_key))
    db.commit()
    return {"ok": True, "added": len(body.one_time_prekeys)}


@router.get("/me/one-time-prekey-count")
def my_opk_count(
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    n = (
        db.query(PreKey)
        .filter(PreKey.owner_id == current.id, PreKey.consumed == False)  # noqa: E712
        .count()
    )
    return {"available": n}


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


@router.get("/{username}/bundle", response_model=PreKeyBundleResponse)
def get_prekey_bundle(
    username: str,
    _current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch a Signal prekey bundle. Consumes one OPK if available."""
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.public_key or not user.signed_prekey:
        raise HTTPException(status_code=404, detail="User has no Signal prekeys")

    opk_row = (
        db.query(PreKey)
        .filter(PreKey.owner_id == user.id, PreKey.consumed == False)  # noqa: E712
        .order_by(PreKey.id.asc())
        .first()
    )
    opk = None
    if opk_row:
        opk = OneTimePreKey(key_id=opk_row.key_id, public_key=opk_row.public_key)
        opk_row.consumed = True
        db.commit()

    return PreKeyBundleResponse(
        username=user.username,
        identity_key=user.public_key,
        signed_prekey=user.signed_prekey,
        signed_prekey_sig=user.signed_prekey_sig,
        one_time_prekey=opk,
    )


@router.get("")
def list_users(
    current: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    users = (
        db.query(User)
        .filter(User.public_key.isnot(None))
        .filter(User.id != current.id)
        .all()
    )
    return [{"username": u.username, "public_key": u.public_key} for u in users]
