from fastapi import FastAPI, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from .database import Base, engine, get_db, DBUser, DBMessage
from .schemas import UserRegisterRequest, MessagePayload
from .auth import verify_ed25519_signature

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Zero-Knowledge Message Relay")

@app.post("/register")
def register_user(request: UserRegisterRequest, db: Session = Depends(get_db)):
    """Registers a user's public keys. (In a full system, this request itself would be self-signed)."""
    if db.query(DBUser).filter(DBUser.user_id == request.user_id).first():
        raise HTTPException(status_code=400, detail="User already exists")
    
    new_user = DBUser(**request.dict())
    db.add(new_user)
    db.commit()
    return {"status": "User registered successfully"}

@app.get("/keys/{user_id}")
def get_user_keys(user_id: str, db: Session = Depends(get_db)):
    """Allows anyone to fetch a user's public keys to start a secure session."""
    user = db.query(DBUser).filter(DBUser.user_id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"identity_key_pub": user.identity_key_pub, "pre_key_pub": user.pre_key_pub}

@app.post("/messages")
async def send_message(
    payload: MessagePayload, 
    request: Request,
    db: Session = Depends(get_db), 
    sender_id: str = Depends(verify_ed25519_signature) # Auth enforced here!
):
    """Stores an encrypted blob for offline users. MUST be signed."""
    msg = DBMessage(
        sender_id=sender_id,
        recipient_id=payload.recipient_id,
        ciphertext=payload.ciphertext,
        nonce=payload.nonce,
        signature=request.headers.get("X-Signature")
    )
    db.add(msg)
    db.commit()
    return {"status": "Message securely queued"}

# @app.get("/messages")
# def get_my_messages(db: Session = Depends(get_db), user_id: str = Depends(verify_ed25519_signature)):
#     """Fetches messages. The requester's ID is guaranteed by the signature."""
#     messages = db.query(DBMessage).filter(DBMessage.recipient_id == user_id).all()
#     # In a real queue, we would delete them here after fetching
#     return [{"sender_id": m.sender_id, "ciphertext": m.ciphertext, "nonce": m.nonce} for m in messages]

@app.get("/messages")
def get_my_messages(db: Session = Depends(get_db), user_id: str = Depends(verify_ed25519_signature)):
    """Fetches messages. The requester's ID is guaranteed by the signature."""
    messages = db.query(DBMessage).filter(DBMessage.recipient_id == user_id).all()
    
    return [{"id": m.id, "sender_id": m.sender_id, "ciphertext": m.ciphertext, "nonce": m.nonce} for m in messages]

@app.delete("/messages/{message_id}")
def delete_message(message_id: int, db: Session = Depends(get_db), user_id: str = Depends(verify_ed25519_signature)):
    """Deletes a message after the client successfully downloads it."""
    msg = db.query(DBMessage).filter(DBMessage.id == message_id, DBMessage.recipient_id == user_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found")
    db.delete(msg)
    db.commit()
    return {"status": "Message securely deleted from relay"}

@app.get("/users")
def list_users(db: Session = Depends(get_db)):
    """Returns a list of all registered users on the relay."""
    users = db.query(DBUser).all()
    return [u.user_id for u in users]