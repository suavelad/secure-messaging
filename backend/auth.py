from fastapi import Request, HTTPException, Depends
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from .database import SessionLocal, DBUser

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def verify_ed25519_signature(request: Request, db: Session = Depends(get_db)):
    """
    Intercepts the request, extracts the X-Sender-ID and X-Signature headers,
    and verifies the payload cryptographically.
    """
    sender_id = request.headers.get("X-Sender-ID")
    signature_hex = request.headers.get("X-Signature")

    if not sender_id or not signature_hex:
        raise HTTPException(status_code=401, detail="Missing Authentication Headers")

    # Fetch the user's trusted public key from our database
    user = db.query(DBUser).filter(DBUser.user_id == sender_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Sender not registered")

    try:
        public_key = serialization.load_pem_public_key(user.identity_key_pub.encode())
        signature = bytes.fromhex(signature_hex)
        
        # Read the raw request body to verify the signature
        body = await request.body()
        
        # Verify the signature
        public_key.verify(signature, body)
    except InvalidSignature:
        raise HTTPException(status_code=403, detail="Invalid cryptographic signature")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Authentication error: {str(e)}")

    return sender_id # Pass the authenticated user_id down to the route