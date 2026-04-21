from pydantic import BaseModel

class UserRegisterRequest(BaseModel):
    user_id: str
    identity_key_pub: str
    pre_key_pub: str

class MessagePayload(BaseModel):
    recipient_id: str
    ciphertext: str
    nonce: str