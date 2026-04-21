import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

class CryptoEngine:
    @staticmethod
    def compute_shared_secret(my_private_x25519, peer_public_x25519):
        """Step 1: Compute ECDH shared secret using my private and their public key."""
        return my_private_x25519.exchange(peer_public_x25519)

    @staticmethod
    def derive_session_key(shared_secret):
        """Step 2: Pass the raw shared secret through HKDF to get a strong 256-bit AES key."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32, # 32 bytes = 256 bits for AES-256
            salt=None, # In a full system, salt would be dynamically negotiated
            info=b"secure_messaging_session_key"
        )
        return hkdf.derive(shared_secret)

    @staticmethod
    def encrypt_message(session_key, plaintext: bytes):
        """Step 3: Encrypt the message using AES-256-GCM."""
        aesgcm = AESGCM(session_key)
        nonce = os.urandom(12) # GCM strictly requires a 12-byte random nonce (IV)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
        return nonce, ciphertext

    @staticmethod
    def decrypt_message(session_key, nonce, ciphertext: bytes):
        """Decrypts an AES-256-GCM message."""
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data=None)

    @staticmethod
    def sign_payload(my_private_ed25519, payload: bytes):
        """Signs the ciphertext to prove who sent it."""
        return my_private_ed25519.sign(payload)

    @staticmethod
    def verify_signature(peer_public_ed25519, signature: bytes, payload: bytes):
        """Verifies the signature on a payload. Returns True if valid, False otherwise."""
        try:
            peer_public_ed25519.verify(signature, payload)
            return True
        except InvalidSignature:
            return False