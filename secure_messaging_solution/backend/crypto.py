"""
Server-side cryptographic utilities.

The server's role is minimal by design (zero-knowledge relay):
  - Verify Ed25519 signatures to authenticate message senders
  - Load public keys from base64-encoded raw bytes

All symmetric encryption / decryption is performed exclusively on the client.
The server never holds or sees any private keys or plaintext.

Signature payload convention
-----------------------------
Signed bytes = UTF-8 encoding of:
    ciphertext_hex  +  nonce_hex  +  unix_timestamp_str

Binding the signature to both the ciphertext AND timestamp prevents an
attacker from reusing a valid signature on a different message or at a
different time.
"""
import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from loguru import logger


def load_ed25519_public_key(key_b64: str) -> Ed25519PublicKey:
    """
    Decode a base64-encoded raw 32-byte Ed25519 public key.

    Args:
        key_b64: Standard base64 string encoding 32 raw bytes.

    Returns:
        Ed25519PublicKey ready for signature verification.

    Raises:
        ValueError: If the decoded bytes are not 32 bytes long.
    """
    raw = base64.b64decode(key_b64)
    if len(raw) != 32:
        raise ValueError(
            f"Ed25519 public key must be 32 bytes, got {len(raw)}"
        )
    return Ed25519PublicKey.from_public_bytes(raw)


def verify_message_signature(
    identity_key_b64: str,
    signature_hex: str,
    ciphertext_hex: str,
    nonce_hex: str,
    unix_timestamp_str: str,
) -> bool:
    """
    Verify the Ed25519 signature on an encrypted message payload.

    The signed payload is (UTF-8 bytes of):
        ciphertext_hex + nonce_hex + unix_timestamp_str

    This construction binds the signature to a specific encrypted message
    at a specific time, preventing signature reuse across messages or
    timestamps.

    Args:
        identity_key_b64:    Sender's Ed25519 public key (base64 raw bytes)
        signature_hex:       Hex-encoded 64-byte Ed25519 signature
        ciphertext_hex:      Hex-encoded AES-GCM ciphertext (as uploaded)
        nonce_hex:           Hex-encoded 12-byte AES-GCM nonce
        unix_timestamp_str:  Unix epoch seconds as a decimal string

    Returns:
        True if the signature is cryptographically valid; False otherwise.
    """
    try:
        pub_key = load_ed25519_public_key(identity_key_b64)
        sig_bytes = binascii.unhexlify(signature_hex)
        # Reproduce the exact byte sequence the client signed
        payload = (ciphertext_hex + nonce_hex + unix_timestamp_str).encode("utf-8")
        pub_key.verify(sig_bytes, payload)
        return True
    except InvalidSignature:
        # Expected failure path — not an error condition
        logger.warning("Ed25519 signature verification failed: invalid signature")
        return False
    except (binascii.Error, ValueError) as exc:
        logger.warning(f"Ed25519 verification failed (malformed input): {exc}")
        return False
    except Exception as exc:
        logger.error(f"Unexpected error during signature verification: {exc}")
        return False
