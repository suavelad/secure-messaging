from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

class KeyManager:
    @staticmethod
    def generate_identity_keypair():
        """Generates an Ed25519 keypair for long-term identity and signing."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def generate_prekey_pair():
        """Generates an X25519 keypair for Diffie-Hellman key exchange."""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_private_key(private_key):
        """Converts a private key object into safely storable bytes."""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() 
            # Note: We use NoEncryption here because our local_storage.py 
            # will handle the actual AES-GCM database encryption layer.
        )

    @staticmethod
    def serialize_public_key(public_key):
        """Converts a public key object into bytes for network sharing."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def deserialize_private_key(pem_bytes):
        """Loads a private key object from bytes."""
        return serialization.load_pem_private_key(pem_bytes, password=None)

    @staticmethod
    def deserialize_public_key(pem_bytes):
        """Loads a public key object from bytes."""
        return serialization.load_pem_public_key(pem_bytes)