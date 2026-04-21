import sqlite3
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class SecureStorage:
    def __init__(self, db_path="local_secure.db", password=b"super_secret_master_password"):
        self.db_path = db_path
        
        # In production, the salt is randomly generated and stored alongside the DB.
        # Hardcoding salt here just for the Phase 1 prototype demonstration.
        salt = b"static_demo_salt" 
        
        # Derive a 256-bit Database Master Key from the user's password
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
        self.db_master_key = kdf.derive(password)
        
        self._initialize_db()

    def _initialize_db(self):
        """Creates the tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS keys 
                          (id TEXT PRIMARY KEY, encrypted_priv_key BLOB)''')
        conn.commit()
        conn.close()

    def _encrypt_data(self, data: bytes):
        """Encrypts data before writing to SQLite."""
        aesgcm = AESGCM(self.db_master_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext # Prepend nonce for easy extraction

    def _decrypt_data(self, encrypted_data: bytes):
        """Decrypts data read from SQLite."""
        aesgcm = AESGCM(self.db_master_key)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        return aesgcm.decrypt(nonce, ciphertext, None)

    def save_private_key(self, key_id: str, raw_private_key_bytes: bytes):
        """Safely stores a private key."""
        encrypted_key = self._encrypt_data(raw_private_key_bytes)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("REPLACE INTO keys (id, encrypted_priv_key) VALUES (?, ?)", 
                       (key_id, encrypted_key))
        conn.commit()
        conn.close()

    def load_private_key(self, key_id: str):
        """Retrieves and decrypts a private key."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT encrypted_priv_key FROM keys WHERE id=?", (key_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return self._decrypt_data(row[0])
        return None