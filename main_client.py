import sys
from core.key_manager import KeyManager
from core.crypto_engine import CryptoEngine
from core.local_storage import SecureStorage
from core.network_client import NetworkClient

API_URL = "http://127.0.0.1:8000"

class SecureMessengerApp:
    def __init__(self, username, password):
        self.username = username
        self.storage = SecureStorage(db_path=f"{username}_local.db", password=password.encode())
        self.network = None
        self.id_priv = None
        self.pre_priv = None
        self._initialize_user()

    def _initialize_user(self):
        """Loads keys from encrypted storage, or generates and registers them if new."""
        raw_id_priv = self.storage.load_private_key("identity_key")
        raw_pre_priv = self.storage.load_private_key("pre_key")

        if raw_id_priv and raw_pre_priv:
            print("[*] Keys found in secure local storage. Loading...")
            self.id_priv = KeyManager.deserialize_private_key(raw_id_priv)
            self.pre_priv = KeyManager.deserialize_private_key(raw_pre_priv)
        else:
            print("[*] New device detected. Generating keys...")
            self.id_priv, id_pub = KeyManager.generate_identity_keypair()
            self.pre_priv, pre_pub = KeyManager.generate_prekey_pair()
            
            self.storage.save_private_key("identity_key", KeyManager.serialize_private_key(self.id_priv))
            self.storage.save_private_key("pre_key", KeyManager.serialize_private_key(self.pre_priv))
            
            # Temporary network client to register keys
            temp_net = NetworkClient(API_URL, self.username, self.id_priv)
            print(f"[*] Registering {self.username} with the directory server...")
            temp_net.register_keys(
                KeyManager.serialize_public_key(id_pub).decode(),
                KeyManager.serialize_public_key(pre_pub).decode()
            )
            print("[+] Device securely provisioned.")

        # Initialize the persistent network client
        self.network = NetworkClient(API_URL, self.username, self.id_priv)

    def send_message(self):
        peer_id = input("\nEnter recipient username: ")
        message_text = input("Enter message: ").encode()

        # 1. Fetch Peer's Public Keys
        res = self.network.get_peer_keys(peer_id)
        if res.status_code != 200:
            print(f"[-] Could not find user '{peer_id}'.")
            return
            
        peer_keys = res.json()
        peer_pre_pub = KeyManager.deserialize_public_key(peer_keys["pre_key_pub"].encode())

        # 2. Cryptographic operations (E2EE)
        shared_secret = CryptoEngine.compute_shared_secret(self.pre_priv, peer_pre_pub)
        session_key = CryptoEngine.derive_session_key(shared_secret)
        nonce, ciphertext = CryptoEngine.encrypt_message(session_key, message_text)

        # 3. Network Upload
        send_res = self.network.send_message(peer_id, ciphertext.hex(), nonce.hex())
        if send_res.status_code == 200:
            print("[+] Message Encrypted and Sent!")
        else:
            print(f"[-] Failed to send: {send_res.text}")

    def check_inbox(self):
        print("\n[*] Polling for messages...")
        res = self.network.fetch_my_messages()
        messages = res.json()
        
        if not messages:
            print("[-] Inbox is empty.")
            return

        print(f"[+] Found {len(messages)} pending messages!")
        for msg in messages:
            sender_id = msg["sender_id"]
            ciphertext = bytes.fromhex(msg["ciphertext"])
            nonce = bytes.fromhex(msg["nonce"])
            
            # 1. Fetch Sender's Public Keys to complete the handshake
            peer_res = self.network.get_peer_keys(sender_id)
            peer_pre_pub = KeyManager.deserialize_public_key(peer_res.json()["pre_key_pub"].encode())
            
            # 2. Cryptographic operations (E2EE)
            shared_secret = CryptoEngine.compute_shared_secret(self.pre_priv, peer_pre_pub)
            session_key = CryptoEngine.derive_session_key(shared_secret)
            
            try:
                plaintext = CryptoEngine.decrypt_message(session_key, nonce, ciphertext)
                print(f"\n[Message from {sender_id}]: {plaintext.decode()}")
                
                # 3. Cleanup: Acknowledge and delete from untrusted server
                self.network.acknowledge_message(msg["id"])
            except Exception as e:
                print(f"\n[-] Failed to decrypt message from {sender_id}: {e}")

    def run(self):
        while True:
            print("\n--- SECURE MESSENGER ---")
            print("1. Send a Message")
            print("2. Check Inbox")
            print("3. Exit")
            choice = input("Select an option: ")
            
            if choice == "1": self.send_message()
            elif choice == "2": self.check_inbox()
            elif choice == "3": break
            else: print("Invalid choice.")

if __name__ == "__main__":
    print("Welcome to SecureMessenger")
    user = input("Username: ")
    pwd = input("Master Password: ")
    app = SecureMessengerApp(user, pwd)
    app.run()