import httpx
import json
from .crypto_engine import CryptoEngine

class NetworkClient:
    def __init__(self, base_url, user_id, identity_priv_key):
        self.base_url = base_url
        self.user_id = user_id
        self.identity_priv_key = identity_priv_key

    def _make_signed_request(self, method, endpoint, payload_dict=None):
        """Automatically signs the payload to authenticate with the server."""
        headers = {"X-Sender-ID": self.user_id}
        content = b""
        
        if payload_dict is not None:
            content = json.dumps(payload_dict).encode()
            headers["Content-Type"] = "application/json"
            
        # Sign the raw body (empty bytes for GET/DELETE, JSON bytes for POST)
        signature = CryptoEngine.sign_payload(self.identity_priv_key, content)
        headers["X-Signature"] = signature.hex()

        url = f"{self.base_url}{endpoint}"
        with httpx.Client() as client:
            if method == "GET":
                return client.get(url, headers=headers)
            elif method == "POST":
                return client.post(url, headers=headers, content=content)
            elif method == "DELETE":
                return client.delete(url, headers=headers)

    def register_keys(self, id_pub_pem: str, pre_pub_pem: str):
        payload = {"user_id": self.user_id, "identity_key_pub": id_pub_pem, "pre_key_pub": pre_pub_pem}
        return self._make_signed_request("POST", "/register", payload)

    def get_peer_keys(self, peer_id: str):
        return self._make_signed_request("GET", f"/keys/{peer_id}")

    def send_message(self, recipient_id: str, ciphertext_hex: str, nonce_hex: str):
        payload = {"recipient_id": recipient_id, "ciphertext": ciphertext_hex, "nonce": nonce_hex}
        return self._make_signed_request("POST", "/messages", payload)

    def fetch_my_messages(self):
        return self._make_signed_request("GET", "/messages")

    def acknowledge_message(self, message_id: int):
        return self._make_signed_request("DELETE", f"/messages/{message_id}")