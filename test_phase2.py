import httpx
import json
import time
from core.key_manager import KeyManager
from core.crypto_engine import CryptoEngine

API_URL = "http://127.0.0.1:8000"

def run_tests():
    print("--- Phase 2: Testing Untrusted Backend API ---\n")
    
    # 1. Generate keys for test user 'alice_test'
    test_user_id = f"alice_{int(time.time())}"
    print(f"[*] Generating keys for {test_user_id}...")
    a_id_priv, a_id_pub = KeyManager.generate_identity_keypair()
    a_pre_priv, a_pre_pub = KeyManager.generate_prekey_pair()
    
    a_id_pub_pem = KeyManager.serialize_public_key(a_id_pub).decode()
    a_pre_pub_pem = KeyManager.serialize_public_key(a_pre_pub).decode()

    with httpx.Client() as client:
        # 2. Register Alice
        print("[*] Registering Alice with the directory server...")
        reg_data = {"user_id": test_user_id, "identity_key_pub": a_id_pub_pem, "pre_key_pub": a_pre_pub_pem}
        # Ignore 400 if already exists from a previous run
        client.post(f"{API_URL}/register", json=reg_data) 
        
        # 3. Create a payload
        payload = {
            "recipient_id": "bob_test",
            "ciphertext": "deadbeef1234", # Dummy ciphertext
            "nonce": "abcdef"
        }
        json_body = json.dumps(payload).encode()

        # 4. Sign the payload exactly as the server expects
        signature = CryptoEngine.sign_payload(a_id_priv, json_body)
        headers = {
            "X-Sender-ID": test_user_id,
            "X-Signature": signature.hex(),
            "Content-Type": "application/json"
        }

        # 5. Send Valid Request
        print("\n[*] Sending properly signed message...")
        response = client.post(f"{API_URL}/messages", content=json_body, headers=headers)
        print(f"Server Response (Should be 200 OK): {response.status_code} - {response.text}")

        # 6. Send Forged Request (Tampered body)
        print("\n[*] ATTEMPTING ATTACK: Modifying payload after signing (MITM/Forgery)...")
        forged_payload = {
            "recipient_id": "bob_test",
            "ciphertext": "malicious_data", 
            "nonce": "abcdef"
        }
        forged_json_body = json.dumps(forged_payload).encode()
        
        # We use the valid signature from earlier, but attach it to tampered data
        response_forged = client.post(f"{API_URL}/messages", content=forged_json_body, headers=headers)
        print(f"Server Response (Should be 403 Forbidden): {response_forged.status_code} - {response_forged.text}")

if __name__ == "__main__":
    run_tests()