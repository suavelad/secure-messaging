from core.key_manager import KeyManager
from core.crypto_engine import CryptoEngine
from core.local_storage import SecureStorage
from cryptography.hazmat.primitives import serialization

def run_milestone():
    print("--- Phase 1: Local Cryptography & Secure Storage Initialization ---\n")
    
    # 1. Initialize our secure encrypted database
    storage = SecureStorage(db_path="test_device.db")
    
    # 2. ALICE generates her keys
    print("[*] Generating Alice's Keys...")
    alice_id_priv, alice_id_pub = KeyManager.generate_identity_keypair()
    alice_pre_priv, alice_pre_pub = KeyManager.generate_prekey_pair()
    
    # 3. BOB generates his keys
    print("[*] Generating Bob's Keys...")
    bob_id_priv, bob_id_pub = KeyManager.generate_identity_keypair()
    bob_pre_priv, bob_pre_pub = KeyManager.generate_prekey_pair()

    # (Demonstrating Secure Storage: Alice saves her private pre-key to DB)
    storage.save_private_key("alice_pre_key", KeyManager.serialize_private_key(alice_pre_priv))
    
    print("\n--- Alice is preparing to send a message to Bob ---")
    plaintext_message = b"Top secret blueprint for the new IoT project."
    print(f"Plaintext: {plaintext_message.decode()}")

    # 4. ALICE: Computes shared secret using her Private Pre-Key and Bob's Public Pre-Key
    shared_secret_alice = CryptoEngine.compute_shared_secret(alice_pre_priv, bob_pre_pub)
    session_key_alice = CryptoEngine.derive_session_key(shared_secret_alice)

    # 5. ALICE: Encrypts the message and signs the ciphertext to prove identity
    nonce, ciphertext = CryptoEngine.encrypt_message(session_key_alice, plaintext_message)
    signature = CryptoEngine.sign_payload(alice_id_priv, ciphertext)
    
    print(f"[+] Message Encrypted! Ciphertext length: {len(ciphertext)} bytes")
    print(f"[+] Signature generated! Length: {len(signature)} bytes")

    # ----- THE UNTRUSTED NETWORK -----
    # Imagine `nonce`, `ciphertext`, and `signature` are transmitted over the internet here.
    # ---------------------------------

    print("\n--- Bob receives the message ---")
    
    # 6. BOB: Verifies that Alice actually sent this (Authentication / Non-repudiation)
    is_valid = CryptoEngine.verify_signature(alice_id_pub, signature, ciphertext)
    if not is_valid:
        print("[-] Alert: Signature verification failed. Message dropped.")
        return
    print("[+] Signature Verified: The sender is definitely Alice.")

    # 7. BOB: Computes the exact same shared secret using his Private Pre-Key and Alice's Public Pre-Key
    shared_secret_bob = CryptoEngine.compute_shared_secret(bob_pre_priv, alice_pre_pub)
    session_key_bob = CryptoEngine.derive_session_key(shared_secret_bob)

    # 8. BOB: Decrypts the message
    decrypted_message = CryptoEngine.decrypt_message(session_key_bob, nonce, ciphertext)
    print(f"[+] Decrypted Message: {decrypted_message.decode()}\n")

    print("Phase 1 Milestone: SUCCESS! Cryptography stack is functioning perfectly.")

if __name__ == "__main__":
    run_milestone()