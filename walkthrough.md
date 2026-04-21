# Secure Messenger UI Walkthrough

I have implemented a premium React-based frontend and a Python-based Client API layer to help you demonstrate the E2EE (End-to-End Encryption) features of the system.

## 🚀 How to Run

The following services have been started and are running in the background:

1.  **Backend Relay (Port 8000)**: The untrusted server that routes encrypted messages.
2.  **Logic API (Port 8001)**: The Python service (`app_server.py`) that uses the project's `core/` security modules to perform local encryption/decryption.
3.  **Frontend (Port 3000)**: The React dashboard (`http://localhost:3000`).

### Dashboard Access
Open your browser to: **[http://localhost:3000](http://localhost:3000)**

---

## 🔒 Showing the Security Implementation

The new UI is specifically designed to "show the security implementation" through the **Security Engine** sidebar on the right.

### 1. Zero-Knowledge Initialization
When you "Sign In" with a username (e.g., `alice`) and a master password:
- The system checks for a local encrypted database (`alice_local.db`).
- It uses the master password with PBKDF2 to pull your private keys.
- **Visual Evidence:** Look at the "Cryptographic Logs" in the sidebar to see the keys being loaded or generated.

### 2. E2EE Handshake & Verification
When sending a message to `bob`:
1.  The client fetches Bob's public keys from the relay.
2.  It performs an **X25519 ECDH exchange** to compute a shared secret.
3.  It derives an **AES-256 session key** using HKDF.
4.  It encrypts the message and signs it with **Ed25519**.
- **Visual Evidence:** The **Active Session Context** card in the UI will update to show the raw shared secret, derived session key, and the unique nonce for that specific message.

### 3. Verification & Decryption
When `bob` logs in and checks his inbox:
1.  The UI shows the incoming "encrypted blob".
2.  The "Security Engine" logs will show the local decryption process using Bob's matching shared secret.
3.  Once decrypted, a `DELETE` request is sent to the relay to ensure forward secrecy/cleanup.

---

## 📂 New Files Created
- [app_server.py](file:///Users/sunday/Documents/CMU/InfoSec/secure-messenger-cmu/app_server.py): The logic API.
- [frontend/](file:///Users/sunday/Documents/CMU/InfoSec/secure-messenger-cmu/frontend/): The React application source code.
- [frontend/src/App.jsx](file:///Users/sunday/Documents/CMU/InfoSec/secure-messenger-cmu/frontend/src/App.jsx): The main UI logic.
