# Secure Messenger (CMU InfoSec Prototype)

This repository contains a world-class, Zero-Knowledge End-to-End Encrypted (E2EE) messaging system. It features a high-fidelity React frontend and a FastAPI-based cryptographic logic layer.

## 🛡️ Security Architecture
The system follows a **Zero-Knowledge** philosophy:
*   **Untrusted Relay (Port 8000)**: A backend that routes encrypted packets but possesses NO keys. It enforces **Ed25519 signature verification** on every request to prevent identity spoofing.
*   **Logic App (Port 8001)**: A local client service that handles X25519/ECDH handshakes, HKDF key derivation, and AES-256-GCM encryption. It stores keys in an encrypted SQLite vault (`*_local.db`).
*   **Aurora-Sleek Frontend (Port 3000)**: A high-fidelity "Command Center" that visualizes the cryptographic lifecycle in real-time.

---

## 🚀 Getting Started

### 1. Environment Setup
Clone the repository and install Python dependencies.
```bash
# Set up virtual environment
make setup-env
source venv/bin/activate

# Install core dependencies
pip install cryptography fastapi uvicorn sqlalchemy pydantic httpx
```

### 2. Frontend Setup
Install Node dependencies for the React application.
```bash
cd frontend
npm install
```

---

## 🛠️ Running the Full Stack

To experience the full E2EE flow, you need to run three components simultaneously.

### Step 1: Start the Untrusted Relay (Port 8000)
This acts as the global internet routing layer.
```bash
make start-server
```

### Step 2: Start the Logic App (Port 8001)
This handles the local cryptographic heavy lifting.
```bash
python app_server.py
```

### Step 3: Start the UI (Port 3000)
Launch the interactive command center.
```bash
cd frontend
npm run dev
```

---

## 💎 Features & Capabilities

### 🔐 Zero-Knowledge Identity
*   **Signup**: Generates unique Ed25519 (Identity) and X25519 (Ephemeral) keypairs.
*   **Local Vault**: Keys are encrypted at rest using **PBKDF2HMAC** derivation from your master password.
*   **Public Key Pinning**: Public keys are registered with the relay during the first signup to prevent Man-in-the-Middle (MITM) attacks.

### 📡 Secure Communication
*   **Peer Discovery**: Real-time directory of all registered nodes on the network.
*   **Handshake Visualization**: View the shared secrets and session keys generated for each active peer.
*   **Notifications**: Red-badge alerting for inbound encrypted traffic from background contacts.

### 🧪 Diagnostics & Audit
*   **Forensics Panel**: Bit-level transparency into the X25519 shared secrets and AES-GCM nonces.
*   **Live Trace**: A telemetry log of all local and network-level security events.

---

## 🧹 Resetting the Environment
To wipe all identities and start a fresh security audit:
1. Stop all running servers.
2. Run the reset command:
   ```bash
   make reset
   ```
   *This deletes all local vaults (`*.db`) and clears the relay state.*


flutter build apk --release
