# SecureMessenger — Full Implementation Reference

> Zero-knowledge, end-to-end encrypted messaging platform.  
> Backend: FastAPI (Python) · Mobile client: Flutter (Dart)

---

## Table of Contents

1. [System Architecture](#1-system-architecture)
2. [Cryptographic Primitives](#2-cryptographic-primitives)
3. [Registration (Sign Up)](#3-registration-sign-up)
4. [Login](#4-login)
5. [Sending a Message](#5-sending-a-message)
6. [Receiving a Message](#6-receiving-a-message)
7. [Session Management & Token Lifecycle](#7-session-management--token-lifecycle)
8. [Anti-Replay Protection](#8-anti-replay-protection)
9. [Security Properties Summary](#9-security-properties-summary)
10. [Real-World Scenario: Alice and Bob](#10-real-world-scenario-alice-and-bob)
11. [Threat Model](#11-threat-model)
12. [Logging & Observability](#12-logging--observability)
13. [Offline Storage & Data Persistence](#13-offline-storage--data-persistence)

---

## 1. System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Mobile Client (Flutter)                       │
│                                                                       │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────────┐ │
│  │  KeyManager  │   │ CryptoEngine │   │    SecureLocalStorage    │ │
│  │              │   │              │   │                          │ │
│  │ Ed25519 keys │   │ X25519 ECDH  │   │  flutter_secure_storage  │ │
│  │ X25519 keys  │   │ HKDF-SHA256  │   │  (Keystore / Keychain)   │ │
│  │              │   │ AES-256-GCM  │   │                          │ │
│  └──────┬───────┘   │ Ed25519 sign │   └─────────────┬────────────┘ │
│         │           └──────┬───────┘                 │              │
│         │                  │                         ▼              │
│         │                  │            ┌──────────────────────────┐ │
│         └──────────────────┘            │    MessageStorage        │ │
│                      │                  │  (Encrypted local vault)  │ │
│                      │                  └──────────────────────────┘ │
│                      │ Only ciphertext leaves the device             │
└──────────────────────┼──────────────────────────────────────────────┘
                        │  HTTPS / WSS
                        │  + X-Nonce header (UUID4)
                        │  + X-Timestamp header (Unix epoch)
                        │  + Authorization: Bearer <JWT>
                        ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     FastAPI Relay (Python)                           │
│                                                                       │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │  Auth Router    │  │  Anti-Replay │  │   Message Router     │   │
│  │                 │  │  Middleware  │  │                      │   │
│  │ /auth/register  │  │              │  │ Ed25519 sig verify   │   │
│  │ /auth/login     │  │ Nonce cache  │  │ Store ciphertext     │   │
│  │ /auth/refresh   │  │ Timestamp ±5m│  │ WebSocket push       │   │
│  └─────────────────┘  └──────────────┘  └──────────────────────┘   │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  SQLite Database (WAL mode)                                 │    │
│  │  users · messages · refresh_tokens                          │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

**Key design principle:** The relay is _zero-knowledge_. It stores only ciphertext and cannot decrypt any message. All cryptographic operations happen exclusively on the mobile device.

---

## 2. Cryptographic Primitives

| Primitive       | Purpose                        | Details                                      |
| --------------- | ------------------------------ | -------------------------------------------- |
| **Ed25519**     | Message signing & verification | 32-byte public key, 64-byte signature        |
| **X25519**      | ECDH key agreement             | 32-byte public key, 32-byte shared secret    |
| **HKDF-SHA256** | Key derivation                 | Info string: `secure_messaging_session_key`  |
| **AES-256-GCM** | Symmetric encryption           | 12-byte nonce, 16-byte authentication tag    |
| **Argon2id**    | Password hashing               | 64 MiB memory · 3 iterations · 4 parallelism |
| **JWT (HS256)** | Access tokens                  | 15-minute TTL                                |
| **SHA-256**     | Refresh token storage          | Raw token never written to DB                |

### Key storage locations

| Platform    | Storage backend                                       |
| ----------- | ----------------------------------------------------- |
| Android     | EncryptedSharedPreferences (hardware-backed Keystore) |
| iOS / macOS | Keychain Services                                     |

Private keys are **generated on-device and never transmitted** under any circumstance.

### Local Data Protection (Idle)

When messages are stored locally on the device (offline cache), they are kept in their **original encrypted format** (AES-GCM ciphertext). Additionally, the entire message history database is encrypted with a device-specific local key stored in the hardware-backed Keychain.

---

## 3. Registration (Sign Up)

### Flow diagram

```
Mobile                                    Backend
  │                                          │
  │  1. Generate Ed25519 identity keypair    │
  │  2. Generate X25519 prekey pair          │
  │  3. Store BOTH private keys in           │
  │     Keystore / Keychain                  │
  │                                          │
  │──── POST /auth/register ───────────────▶ │
  │     {                                    │
  │       username,                          │
  │       password,          (plaintext)     │
  │       identity_key_pub,  (base64 Ed25519)│
  │       pre_key_pub        (base64 X25519) │
  │     }                                    │
  │     + X-Nonce: <uuid4>                   │
  │     + X-Timestamp: <unix_epoch>          │
  │                                          │
  │                          4. Argon2id hash password
  │                          5. Store user + public keys
  │                          6. Issue JWT access token (15 min)
  │                          7. Issue refresh token (7 days)
  │                             Store SHA-256(refresh_token) in DB
  │                                          │
  │◀─── 201 Created ────────────────────────│
  │     {                                    │
  │       user_id,                           │
  │       username,                          │
  │       access_token,                      │
  │       refresh_token                      │
  │     }                                    │
  │                                          │
  │  8. Save tokens + userId in Keychain     │
  │  9. Connect WebSocket                    │
 10. Navigate → Home screen               │
```

### What the backend stores for each user

```sql
users (
  user_id        TEXT PRIMARY KEY,   -- UUID4
  username       TEXT UNIQUE,
  password_hash  TEXT,               -- Argon2id hash, never the plaintext
  identity_key_pub TEXT,             -- base64 Ed25519 public key (32 bytes)
  pre_key_pub    TEXT                -- base64 X25519 public key  (32 bytes)
)
```

The backend **never** sees the private keys. It only stores the public halves needed for other users to perform ECDH and to verify signatures.

### Password security

Argon2id configuration:

```python
passlib.hash.argon2.using(
    memory_cost = 65536,   # 64 MiB — forces GPU/ASIC to use real memory
    time_cost   = 3,       # 3 iterations
    parallelism = 4,       # 4 parallel threads
)
```

A password cracker that can test 1 billion MD5 hashes/second would need **~1,000 years** to brute-force a single Argon2id hash with these parameters.

---

## 4. Login

### Flow diagram

```
Mobile                                    Backend
  │                                          │
  │──── POST /auth/login ──────────────────▶ │
  │     { username, password }               │
  │     + X-Nonce + X-Timestamp              │
  │                                          │
  │                          1. Look up user by username
  │                          2. Argon2id.verify(password, stored_hash)
  │                             (If user not found, run verify() anyway
  │                              on a dummy hash to prevent timing attacks)
  │                          3. Issue new access token + refresh token
  │                                          │
  │◀─── 200 OK ─────────────────────────────│
  │     { access_token, refresh_token, ... } │
  │                                          │
  │  3. Load private keys from Keychain      │
  │  4. Save new tokens in Keychain          │
  │  5. Connect WebSocket                    │
  6. Navigate → Home screen               │
```

### Logout Behavior

To support seamless transitions without compromising security, logging out of the application **only invalidates the network session tokens**. The cryptographic identity and pre-keys are preserved in the Hardware Keystore/Keychain. This ensures that:

1. A user can log back in and immediately decrypt their existing message history.
2. The user's device remains their "trusted identity" as long as they possess the physical hardware.

A "Factory Reset" option (available in Settings) is required to wipe the cryptographic identity keys entirely.

### Timing attack prevention

If a username does not exist, the backend still calls `argon2.verify()` on a dummy hash string. This ensures the response time is identical whether the user exists or not, preventing an attacker from enumerating valid usernames by measuring response latency.

```python
# backend/routers/auth.py
if db_user is None:
    # Run a dummy verification to consume the same CPU time
    argon2.verify("dummy_plaintext", DUMMY_HASH)
    raise HTTPException(status_code=401, detail="Invalid credentials")
```

---

## 5. Sending a Message

This is the most security-critical flow. Every step happens entirely on the sender's device.

### Full encryption pipeline

```
Sender's device
─────────────────────────────────────────────────────────
 plaintext = "Hello Bob"

 Step 1 ── X25519 ECDH ──────────────────────────────────
   shared_secret = X25519(
       my_prekey_private,         ← stored in Keychain, never leaves device
       recipient_prekey_public    ← fetched from relay (public, safe to fetch)
   )
   ↓ 32-byte shared secret

 Step 2 ── HKDF-SHA256 ──────────────────────────────────
   session_key = HKDF(
       ikm  = shared_secret,
       info = "secure_messaging_session_key",
       len  = 32
   )
   ↓ 256-bit AES session key

 Step 3 ── AES-256-GCM encryption ───────────────────────
   nonce     = random 12 bytes
   secretBox = AES-256-GCM(session_key, plaintext, nonce)
   combined  = secretBox.cipherText ‖ secretBox.mac   ← 16-byte GCM tag appended
   ↓
   ciphertext_hex = hex(combined)
   nonce_hex      = hex(nonce)

 Step 4 ── Ed25519 signature ─────────────────────────────
   unix_ts      = str(unix_epoch_seconds)
   signed_data  = UTF8( ciphertext_hex + nonce_hex + unix_ts )
   signature    = Ed25519.sign(identity_private_key, signed_data)
   signature_hex = hex(signature)   ← 64 bytes
─────────────────────────────────────────────────────────

Sent to relay:
  POST /messages
  {
    recipient_id:   "bob-uuid",
    ciphertext_hex: "a3f9...",
    nonce_hex:      "b1c2...",
    signature_hex:  "d4e5...",
    timestamp:      "2026-04-18T14:32:00Z"
  }
```

### Backend validation on receipt

Before storing the message, the relay runs three checks:

1. **Recipient exists** — rejects messages to unknown users
2. **Timestamp window** — message timestamp must be within ±5 minutes of server time, preventing old messages from being re-injected
3. **Ed25519 signature** — verifies `signature_hex` over `ciphertext_hex + nonce_hex + unix_ts` using the sender's public identity key stored at registration

If any check fails, the message is rejected with 400/403 and is never stored.

---

## 6. Receiving a Message

### Real-time delivery via WebSocket

```
Backend                                   Recipient's device
  │                                          │
  │  Message stored for Bob                  │
  │──── WS push {type:"new_message", ...} ─▶│
  │                                          │
  │                          1. Fetch sender's public keys from cache
  │                             (or relay if not cached)
  │                                          │
  │                          2. Verify Ed25519 signature
  │                             payload = ciphertext_hex + nonce_hex + unix_ts
  │                             Ed25519.verify(sender_identity_pub, sig, payload)
  │                             → FAIL: show "⚠ Signature invalid" warning
  │                             → PASS: proceed to decrypt
  │                                          │
  │                          3. X25519 ECDH
  │                             shared_secret = X25519(
  │                                 my_prekey_private,
  │                                 sender_prekey_public
  │                             )
  │                             ← Same value as sender computed (ECDH commutativity)
  │                                          │
  │                          4. HKDF-SHA256
  │                             session_key = same 256-bit key as sender derived
  │                                          │
  │                          5. AES-256-GCM decrypt
  │                             cipherText = combined[:-16]
  │                             mac        = combined[-16:]
  │                             plain = AES-256-GCM⁻¹(session_key, nonce, cipherText, mac)
  │                             → GCM tag mismatch: drop message silently
  │                             → OK: display plaintext
  │                                          │
  │◀─── DELETE /messages/{id} ─────────────│
  │  Forward deletion: ciphertext removed    │
  │  from relay immediately after decryption │
```

### ECDH commutativity — why both parties get the same key

```
Alice computes:  X25519(alice_priv, bob_pub)   = shared_secret
Bob computes:    X25519(bob_priv,   alice_pub)  = shared_secret  ← identical

The shared secret is mathematically identical without ever being transmitted.
An eavesdropper who captures both public keys cannot derive it without a
private key (Computational Diffie-Hellman assumption).
```

### Forward deletion

Once the recipient's device successfully decrypts a message, it immediately calls `DELETE /messages/{id}`. The relay removes the ciphertext. This limits the relay's exposure window — even if the relay database is later compromised, messages that have already been delivered are gone.

---

## 7. Session Management & Token Lifecycle

### Access token (JWT, 15 minutes)

```
Header:  { "alg": "HS256", "typ": "JWT" }
Payload: { "sub": "<user_id>", "exp": <unix_ts + 900> }
Signed with: HMAC-SHA256(JWT_SECRET)
```

Every API request carries `Authorization: Bearer <access_token>`. The backend validates the signature and expiry on every call with no database lookup.

### Refresh token (7 days)

When an access token expires (HTTP 401), the mobile client automatically:

```
Mobile                           Backend
  │── POST /auth/refresh ──────▶ │
  │   { refresh_token: "..." }   │
  │                              │  1. SHA-256(token) → look up in DB
  │                              │  2. Check not revoked, not expired
  │                              │  3. Revoke old refresh token
  │                              │  4. Issue new access token + new refresh token
  │◀─ { access_token, refresh } ─│
  │                              │
  │  Save new tokens in Keychain │
  │  Retry original request      │
```

**Token rotation:** every refresh call invalidates the previous refresh token and issues a new one. A stolen refresh token can therefore only be used once before it is invalidated.

**Secure storage:** The raw refresh token is never written to the database. Only `SHA-256(token)` is stored. A full database dump does not expose any live tokens.

---

## 8. Anti-Replay Protection

Every protected API call must include two headers:

```
X-Nonce:     550e8400-e29b-41d4-a716-446655440000   ← UUID4, never reused
X-Timestamp: 1745000000                              ← Unix epoch seconds
```

The server enforces:

```
1. abs(server_time - X-Timestamp) ≤ 300 seconds
      → Rejects requests with old or future timestamps

2. X-Nonce not seen before (within the 300-second window)
      → Rejects exact duplicate requests
```

An attacker who captures a valid signed request cannot replay it:

- After 300 seconds, the timestamp is outside the window → **rejected**
- Within 300 seconds, the nonce is already in the server's cache → **rejected**

The nonce cache uses in-memory storage with TTL. Nonces older than 300 seconds are pruned automatically.

---

## 9. Security Properties Summary

| Property                        | Mechanism                  | Where enforced                   |
| ------------------------------- | -------------------------- | -------------------------------- |
| Confidentiality                 | AES-256-GCM encryption     | Device (send) + Device (receive) |
| Integrity                       | GCM authentication tag     | Device (receive)                 |
| Authenticity                    | Ed25519 signature          | Relay (store) + Device (receive) |
| Forward secrecy (partial)       | Per-session HKDF key       | Device                           |
| Password security               | Argon2id                   | Relay (register/login)           |
| Anti-replay                     | UUID nonce + timestamp     | Relay (all protected routes)     |
| Username enumeration prevention | Constant-time dummy verify | Relay (login)                    |
| Token theft mitigation          | Short TTL + rotation       | Relay (refresh)                  |
| DB breach token exposure        | SHA-256 hash only stored   | Relay (DB)                       |
| Private key exfiltration        | Hardware Keystore/Keychain | Device OS                        |
| Post-delivery exposure          | Forward deletion           | Relay + Device (no disk write)   |
| Network interception            | TLS (HTTPS/WSS)            | Transport layer                  |

---

## 10. Real-World Scenario: Alice and Bob

### Setup

Alice and Bob are colleagues who need to exchange sensitive project information. Both have installed SecureMessenger.

---

### Alice registers

1. Alice opens the app and taps **Create Account**.
2. On her device, two keypairs are generated silently in the background:
   - `alice_identity_priv` / `alice_identity_pub` — Ed25519
   - `alice_prekey_priv` / `alice_prekey_pub` — X25519
3. Both private keys are written to her phone's Keychain. They never leave it.
4. The registration request is sent to the relay:
   ```json
   {
     "username": "alice",
     "password": "my-strong-password",
     "identity_key_pub": "base64(alice_identity_pub)",
     "pre_key_pub": "base64(alice_prekey_pub)"
   }
   ```
5. The relay hashes the password with Argon2id and stores the public keys.
6. Alice receives a JWT and is taken to the home screen.

Bob goes through the same process on his own device.

---

### Alice sends Bob a message

Alice selects Bob from the contact list and types: _"The Q3 report is ready. Check the shared drive."_

**On Alice's device (invisible to the user, happens in ~50 ms):**

```
1. Fetch bob_prekey_pub from relay (public key, safe to transmit)

2. ECDH:
   shared = X25519(alice_prekey_priv, bob_prekey_pub)
            = 0x8f3a...c2d1  (32 bytes, never leaves Alice's device)

3. HKDF:
   session_key = HKDF-SHA256(shared, info="secure_messaging_session_key")
               = 0xa7b2...e9f4  (256-bit AES key)

4. Encrypt:
   nonce      = random_bytes(12)
   ciphertext = AES-256-GCM(session_key, "The Q3 report is ready...", nonce)
              = 0x3d9e...  (looks like random noise)

5. Sign:
   payload    = hex(ciphertext) + hex(nonce) + "1745000000"
   signature  = Ed25519.sign(alice_identity_priv, payload)

6. Upload to relay:
   POST /messages  { recipient: bob, ciphertext, nonce, signature, timestamp }
```

**On the relay:**

```
1. Timestamp check: abs(server_time - 1745000000) = 2s → OK
2. Signature check:
   Ed25519.verify(alice_identity_pub, signature, payload) → VALID
3. Store ciphertext in DB
4. WebSocket push to Bob if connected
```

The relay sees only random-looking bytes. It has no way to read _"The Q3 report is ready."_

---

### Bob receives the message

Bob's phone receives the WebSocket push notification.

**On Bob's device:**

```
1. Fetch alice_prekey_pub and alice_identity_pub from relay

2. Verify signature:
   payload = hex(ciphertext) + hex(nonce) + "1745000000"
   Ed25519.verify(alice_identity_pub, signature, payload) → VALID
   (If invalid: show "⚠ Signature invalid" instead of decrypting)

3. ECDH:
   shared = X25519(bob_prekey_priv, alice_prekey_pub)
          = 0x8f3a...c2d1  ← IDENTICAL to what Alice computed

4. HKDF:
   session_key = 0xa7b2...e9f4  ← IDENTICAL to Alice's key

5. Decrypt:
   plaintext = AES-256-GCM⁻¹(session_key, ciphertext, nonce)
             = "The Q3 report is ready. Check the shared drive."

6. Display message to Bob ✓

7. DELETE /messages/{id}  ← remove from relay immediately
```

---

### What an attacker sees at each layer

| Attack surface               | What the attacker captures                     | Can they read the message?                                                        |
| ---------------------------- | ---------------------------------------------- | --------------------------------------------------------------------------------- |
| Network (TLS stripped)       | `ciphertext_hex`, `nonce_hex`, `signature_hex` | **No** — AES-256-GCM, key never transmitted                                       |
| Relay database dump          | Same ciphertext + nonce + signature            | **No** — relay cannot derive session key                                          |
| Replay the same POST         | Exact same request                             | **No** — nonce already in cache, rejected within 300 s                            |
| Delay then replay            | Same request sent after 5 min                  | **No** — timestamp outside ±5 min window                                          |
| Modify ciphertext in transit | Altered bytes reach relay                      | **No** — Ed25519 sig check fails at relay, message rejected before storage        |
| Modify ciphertext in relay   | Altered bytes reach Bob                        | **No** — GCM auth tag mismatch, decryption fails; sig invalid warning shown       |
| Steal Alice's JWT            | Make API calls as Alice                        | **Limited** — can fetch ciphertext Bob hasn't deleted yet, but cannot decrypt it  |
| Steal Alice's refresh token  | Get new JWTs                                   | **Limited** — rotation means token works once, then invalidated                   |
| Full relay DB + JWT theft    | Everything the relay knows                     | **No** — cannot derive X25519 session key without Alice's or Bob's private prekey |

The only attack that succeeds is physical access to Alice's or Bob's **unlocked device**, which is outside the scope of the cryptographic security model.

---

## 11. Threat Model

### In scope (protected)

- Passive eavesdropping on the network
- Active MITM (message modification in transit)
- Compromised relay server (full DB read access)
- Replayed HTTP requests
- Brute-force attacks on passwords
- Stolen JWT tokens
- Stolen refresh tokens

### Out of scope (not protected by this system)

- Physical access to an unlocked device
- Compromise of the device OS or Keystore/Keychain
- A malicious recipient who screenshots messages after decryption
- Attacks on the TLS certificate chain (certificate pinning not implemented)
- Long-term forward secrecy (the same prekey is used for all sessions; a proper Double Ratchet would rotate keys per-message)

---

## 12. Logging & Observability

SecureMessenger implements a multi-tier logging system to provide end-to-end visibility of the cryptographic pipeline and network relay status without exposing secrets.

### Mobile Log Prefixes

| Prefix       | Category           | Description                                                                  |
| ------------ | ------------------ | ---------------------------------------------------------------------------- |
| `[CRYPTO]`   | **Cryptography**   | Plaintext before encryption, signature verification, and decryption results. |
| `[NETWORK]`  | **Networking**     | Full outgoing JSON payloads and API response statuses.                       |
| `[KEYSTORE]` | **Key Management** | Generation and loading of identity/pre-keys from secure storage.             |
| `[OFFLINE]`  | **Persistence**    | Secure message backup and retrieval from the encrypted local disk.           |
| `[SYNC]`     | **Sync**           | Real-time polling and message retrieval from the backend relay.              |

### Backend Log Groups

| Prefix       | Description                                                                          |
| ------------ | ------------------------------------------------------------------------------------ |
| `[KEY_MGMT]` | Registration of public halves and public key fetch events.                           |
| `[AUTH]`     | JWT issuance, verification, and rotation / revocation of refresh tokens.             |
| `[NETWORK]`  | End-to-side traffic: logs sender ID, recipient ID, and message arrival/relay status. |

---

## 13. Offline Storage & Data Persistence

To provide a consistent user experience during network outages, the mobile client maintains an **Encrypted Local Vault**.

### Message Persistence Flow

1. **Receipt**: An encrypted blob arrives via WebSocket or Polling.
2. **Decryption**: The message is decrypted for immediate in-memory display (`[PEER-TO-PEER]` log).
3. **Storage**: The **original raw encrypted blob** (ciphertext, nonce, signature) is written to the local disk.
4. **File Encryption**: The local vault file itself is encrypted using a local AES-256 key generated and stored in the OS Keychain.

This "Double Encryption" strategy ensures that even if an attacker gains root access to the mobile file system, they cannot read the messages without also compromising the hardware-backed Secure Enclave / Keystore.

_Generated: April 2026 · SecureMessenger v2.5_
