# MiniTLS Chat — Mutual-Authentication Client/Server Chat

A multi-user chat application whose connection is secured by a **custom, fully-visible handshake protocol ("MiniTLS")** with **mutual authentication**: the client verifies the server *and* the server verifies the client, using X.509 certificates. Every step — ClientHello, ServerHello, key exchange, certificate exchange, signatures, Finished, encrypted records — is printed to the terminal so you can see exactly what happens behind the scenes.

> **Why not just use Python's `ssl` module?** `ssl` performs the handshake inside OpenSSL and hides it. For an assignment about *how* the handshake works, we implement the protocol ourselves (TLS 1.3-inspired) on top of raw TCP sockets, using the audited `cryptography` package only for primitives (X25519, RSA, AES-GCM, HKDF, X.509). **Do not use MiniTLS in production** — use real TLS.

---

## 1. Quick start

```bash
pip install -r requirements.txt        # only dependency: cryptography

python gen_certs.py                    # 1) create CA + server + client certificates

python server.py                       # 2) terminal 1 - server
python client.py --name bob            # 3) terminal 2 - client "bob"
python client.py --name alice          # 4) terminal 3 - client "alice"
```

Type in a client terminal to chat. Commands: `/who`, `/quit`.
Add `--quiet` to `server.py` / `client.py` to hide the handshake internals.

Run the automated test (starts everything itself, checks good and bad clients):

```bash
python test_e2e.py
```

### Attack demos (should all be REJECTED)

| Command | What it simulates | Who rejects it | Why |
|---|---|---|---|
| `python client.py --name mallory` | Forged client certificate (issued by an attacker's CA that copies our CA's *name*) | **Server** | CA signature on the certificate does not verify |
| `python client.py --name olduser` | Genuine but **expired** certificate | **Server** | Outside validity period |
| `python client.py --name alice --server-name evil.com` | Client connects expecting a different host (impersonation / wrong server) | **Client** | Hostname not in server cert's SAN |
| Client without any certificate | Anonymous client | **Server** | Cannot produce Certificate / CertificateVerify |

Watch the `✔` / `✘` lines in the terminal output.

---

## 2. Project structure

| File | Purpose |
|---|---|
| `minitls.py` | **The protocol**: message framing, certificate validation, signatures, key schedule, AEAD record layer, `server_handshake()`, `client_handshake()` |
| `server.py` | Multi-threaded chat server; authenticates every client, relays encrypted chat |
| `client.py` | Chat client; handshake, then send/receive thread |
| `gen_certs.py` | Builds the mini-PKI: root CA, server cert, alice, bob, and two *bad* certs (mallory, olduser) |
| `logutil.py` | Coloured step-by-step logging |
| `test_e2e.py` | Automated end-to-end test |
| `certs/` | Generated keys + certificates (created by `gen_certs.py`) |

---

## 3. Architecture

```
            ┌──────────────────────────────┐
            │  MiniTLS Root CA (ca.crt)    │   Both sides trust ONLY this CA.
            └──────────────┬───────────────┘   It signed: server.crt, alice.crt, bob.crt
        signs              │              signs
      ┌────────────────────┴───────────────────────┐
      ▼                                            ▼
┌───────────┐            TCP :5555            ┌───────────┐
│  CLIENT   │ ◀════ MiniTLS handshake ══════▶ │  SERVER   │
│ alice.crt │ ◀═══ AES-256-GCM records ═════▶ │ server.crt│
│ alice.key │                                 │ server.key│
└───────────┘                                 └───────────┘
```

Layers inside each program:

1. **TCP socket** – raw bytes.
2. **Framing** – every message = 4-byte length + payload.
3. **Handshake layer** – plaintext JSON messages (so you can read them), all recorded in a *transcript*.
4. **Record layer** – after the handshake every message is AEAD-encrypted (AES-256-GCM or ChaCha20-Poly1305).
5. **Chat application** – JSON `{"type":"chat","text":"…"}` inside the encrypted records.

---

## 4. The handshake, message by message

```
 CLIENT                                                         SERVER
   │  1. ClientHello  {version, client_random, cipher_suites,     │
   │                   client X25519 public key}                  │
   │ ───────────────────────────────────────────────────────────▶ │
   │  2. ServerHello  {server_random, chosen suite,               │
   │                   server X25519 public key}                  │
   │ ◀─────────────────────────────────────────────────────────── │
   │      ╔═══ 3. KEY EXCHANGE (nothing sent!) ═══╗               │
   │      ║ both compute shared = X25519(priv,pub) ║               │
   │      ║ then derive master + 6 keys via HKDF   ║               │
   │      ╚════════════════════════════════════════╝               │
   │  4. Certificate  {server X.509}                              │
   │ ◀─────────────────────────────────────────────────────────── │  client validates it
   │  5. CertificateRequest  {accepted CA}   ← makes it MUTUAL    │
   │ ◀─────────────────────────────────────────────────────────── │
   │  6. CertificateVerify  {sign(transcript hash)}               │
   │ ◀─────────────────────────────────────────────────────────── │  client verifies signature
   │  7. Certificate  {client X.509}                              │
   │ ───────────────────────────────────────────────────────────▶ │  server validates it
   │  8. CertificateVerify  {sign(transcript hash)}               │
   │ ───────────────────────────────────────────────────────────▶ │  server verifies signature
   │  9a. Finished [ENCRYPTED] HMAC(client_fin_key, transcript)   │
   │ ───────────────────────────────────────────────────────────▶ │
   │  9b. Finished [ENCRYPTED] HMAC(server_fin_key, transcript)   │
   │ ◀─────────────────────────────────────────────────────────── │
   │══════════ AES-GCM encrypted chat records ══════════════════ │
```

### What each step does and why it exists

| # | Message | Contents | Purpose / what attack it stops |
|---|---|---|---|
| 1 | **ClientHello** | 32-byte `client_random`, list of cipher suites, client's **ephemeral** X25519 public key | Starts the session; the random value makes every handshake unique (**replay protection**); offers ciphers for **negotiation** |
| 2 | **ServerHello** | `server_random`, chosen suite, server's ephemeral X25519 public key | Completes negotiation and Diffie–Hellman |
| 3 | **Key exchange** | *No message* — each side computes `X25519(my_private, peer_public)` | Both get the **same shared secret** without ever sending it. Because keys are ephemeral → **forward secrecy** |
| 4 | **Certificate** (server) | Server's X.509 cert (public key + identity + CA signature) | Tells the client who the server claims to be |
| 5 | **CertificateRequest** | Name of accepted CA | The server *demands* a client certificate → this is what makes authentication **mutual** |
| 6 | **CertificateVerify** (server) | RSA-PSS signature over hash of *all messages so far* | Certificates are public, anybody can copy one. Only the private-key owner can sign. Since the hash includes both ephemeral keys, the signature **binds the key exchange to the server's identity → stops man-in-the-middle** |
| 7 | **Certificate** (client) | Client's X.509 cert | Client identity for the server |
| 8 | **CertificateVerify** (client) | Signature over transcript hash | Client proves it owns the private key (a stolen *certificate* alone is useless) |
| 9 | **Finished** ×2 | `HMAC(finished_key, transcript_hash)` sent **encrypted** | Confirms both sides derived identical keys and saw identical handshake bytes → **detects tampering/downgrade** of any earlier message |

### Certificate validation (performed by both sides, on the peer's cert)

1. **Issuer** equals the trusted CA's name.
2. **CA signature** on the certificate body verifies with the CA's public key ← *this is the real trust decision*. (This is why `mallory` fails even though its issuer name looks right.)
3. **Validity period** – not expired, not yet valid.
4. **Extended Key Usage** – server cert must allow `serverAuth`, client cert must allow `clientAuth`.
5. **Hostname** (client checks server only) – expected name is in the Subject Alternative Name.

---

## 5. Key schedule (how keys are made)

```
shared_secret  = X25519(my_ephemeral_private, peer_ephemeral_public)      (32 B, same on both sides)
master_secret  = HMAC-SHA256( key = client_random ‖ server_random, msg = shared_secret )   # HKDF-Extract
each key       = HKDF-Expand( master_secret, info = "MiniTLS " + label, length )           # HKDF-Expand
```

| Key | Size | Used for |
|---|---|---|
| `client_write_key` / `server_write_key` | 32 B | AEAD encryption client→server / server→client |
| `client_write_iv` / `server_write_iv` | 12 B | Base value for per-record nonces |
| `client_finished_key` / `server_finished_key` | 32 B | HMAC for Finished messages |

Separate keys per direction ⇒ a message can't be reflected back to its sender.

## 6. Record layer (encrypted chat)

```
nonce      = write_iv  XOR  sequence_number (96-bit)          # unique for every record
aad        = "MiniTLS" ‖ sequence_number (64-bit)
record     = AES-256-GCM-Encrypt(key, nonce, plaintext, aad)   # ciphertext ‖ 16-byte auth tag
```

* **Confidentiality** – ciphertext is unreadable without the key.
* **Integrity + authenticity** – the GCM tag detects any modified bit (`InvalidTag`).
* **Replay / reorder / drop protection** – the sequence number is baked into nonce and AAD; a replayed or reordered record fails to decrypt.

The server log shows, for every message: the encrypted bytes on the wire, the decrypted plaintext, and the re-encryption for each recipient.

---

## 7. Security properties achieved

| Property | How |
|---|---|
| Server authentication | Server cert chained to CA + CertificateVerify signature |
| **Client authentication** | Client cert chained to CA + CertificateVerify signature (server requests it) |
| Identity cannot be spoofed in chat | Server labels messages with the **CN from the verified certificate**, not with anything the client types |
| Confidentiality | AES-256-GCM / ChaCha20-Poly1305 |
| Integrity | AEAD tags, transcript-bound signatures, Finished MACs |
| Forward secrecy | Ephemeral X25519 per connection; long-term RSA keys only *sign* |
| Replay protection | Random nonces in Hellos, sequence numbers in records |
| MITM protection | Signature over transcript that contains both ephemeral public keys |
| Downgrade protection | Cipher-suite lists are part of the signed/MAC'd transcript |

