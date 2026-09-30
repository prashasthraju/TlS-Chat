"""
MiniTLS - a small, readable, TLS-1.3-*inspired* protocol with MUTUAL authentication.

It is deliberately NOT real TLS: every handshake message is plain JSON so you can
watch it, and each step is logged.  Crypto primitives come from the audited
`cryptography` package - we only design the *protocol* around them.

Handshake (mutual authentication):

    Client                                            Server
    ------                                            ------
    1. ClientHello  (random, suites, X25519 pub) ───────▶
                    ◀─────── 2. ServerHello (random, suite, X25519 pub)
                         [both sides now compute ECDHE shared secret + keys]
                    ◀─────── 3. Certificate (server X.509)
                    ◀─────── 4. CertificateRequest   <-- this makes it MUTUAL
                    ◀─────── 5. CertificateVerify (server signs transcript)
    6. Certificate (client X.509) ──────────────────────▶
    7. CertificateVerify (client signs transcript) ─────▶
    8. Finished  (HMAC over transcript, ENCRYPTED) ─────▶
                    ◀─────── 9. Finished (HMAC over transcript, ENCRYPTED)
    ======== application data: AES-256-GCM records, both directions ========
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import socket
import struct

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from logutil import Log, hexv

VERSION = "MiniTLS/1.0"

# name -> (AEAD class, key length).  Server picks the first one *it* prefers
# that the client also offered (cipher-suite negotiation).
SUITES = {
    "MINITLS_X25519_RSAPSS_AES256GCM_SHA256": AESGCM,
    "MINITLS_X25519_RSAPSS_CHACHA20POLY1305_SHA256": ChaCha20Poly1305,
}
CLIENT_SUITE_PREFERENCE = list(SUITES)
SERVER_SUITE_PREFERENCE = list(SUITES)

CTX_SERVER_CV = b"MiniTLS, server CertificateVerify"
CTX_CLIENT_CV = b"MiniTLS, client CertificateVerify"


class HandshakeError(Exception):
    pass


# ───────────────────────────── helpers ─────────────────────────────────
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def send_frame(sock: socket.socket, data: bytes):
    """Wire framing: 4-byte big-endian length + payload."""
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_frame(sock: socket.socket) -> bytes:
    (n,) = struct.unpack(">I", recv_exact(sock, 4))
    if n > 1_000_000:
        raise ConnectionError("frame too large")
    return recv_exact(sock, n)


class Transcript:
    """Running record of every handshake message (raw bytes as sent on the wire).
    Signatures and Finished MACs cover its hash, so any tampering/downgrade
    of ANY earlier message is detected."""

    def __init__(self):
        self.msgs = []

    def add(self, raw: bytes):
        self.msgs.append(raw)

    def hash(self) -> bytes:
        h = hashlib.sha256()
        for m in self.msgs:
            h.update(m)
        return h.digest()


def send_msg(sock, msg: dict, transcript: Transcript) -> bytes:
    raw = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()
    send_frame(sock, raw)
    transcript.add(raw)
    return raw


def recv_msg(sock, expected: str, transcript: Transcript) -> dict:
    raw = recv_frame(sock)
    try:
        msg = json.loads(raw)
    except ValueError:
        raise HandshakeError("malformed handshake message")
    if msg.get("type") == "Alert":
        raise HandshakeError(f"peer sent ALERT: {msg.get('description')}")
    if msg.get("type") != expected:
        raise HandshakeError(f"unexpected message {msg.get('type')!r}, wanted {expected!r}")
    transcript.add(raw)
    return msg


def send_alert(sock, description: str):
    try:
        send_frame(sock, json.dumps({"type": "Alert", "description": description}).encode())
    except OSError:
        pass


# ───────────────────────────── certificates ────────────────────────────
def load_cert(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())


def load_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def cert_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def cn_of(cert) -> str:
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def not_before(cert) -> datetime.datetime:
    """Timezone-aware start of validity (works on old and new `cryptography`)."""
    if hasattr(cert, "not_valid_before_utc"):
        return cert.not_valid_before_utc
    return cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)


def not_after(cert) -> datetime.datetime:
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc
    return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def describe_cert(cert, log: Log, label: str):
    log.field(f"{label} subject", cert.subject.rfc4514_string())
    log.field(f"{label} issuer", cert.issuer.rfc4514_string())
    log.field(f"{label} valid", f"{not_before(cert):%Y-%m-%d} → {not_after(cert):%Y-%m-%d}")
    log.field(f"{label} SHA-256 fingerprint", cert.fingerprint(hashes.SHA256()).hex()[:32] + "…")


def verify_cert(cert, ca_cert, role: str, log: Log, hostname: str = None):
    """Validate a peer certificate.  `role` is 'server' or 'client'.
    Raises HandshakeError with a precise reason on any failure."""
    # 1. Issuer name must match our trusted CA
    if cert.issuer != ca_cert.subject:
        log.check("issuer matches trusted CA", False)
        raise HandshakeError(f"untrusted issuer: {cert.issuer.rfc4514_string()}")
    log.check(f"issuer == trusted CA  ({ca_cert.subject.rfc4514_string()})")

    # 2. CA's signature over the certificate body must verify (this is the real trust check)
    try:
        ca_cert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm
        )
    except InvalidSignature:
        log.check("CA signature on certificate is valid  (FORGED / not signed by our CA!)", False)
        raise HandshakeError("certificate signature was NOT made by the trusted CA (forged certificate)")
    log.check("CA signature over certificate body verifies")

    # 3. Validity period
    now = datetime.datetime.now(datetime.timezone.utc)
    if not (not_before(cert) <= now <= not_after(cert)):
        log.check(f"within validity period  (expired on {not_after(cert):%Y-%m-%d})", False)
        raise HandshakeError(f"certificate not valid now (expired {not_after(cert):%Y-%m-%d})")
    log.check("current time is inside validity period")

    # 4. Extended Key Usage must allow this role
    want = ExtendedKeyUsageOID.SERVER_AUTH if role == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        eku = []
    if want not in eku:
        log.check(f"Extended Key Usage allows {role}Auth", False)
        raise HandshakeError(f"certificate is not permitted for {role} authentication")
    log.check(f"Extended Key Usage contains {role}Auth")

    # 5. Server only: name must match what the client wanted to reach
    if role == "server" and hostname:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = san.get_values_for_type(x509.DNSName)
        if hostname not in names:
            log.check(f"hostname {hostname!r} present in SAN {names}", False)
            raise HandshakeError(f"hostname mismatch: wanted {hostname!r}, cert has {names}")
        log.check(f"hostname {hostname!r} found in SubjectAltName {names}")


# ───────────────────────────── signatures ──────────────────────────────
def _cv_payload(context: bytes, transcript_hash: bytes) -> bytes:
    # 64 spaces + context + 0x00 + hash  (same idea as TLS 1.3's CertificateVerify)
    return b"\x20" * 64 + context + b"\x00" + transcript_hash


_PSS = lambda: padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)


def sign_transcript(priv, context: bytes, th: bytes) -> bytes:
    return priv.sign(_cv_payload(context, th), _PSS(), hashes.SHA256())


def verify_transcript_sig(pub, sig: bytes, context: bytes, th: bytes):
    try:
        pub.verify(sig, _cv_payload(context, th), _PSS(), hashes.SHA256())
    except InvalidSignature:
        raise HandshakeError("CertificateVerify signature invalid - peer does not hold the private key")


# ───────────────────────────── key schedule ────────────────────────────
def derive_keys(shared: bytes, client_random: bytes, server_random: bytes):
    """shared secret -> master secret -> six independent keys.
       master = HMAC-SHA256(salt = client_random||server_random, shared)     (HKDF-Extract)
       key_x  = HKDF-Expand(master, info = "MiniTLS " + label, length)       (HKDF-Expand)"""
    master = hmac.new(client_random + server_random, shared, hashlib.sha256).digest()

    def expand(label: str, n: int) -> bytes:
        return HKDFExpand(hashes.SHA256(), n, b"MiniTLS " + label.encode()).derive(master)

    keys = {
        "c_key": expand("client write key", 32),
        "s_key": expand("server write key", 32),
        "c_iv": expand("client write iv", 12),
        "s_iv": expand("server write iv", 12),
        "c_fin": expand("client finished key", 32),
        "s_fin": expand("server finished key", 32),
    }
    return master, keys


def log_key_schedule(log: Log, shared, master, keys):
    log.field("ECDHE shared secret", hexv(shared))
    log.field("master secret", hexv(master))
    log.field("client_write_key (AEAD)", hexv(keys["c_key"]))
    log.field("server_write_key (AEAD)", hexv(keys["s_key"]))
    log.field("client_write_iv", hexv(keys["c_iv"]))
    log.field("server_write_iv", hexv(keys["s_iv"]))
    log.field("client_finished_key (HMAC)", hexv(keys["c_fin"]))
    log.field("server_finished_key (HMAC)", hexv(keys["s_fin"]))


# ───────────────────────────── record layer ────────────────────────────
class RecordLayer:
    """AEAD encryption of every post-handshake message.
       nonce = write_iv XOR 96-bit sequence number   (unique per record)
       aad   = "MiniTLS" || 64-bit sequence number   (binds record to its position
                                                     -> replay / reorder / drop is detected)"""

    def __init__(self, aead_cls, write_key, write_iv, read_key, read_iv):
        self._w, self._r = aead_cls(write_key), aead_cls(read_key)
        self._wiv, self._riv = write_iv, read_iv
        self.wseq = 0
        self.rseq = 0

    @staticmethod
    def _nonce(iv: bytes, seq: int) -> bytes:
        return bytes(a ^ b for a, b in zip(iv, seq.to_bytes(12, "big")))

    @staticmethod
    def _aad(seq: int) -> bytes:
        return b"MiniTLS" + seq.to_bytes(8, "big")

    def seal(self, plaintext: bytes) -> bytes:
        ct = self._w.encrypt(self._nonce(self._wiv, self.wseq), plaintext, self._aad(self.wseq))
        self.wseq += 1
        return ct

    def open(self, ciphertext: bytes) -> bytes:
        pt = self._r.decrypt(self._nonce(self._riv, self.rseq), ciphertext, self._aad(self.rseq))
        self.rseq += 1
        return pt


def make_record_layer(suite: str, keys: dict, is_client: bool) -> RecordLayer:
    aead = SUITES[suite]
    if is_client:
        return RecordLayer(aead, keys["c_key"], keys["c_iv"], keys["s_key"], keys["s_iv"])
    return RecordLayer(aead, keys["s_key"], keys["s_iv"], keys["c_key"], keys["c_iv"])


def _raw_pub(priv: x25519.X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _finished_mac(fin_key: bytes, th: bytes) -> bytes:
    return hmac.new(fin_key, th, hashlib.sha256).digest()


def _send_finished(sock, rec: RecordLayer, mac: bytes):
    plain = json.dumps({"type": "Finished", "verify_data": mac.hex()}, sort_keys=True, separators=(",", ":")).encode()
    send_frame(sock, rec.seal(plain))
    return plain


def _recv_finished(sock, rec: RecordLayer):
    try:
        plain = rec.open(recv_frame(sock))
    except Exception:
        raise HandshakeError("could not decrypt peer Finished (keys differ - handshake was tampered with)")
    msg = json.loads(plain)
    if msg.get("type") != "Finished":
        raise HandshakeError("expected Finished")
    return plain, bytes.fromhex(msg["verify_data"])


# ══════════════════════════ SERVER HANDSHAKE ═══════════════════════════
def server_handshake(sock, server_cert, server_key, ca_cert, log: Log):
    """Returns (RecordLayer, client_certificate) or raises HandshakeError."""
    tr = Transcript()
    try:
        # ── 1. ClientHello ────────────────────────────────────────────
        log.banner("STEP 1 · ClientHello  (client says hi, offers ciphers, sends ephemeral key)")
        m = recv_msg(sock, "ClientHello", tr)
        log.recv("ClientHello", "client")
        client_random, client_pub = b64d(m["random"]), b64d(m["key_share"])
        log.field("protocol version", m["version"])
        log.field("client_random (32B nonce)", hexv(client_random))
        log.field("offered cipher suites", m["cipher_suites"])
        log.field("client X25519 public key", hexv(client_pub))
        log.note("client_random makes this session unique -> stops replay of an old handshake.")
        if m["version"] != VERSION:
            raise HandshakeError("unsupported protocol version")
        suite = next((s for s in SERVER_SUITE_PREFERENCE if s in m["cipher_suites"]), None)
        if suite is None:
            raise HandshakeError("no common cipher suite")

        # ── 2. ServerHello ────────────────────────────────────────────
        log.banner("STEP 2 · ServerHello  (server picks cipher, sends its ephemeral key)")
        eph = x25519.X25519PrivateKey.generate()
        server_random = os.urandom(32)
        send_msg(sock, {"type": "ServerHello", "version": VERSION, "random": b64e(server_random),
                        "cipher_suite": suite, "key_share": b64e(_raw_pub(eph))}, tr)
        log.send("ServerHello", "client")
        log.field("server_random (32B nonce)", hexv(server_random))
        log.field("chosen cipher suite", suite)
        log.field("server X25519 public key", hexv(_raw_pub(eph)))
        log.note("Key shares are EPHEMERAL (generated per connection) -> forward secrecy.")

        # ── key exchange ──────────────────────────────────────────────
        log.banner("STEP 3 · KEY EXCHANGE  (ECDHE - both sides compute the SAME secret, never sent)")
        shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(client_pub))
        master, keys = derive_keys(shared, client_random, server_random)
        log_key_schedule(log, shared, master, keys)
        log.note("shared = X25519(my_private, peer_public).  An eavesdropper sees only the public keys.")
        log.note("Keys are computed now but unused until Finished; identities are still UNVERIFIED.")
        rec = make_record_layer(suite, keys, is_client=False)

        # ── 4. server Certificate ─────────────────────────────────────
        log.banner("STEP 4 · Server Certificate  (server proves WHO it claims to be)")
        send_msg(sock, {"type": "Certificate", "cert": cert_pem(server_cert).decode()}, tr)
        log.send("Certificate", "client")
        describe_cert(server_cert, log, "server cert")

        # ── 5. CertificateRequest (mutual auth!) ──────────────────────
        log.banner("STEP 5 · CertificateRequest  (server DEMANDS a client cert -> MUTUAL auth)")
        send_msg(sock, {"type": "CertificateRequest", "accepted_ca": ca_cert.subject.rfc4514_string()}, tr)
        log.send("CertificateRequest", "client")
        log.field("accepted CA", ca_cert.subject.rfc4514_string())

        # ── 6. server CertificateVerify ───────────────────────────────
        log.banner("STEP 6 · Server CertificateVerify  (proof of private-key possession)")
        th = tr.hash()
        sig = sign_transcript(server_key, CTX_SERVER_CV, th)
        send_msg(sock, {"type": "CertificateVerify", "signature": b64e(sig)}, tr)
        log.send("CertificateVerify", "client")
        log.field("transcript hash signed", hexv(th))
        log.field("RSA-PSS signature", hexv(sig, 24))
        log.note("A certificate is public; anyone can copy it.  Only the real owner can SIGN this hash.")
        log.note("The hash includes both ephemeral keys -> binds the key exchange to the server identity (stops MITM).")

        # ── 7. client Certificate ─────────────────────────────────────
        log.banner("STEP 7 · Client Certificate  (now the server authenticates the CLIENT)")
        m = recv_msg(sock, "Certificate", tr)
        log.recv("Certificate", "client")
        client_cert = x509.load_pem_x509_certificate(m["cert"].encode())
        describe_cert(client_cert, log, "client cert")
        log.info("validating client certificate …")
        verify_cert(client_cert, ca_cert, "client", log)

        # ── 8. client CertificateVerify ───────────────────────────────
        log.banner("STEP 8 · Client CertificateVerify  (client proves it owns the private key)")
        th = tr.hash()
        m = recv_msg(sock, "CertificateVerify", tr)
        log.recv("CertificateVerify", "client")
        sig = b64d(m["signature"])
        log.field("transcript hash expected", hexv(th))
        log.field("client signature", hexv(sig, 24))
        verify_transcript_sig(client_cert.public_key(), sig, CTX_CLIENT_CV, th)
        log.check(f"signature verifies with public key in cert -> client really is '{cn_of(client_cert)}'")

        # ── 9. Finished (encrypted) ───────────────────────────────────
        log.banner("STEP 9 · Finished  (first ENCRYPTED messages - confirms both sides have same keys/transcript)")
        th = tr.hash()
        plain, got = _recv_finished(sock, rec)
        log.recv("Finished [encrypted]", "client")
        expect = _finished_mac(keys["c_fin"], th)
        log.field("client verify_data (received)", hexv(got))
        log.field("HMAC(client_finished_key, transcript)", hexv(expect))
        if not hmac.compare_digest(got, expect):
            raise HandshakeError("client Finished MAC mismatch")
        log.check("client Finished OK - decrypted with client_write_key, transcript matches")
        tr.add(plain)
        mac = _finished_mac(keys["s_fin"], tr.hash())
        _send_finished(sock, rec, mac)
        log.send("Finished [encrypted]", "client")
        log.field("server verify_data", hexv(mac))

        log.banner("🔒 HANDSHAKE COMPLETE · mutual authentication succeeded · channel is AES-256-GCM encrypted")
        return rec, client_cert
    except HandshakeError as e:
        send_alert(sock, str(e))
        raise


# ══════════════════════════ CLIENT HANDSHAKE ═══════════════════════════
def client_handshake(sock, client_cert, client_key, ca_cert, hostname: str, log: Log):
    """Returns (RecordLayer, server_certificate) or raises HandshakeError."""
    tr = Transcript()
    try:
        # ── 1. ClientHello ────────────────────────────────────────────
        log.banner("STEP 1 · ClientHello  (client says hi, offers ciphers, sends ephemeral key)")
        eph = x25519.X25519PrivateKey.generate()
        client_random = os.urandom(32)
        send_msg(sock, {"type": "ClientHello", "version": VERSION, "random": b64e(client_random),
                        "cipher_suites": CLIENT_SUITE_PREFERENCE, "key_share": b64e(_raw_pub(eph))}, tr)
        log.send("ClientHello", "server")
        log.field("protocol version", VERSION)
        log.field("client_random (32B nonce)", hexv(client_random))
        log.field("offered cipher suites", CLIENT_SUITE_PREFERENCE)
        log.field("client X25519 public key", hexv(_raw_pub(eph)))
        log.field("client X25519 PRIVATE key", "(kept secret, never leaves this process)")

        # ── 2. ServerHello ────────────────────────────────────────────
        log.banner("STEP 2 · ServerHello  (server picks cipher, sends its ephemeral key)")
        m = recv_msg(sock, "ServerHello", tr)
        log.recv("ServerHello", "server")
        server_random, server_pub, suite = b64d(m["random"]), b64d(m["key_share"]), m["cipher_suite"]
        log.field("server_random (32B nonce)", hexv(server_random))
        log.field("chosen cipher suite", suite)
        log.field("server X25519 public key", hexv(server_pub))
        if suite not in CLIENT_SUITE_PREFERENCE:
            raise HandshakeError("server chose a suite we never offered")

        # ── key exchange ──────────────────────────────────────────────
        log.banner("STEP 3 · KEY EXCHANGE  (ECDHE - both sides compute the SAME secret, never sent)")
        shared = eph.exchange(x25519.X25519PublicKey.from_public_bytes(server_pub))
        master, keys = derive_keys(shared, client_random, server_random)
        log_key_schedule(log, shared, master, keys)
        log.note("Compare with the server's log: the secrets are IDENTICAL although never transmitted.")
        rec = make_record_layer(suite, keys, is_client=True)

        # ── 4. server Certificate ─────────────────────────────────────
        log.banner("STEP 4 · Server Certificate  (client checks WHO the server is)")
        m = recv_msg(sock, "Certificate", tr)
        log.recv("Certificate", "server")
        server_cert = x509.load_pem_x509_certificate(m["cert"].encode())
        describe_cert(server_cert, log, "server cert")
        log.info("validating server certificate …")
        verify_cert(server_cert, ca_cert, "server", log, hostname=hostname)

        # ── 5. CertificateRequest ─────────────────────────────────────
        log.banner("STEP 5 · CertificateRequest  (server wants OUR certificate too)")
        m = recv_msg(sock, "CertificateRequest", tr)
        log.recv("CertificateRequest", "server")
        log.field("server accepts certs issued by", m["accepted_ca"])

        # ── 6. server CertificateVerify ───────────────────────────────
        log.banner("STEP 6 · Server CertificateVerify  (does the server really own that cert?)")
        th = tr.hash()
        m = recv_msg(sock, "CertificateVerify", tr)
        log.recv("CertificateVerify", "server")
        sig = b64d(m["signature"])
        log.field("transcript hash expected", hexv(th))
        log.field("server signature", hexv(sig, 24))
        verify_transcript_sig(server_cert.public_key(), sig, CTX_SERVER_CV, th)
        log.check("signature verifies -> server holds the private key AND saw the same hellos (no MITM)")

        # ── 7. client Certificate ─────────────────────────────────────
        log.banner("STEP 7 · Client Certificate  (we present our identity)")
        send_msg(sock, {"type": "Certificate", "cert": cert_pem(client_cert).decode()}, tr)
        log.send("Certificate", "server")
        describe_cert(client_cert, log, "client cert")

        # ── 8. client CertificateVerify ───────────────────────────────
        log.banner("STEP 8 · Client CertificateVerify  (we prove we own our private key)")
        th = tr.hash()
        sig = sign_transcript(client_key, CTX_CLIENT_CV, th)
        send_msg(sock, {"type": "CertificateVerify", "signature": b64e(sig)}, tr)
        log.send("CertificateVerify", "server")
        log.field("transcript hash signed", hexv(th))
        log.field("RSA-PSS signature", hexv(sig, 24))

        # ── 9. Finished (encrypted) ───────────────────────────────────
        log.banner("STEP 9 · Finished  (first ENCRYPTED messages)")
        mac = _finished_mac(keys["c_fin"], tr.hash())
        plain = _send_finished(sock, rec, mac)
        log.send("Finished [encrypted]", "server")
        log.field("client verify_data", hexv(mac))
        tr.add(plain)
        _, got = _recv_finished(sock, rec)
        log.recv("Finished [encrypted]", "server")
        expect = _finished_mac(keys["s_fin"], tr.hash())
        log.field("server verify_data (received)", hexv(got))
        if not hmac.compare_digest(got, expect):
            raise HandshakeError("server Finished MAC mismatch")
        log.check("server Finished OK - both sides agree on keys and on every handshake byte")

        log.banner("🔒 HANDSHAKE COMPLETE · mutual authentication succeeded · channel is AES-256-GCM encrypted")
        return rec, server_cert
    except HandshakeError as e:
        send_alert(sock, str(e))
        raise
