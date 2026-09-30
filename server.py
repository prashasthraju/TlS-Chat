"""
Mutual-auth chat SERVER.   python server.py [--port 5555] [--quiet]

* Every client must pass the MiniTLS handshake (valid cert + key possession).
* The client's *username is taken from its certificate CN* - it cannot be spoofed.
* After the handshake every message is AES-GCM encrypted.
* NOTE: the server relays chat (decrypt from A -> re-encrypt for B), so it can read
  messages.  This is transport security (like TLS), not end-to-end between users.
"""
import argparse
import json
import socket
import threading
import time

from cryptography.exceptions import InvalidTag

import minitls as m
from logutil import Log, hexv, c

clients = {}            # name -> Peer
clients_lock = threading.Lock()


class Peer:
    def __init__(self, name, conn, rec):
        self.name, self.conn, self.rec = name, conn, rec
        self.wlock = threading.Lock()

    def send(self, obj, log=None):
        data = json.dumps(obj, separators=(",", ":")).encode()
        with self.wlock:
            seq = self.rec.wseq
            ct = self.rec.seal(data)
            m.send_frame(self.conn, ct)
        if log:
            log.field(f"→ {self.name}: plaintext", data.decode())
            log.field(f"→ {self.name}: AES-GCM record #{seq}", hexv(ct, 24))


def broadcast(obj, log, exclude=None):
    with clients_lock:
        targets = [p for p in clients.values() if p is not exclude]
    for p in targets:
        try:
            p.send(obj, log)
        except OSError:
            pass


def handle(conn, addr, args, ca, scert, skey):
    log = Log("SERVER", f"{addr[0]}:{addr[1]}", verbose=not args.quiet)
    log.info(c("1", f"new TCP connection from {addr[0]}:{addr[1]} - starting handshake"))
    try:
        rec, ccert = m.server_handshake(conn, scert, skey, ca, log)
    except (m.HandshakeError, ConnectionError, OSError) as e:
        log.fail(f"HANDSHAKE FAILED - connection rejected: {e}")
        conn.close()
        return
    name = m.cn_of(ccert)
    peer = Peer(name, conn, rec)
    with clients_lock:
        if name in clients:
            dup = True
        else:
            dup = False
            clients[name] = peer
    if dup:
        peer.send({"type": "system", "text": f"'{name}' is already connected"})
        log.fail(f"duplicate login for '{name}'")
        conn.close()
        return
    log.ok(f"authenticated as {c('1;32', name)} (from certificate CN)")
    broadcast({"type": "system", "text": f"{name} joined"}, log)
    peer.send({"type": "system", "text": f"welcome {name}! online: {', '.join(sorted(clients))}"}, log)

    try:
        while True:
            ct = m.recv_frame(conn)
            log.banner(f"APPLICATION DATA from {name}")
            log.field(f"encrypted record #{rec.rseq} on the wire", hexv(ct, 32))
            pt = rec.open(ct)                   # raises InvalidTag if tampered / replayed / reordered
            msg = json.loads(pt)
            log.field("decrypted plaintext", pt.decode())
            if msg.get("type") == "chat":
                text = str(msg.get("text", ""))[:2000]
                out = {"type": "chat", "from": name, "text": text, "ts": time.strftime("%H:%M:%S")}
                log.note("re-encrypting separately for each recipient with THEIR session keys")
                broadcast(out, log, exclude=peer)
            elif msg.get("type") == "who":
                peer.send({"type": "system", "text": "online: " + ", ".join(sorted(clients))}, log)
    except InvalidTag:
        log.fail(f"{name}: record failed AEAD authentication (tampered/replayed) - closing")
    except (ConnectionError, OSError):
        pass
    finally:
        with clients_lock:
            if clients.get(name) is peer:
                del clients[name]
        conn.close()
        log.info(f"{name} disconnected")
        broadcast({"type": "system", "text": f"{name} left"}, log)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--certs", default="certs")
    ap.add_argument("--quiet", action="store_true", help="hide handshake internals")
    args = ap.parse_args()

    ca = m.load_cert(f"{args.certs}/ca.crt")
    scert, skey = m.load_cert(f"{args.certs}/server.crt"), m.load_key(f"{args.certs}/server.key")

    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.host, args.port))
    s.listen()
    print(c("1;35", f"MiniTLS chat server listening on {args.host}:{args.port}  (mutual auth REQUIRED)"), flush=True)
    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle, args=(conn, addr, args, ca, scert, skey), daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nbye")
