"""
Mutual-auth chat CLIENT.   python client.py --name alice [--host 127.0.0.1] [--port 5555] [--quiet]

Commands inside chat:  /who  list users     /quit  leave
"""
import argparse
import json
import socket
import sys
import threading

from cryptography.exceptions import InvalidTag

import minitls as m
from logutil import Log, hexv, c


def receiver(sock, rec, log, stop):
    try:
        while not stop.is_set():
            ct = m.recv_frame(sock)
            seq = rec.rseq
            msg = json.loads(rec.open(ct))
            log.field(f"received AES-GCM record #{seq}", hexv(ct, 24))
            if msg["type"] == "chat":
                print(c("1;32", f"\n[{msg['ts']}] {msg['from']}: ") + msg["text"], flush=True)
            else:
                print(c("90", f"\n* {msg['text']}"), flush=True)
    except InvalidTag:
        log.fail("received record failed authentication - closing")
    except (ConnectionError, OSError):
        pass
    finally:
        stop.set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5555)
    ap.add_argument("--name", required=True, help="which certs/<name>.crt/.key to authenticate with")
    ap.add_argument("--certs", default="certs")
    ap.add_argument("--server-name", default="localhost", help="hostname the server cert must be valid for")
    ap.add_argument("--quiet", action="store_true", help="hide handshake internals")
    args = ap.parse_args()

    log = Log("CLIENT", args.name, verbose=not args.quiet)
    ca = m.load_cert(f"{args.certs}/ca.crt")
    ccert, ckey = m.load_cert(f"{args.certs}/{args.name}.crt"), m.load_key(f"{args.certs}/{args.name}.key")

    sock = socket.create_connection((args.host, args.port))
    log.info(c("1", f"TCP connected to {args.host}:{args.port} - starting handshake"))
    try:
        rec, scert = m.client_handshake(sock, ccert, ckey, ca, args.server_name, log)
    except (m.HandshakeError, ConnectionError, OSError) as e:
        log.fail(f"HANDSHAKE FAILED: {e}")
        sock.close()
        sys.exit(1)
    log.ok(f"secure session with '{m.cn_of(scert)}' established. Type messages, /who, /quit")

    stop = threading.Event()
    threading.Thread(target=receiver, args=(sock, rec, log, stop), daemon=True).start()
    try:
        for line in sys.stdin:
            if stop.is_set():
                break
            line = line.strip()
            if not line:
                continue
            if line == "/quit":
                break
            obj = {"type": "who"} if line == "/who" else {"type": "chat", "text": line}
            data = json.dumps(obj, separators=(",", ":")).encode()
            seq = rec.wseq
            ct = rec.seal(data)
            m.send_frame(sock, ct)
            log.field("plaintext", data.decode())
            log.field(f"sent AES-GCM record #{seq}", hexv(ct, 24))
    except (KeyboardInterrupt, OSError):
        pass
    finally:
        sock.close()
        print("disconnected")


if __name__ == "__main__":
    main()
