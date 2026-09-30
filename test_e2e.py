"""Automated end-to-end test:  python test_e2e.py
Starts a server, connects alice+bob, checks message delivery, then checks that a
forged cert (mallory) and an expired cert (olduser) are REJECTED."""
import subprocess, sys, time, os

PORT = "5599"
env = dict(os.environ, PYTHONUNBUFFERED="1")
py = sys.executable


def spawn(*a):
    return subprocess.Popen([py, "-u", *a], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, env=env)


def check(label, cond):
    print(("PASS  " if cond else "FAIL  ") + label)
    if not cond:
        check.failed = True
check.failed = False

server = spawn("server.py", "--port", PORT)
time.sleep(1)
bob = spawn("client.py", "--name", "bob", "--port", PORT)
time.sleep(1.5)
alice = spawn("client.py", "--name", "alice", "--port", PORT)
time.sleep(1.5)
alice.stdin.write("hello bob, this is secret\n"); alice.stdin.flush()
time.sleep(1)
bob.stdin.write("hi alice!\n"); bob.stdin.flush()
time.sleep(1)
alice.stdin.write("/quit\n"); alice.stdin.flush()
bob.stdin.write("/quit\n"); bob.stdin.flush()
time.sleep(0.5)
a_out = alice.communicate(timeout=5)[0]
b_out = bob.communicate(timeout=5)[0]

check("alice handshake completed", "HANDSHAKE COMPLETE" in a_out)
check("bob handshake completed", "HANDSHAKE COMPLETE" in b_out)
check("bob received alice's message", "alice: hello bob, this is secret" in b_out)
check("alice received bob's message", "bob: hi alice!" in a_out)

for bad, reason in (("mallory", "forged certificate"), ("olduser", "expired")):
    p = spawn("client.py", "--name", bad, "--port", PORT)
    out = p.communicate(timeout=10)[0]
    check(f"{bad} rejected ({reason})", p.returncode != 0 and "HANDSHAKE COMPLETE" not in out)

server.terminate()
s_out = server.communicate(timeout=5)[0]
check("server logged authenticated alice", "authenticated as alice" in s_out)
check("server logged rejection of mallory", "forged certificate" in s_out)
check("server logged rejection of olduser", "expired" in s_out)
open("/tmp/server_out.txt", "w").write(s_out); open("/tmp/alice_out.txt", "w").write(a_out)
sys.exit(1 if check.failed else 0)
