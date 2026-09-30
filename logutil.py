"""Tiny pretty-printer so every handshake step is clearly visible in the terminal."""
import os
import sys
import threading

_lock = threading.Lock()
USE_COLOR = (sys.stdout.isatty() or os.environ.get("FORCE_COLOR")) and not os.environ.get("NO_COLOR")


def c(code, s):
    return f"\033[{code}m{s}\033[0m" if USE_COLOR else s


def hexv(b: bytes, n: int = 32) -> str:
    """Hex string, truncated for display."""
    h = b.hex()
    if len(b) > n:
        return f"{h[:n*2]}…  ({len(b)} bytes)"
    return f"{h}  ({len(b)} bytes)"


class Log:
    def __init__(self, role: str, tag: str = "", verbose: bool = True):
        self.role, self.tag, self.verbose = role, tag, verbose
        self.color = "1;36" if role == "CLIENT" else "1;35"

    def _pfx(self):
        return c(self.color, f"[{self.role}{' ' + self.tag if self.tag else ''}]")

    def _p(self, text):
        with _lock:
            print(text, flush=True)

    # ---- always shown -------------------------------------------------
    def info(self, text):
        self._p(f"{self._pfx()} {text}")

    def ok(self, text):
        self._p(f"{self._pfx()} {c('1;32', '✔')} {text}")

    def fail(self, text):
        self._p(f"{self._pfx()} {c('1;31', '✘')} {c('31', text)}")

    # ---- verbose only -------------------------------------------------
    def banner(self, title):
        if not self.verbose:
            return
        line = c("1;33", "═" * 74)
        self._p(f"\n{line}\n{self._pfx()} {c('1;33', title)}\n{line}")

    def send(self, name, to):
        if self.verbose:
            self._p(f"{self._pfx()} {c('1;34', '──▶ SEND')} {c('1', name)}  (to {to})")

    def recv(self, name, frm):
        if self.verbose:
            self._p(f"{self._pfx()} {c('1;34', '◀── RECV')} {c('1', name)}  (from {frm})")

    def field(self, label, value):
        if self.verbose:
            self._p(f"{self._pfx()}     {c('90', label + ':'):<34} {value}")

    def note(self, text):
        if self.verbose:
            self._p(f"{self._pfx()}   {c('3;33', '💡 ' + text)}")

    def check(self, text, good=True):
        if self.verbose:
            mark = c("1;32", "✔") if good else c("1;31", "✘")
            self._p(f"{self._pfx()}     {mark} {text}")
