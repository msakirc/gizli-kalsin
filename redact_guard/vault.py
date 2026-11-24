"""Token vault: deterministic, reversible substitution of sensitive values.

Tokens look like ``RDX_<CLASS>_<12 hex>`` (e.g. ``RDX_SECRET_3fa9c2b1d0e4``).
The 12-char suffix never contains a run of 6+ digits, so a token can never
look like a 10-digit VKN or 11-digit TCKN.

* Deterministic: the same value always maps to the same token (HMAC with a
  local key), so prompt caching stays stable and a value seen in a .env file
  gets the same token when it later shows up in a log line.
* Reversible: the vault keeps token -> value so responses (file edits,
  shell commands) can be restored locally before Claude Code executes them.
* The real values never leave this process. Optional persistence is
  encrypted with Fernet using a key stored with 0600 permissions.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path

# Classes. Keep them single words: the token regex depends on it.
SECRET = "SECRET"      # passwords, API keys, tokens, connection-string passwords
PRIVKEY = "PRIVKEY"    # PEM / PGP private key blocks
USER = "USER"          # usernames, home-directory names
EMAIL = "EMAIL"
IP = "IP"              # public IPv4
IPPRIV = "IPPRIV"      # RFC1918 / CGNAT / link-local IPv4
IPV6 = "IPV6"
HOST = "HOST"          # internal hostnames
PHONE = "PHONE"
TCKN = "TCKN"          # Turkish national ID (T.C. Kimlik No)
VKN = "VKN"            # Turkish tax number (Vergi Kimlik No)
IBAN = "IBAN"
CARD = "CARD"          # payment card numbers (Luhn-valid)
PERSON = "PERSON"      # names from your names list
CUSTOM = "CUSTOM"      # your own regexes

ALL_CLASSES = frozenset({SECRET, PRIVKEY, USER, EMAIL, IP, IPPRIV, IPV6, HOST,
                         PHONE, TCKN, VKN, IBAN, CARD, PERSON, CUSTOM})
# Classes that are fine to restore inside shell commands (they're needed to
# address machines, and they are not credentials).
NETWORK_IDENTITY_CLASSES = frozenset({USER, EMAIL, IP, IPPRIV, IPV6, HOST})

TOKEN_LEN = 12
TOKEN_RE = re.compile(r"RDX_([A-Z][A-Z0-9]*)_([0-9a-f]{12})")
# Text that could be the beginning of a token (used by the stream restorer to
# hold back a tail that may be completed by the next chunk).
TOKEN_PREFIX_RE = re.compile(r"R(?:D(?:X(?:_[A-Z0-9]*(?:_[0-9a-f]{0,12})?)?)?)?$")
_DIGIT_RUN = re.compile(r"\d{6,}")


@dataclass(frozen=True)
class Entry:
    value: str
    cls: str


class Vault:
    def __init__(self, key: bytes, path: Path | None = None, min_exact_len: int = 6):
        if len(key) < 32:
            raise ValueError("vault key must be at least 32 bytes")
        self._tok_key = hmac.new(key, b"redact-guard/token", hashlib.sha256).digest()
        # Fragments of the raw key as hex and base64: if any shows up in an outgoing request,
        # someone dumped the key file (od/xxd/base64/.hex()) and the request is refused.
        hx = key.hex()
        self.key_hex_markers = tuple(hx[i:i + 12] for i in range(0, len(hx) - 11, 12))
        b64 = base64.b64encode(key).decode()
        self.key_b64_markers = tuple(b64[i:i + 12] for i in range(0, len(b64) - 11, 12))
        self._enc_key = hmac.new(key, b"redact-guard/encrypt", hashlib.sha256).digest()
        self._by_token: dict[str, Entry] = {}
        self._by_value: dict[tuple[str, str], str] = {}
        self._exact: dict[str, str] = {}   # value -> token, for exact-match pass
        self._lock = threading.RLock()
        self._path = path
        self.min_exact_len = min_exact_len
        self.version = 0                    # bumps when exact-match set grows
        if path is not None:
            self._load()

    # ------------------------------------------------------------------ core
    def token_for(self, value: str, cls: str, exact: bool = True) -> str:
        if cls not in ALL_CLASSES:
            raise ValueError(f"unknown class {cls}")
        with self._lock:
            tok = self._by_value.get((cls, value))
            if tok:
                return tok
            salt = 0
            while True:
                msg = f"{cls}\x00{salt}\x00{value}".encode()
                digest = hmac.new(self._tok_key, msg, hashlib.sha256).hexdigest()[:TOKEN_LEN]
                tok = f"RDX_{cls}_{digest}"
                existing = self._by_token.get(tok)
                if not _DIGIT_RUN.search(digest) and (existing is None or existing.value == value):
                    break
                salt += 1  # digit run (could look like an ID number) or collision: re-derive
            self._by_token[tok] = Entry(value, cls)
            self._by_value[(cls, value)] = tok
            if exact and len(value) >= self.min_exact_len and value not in self._exact:
                self._exact[value] = tok
                self.version += 1
            self._persist_add(tok, value, cls, exact)
            return tok

    def lookup(self, token: str) -> Entry | None:
        return self._by_token.get(token)

    def exact_values(self) -> dict[str, str]:
        with self._lock:
            return dict(self._exact)

    def __len__(self) -> int:
        return len(self._by_token)

    # ----------------------------------------------------------- persistence
    def _fernet(self):
        from base64 import urlsafe_b64encode
        from cryptography.fernet import Fernet
        return Fernet(urlsafe_b64encode(self._enc_key))

    def _persist_add(self, tok: str, value: str, cls: str, exact: bool) -> None:
        if self._path is None:
            return
        line = json.dumps({"t": tok, "v": value, "c": cls, "x": exact}).encode()
        blob = self._fernet().encrypt(line)
        fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
        try:
            os.write(fd, blob + b"\n")
        finally:
            os.close(fd)

    def _load(self) -> None:
        assert self._path is not None
        if not self._path.exists():
            return
        f = self._fernet()
        for raw in self._path.read_bytes().splitlines():
            if not raw.strip():
                continue
            rec = json.loads(f.decrypt(raw))
            entry = Entry(rec["v"], rec["c"])
            self._by_token[rec["t"]] = entry
            self._by_value[(entry.cls, entry.value)] = rec["t"]
            if rec.get("x") and len(entry.value) >= self.min_exact_len:
                self._exact[entry.value] = rec["t"]
        self.version += 1


def load_or_create_key(path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        if os.name != "nt":   # NTFS doesn't use mode bits; the key lives in your profile (ACL'd to you)
            mode = path.stat().st_mode & 0o777
            if mode & 0o077:
                raise PermissionError(f"{path} must not be readable by group/others (chmod 600)")
        try:
            return path.read_bytes()
        except PermissionError as e:
            raise PermissionError(
                f"{path} exists but this account can't read it. If an older redact-guard created it, "
                f"re-run the installer (it repairs the permissions)") from e
    key = os.urandom(48)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        os.write(fd, key)
    finally:
        os.close(fd)
    if os.name == "nt":
        _restrict_windows_acl(path)
    return key


def _restrict_windows_acl(path: Path) -> None:
    """Best effort: remove inherited ACEs and grant only the current user (icacls)."""
    import subprocess
    user = os.environ.get("USERNAME")
    prof = os.environ.get("USERPROFILE", "").lower()
    if not user or user.endswith("$") or prof.endswith("systemprofile"):
        return    # running as SYSTEM: the isolated state folder's ACL already protects the key
    subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                   capture_output=True, check=False)
