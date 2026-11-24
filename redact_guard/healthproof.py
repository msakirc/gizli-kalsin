"""Proof that a health answer comes from the real redact-guard, not from a look-alike.

A hostile repository's .claude/settings.json can point ANTHROPIC_BASE_URL or HTTPS_PROXY at
its own server, and that server can answer {"ok": true}. So the prompt hook sends a fresh
nonce and expects HMAC(secret, nonce) back. The secret sits in a local file at a FIXED path
(never taken from the environment, which the repository controls). A remote server can't
read it; local processes can, which is fine: this check is about where the traffic goes.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from pathlib import Path

PREFIX = b"redact-guard-health:"


def candidate_paths() -> list[Path]:
    """Where installers put the secret, in the order the hook looks."""
    out = []
    pd = os.environ.get("ProgramData") or (r"C:\ProgramData" if os.name == "nt" else None)
    if os.name == "nt" and pd:
        out.append(Path(pd) / "redact-guard" / "public" / "hook-secret")
    else:
        out.append(Path("/etc/redact-guard/hook-secret"))
    try:
        out.append(Path("~/.config/redact-guard/hook-secret").expanduser())
    except RuntimeError:        # no home directory in this environment (Windows without USERPROFILE)
        pass
    return out


def load(path: Path | None = None, create: bool = False) -> bytes | None:
    paths = [path] if path else candidate_paths()
    for p in paths:
        try:
            v = p.read_text().strip()
            if v:
                return v.encode()
        except OSError:
            continue
    if create and path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        v = secrets.token_hex(32)
        path.write_text(v + "\n")
        try:
            os.chmod(path, 0o644)        # readable is fine; see module docstring
        except OSError:
            pass
        return v.encode()
    return None


def proof(secret: bytes, nonce: str) -> str:
    return hmac.new(secret, PREFIX + nonce.encode()[:128], hashlib.sha256).hexdigest()


def verify(secret: bytes, nonce: str, got: str | None) -> bool:
    return bool(got) and hmac.compare_digest(proof(secret, nonce), str(got))


def get_json(url: str, via_proxy: str | None = None) -> dict:
    """Plain-HTTP GET, directly or through an HTTP proxy. Uses http.client, not urllib's
    opener: building that opener creates a TLS context and loads the OS certificate store,
    which can fail on Windows (a broken cert in the store, a stripped environment) even
    though nothing here uses TLS."""
    import http.client
    import json
    import urllib.parse
    target = urllib.parse.urlsplit(via_proxy or url)
    if target.scheme not in ("http", ""):
        raise ValueError(f"unsupported scheme {target.scheme!r}")
    conn = http.client.HTTPConnection(target.hostname or "127.0.0.1", target.port or 80, timeout=3)
    try:
        if via_proxy:
            conn.request("GET", url, headers={"Host": urllib.parse.urlsplit(url).netloc})
        else:
            u = urllib.parse.urlsplit(url)
            conn.request("GET", (u.path or "/") + (f"?{u.query}" if u.query else ""))
        resp = conn.getresponse()
        if resp.status != 200:
            raise ValueError(f"HTTP {resp.status}")
        return json.loads(resp.read(65536))
    finally:
        conn.close()
