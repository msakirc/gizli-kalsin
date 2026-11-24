"""Chain behind the proxy that is already on this machine (corporate / system proxy).

redact-guard sits in front of it:

    Claude Code -> redact-guard (redacts) -> your existing proxy -> internet

Only Claude Code is pointed at redact-guard (through its settings). Every other
program keeps using your existing proxy exactly as before. Your corporate proxy
then only ever sees redacted traffic.

`corporate_proxy.url` in the config:
  auto (default)   use HTTPS_PROXY/HTTP_PROXY from redact-guard's own environment,
                   else the Windows system proxy (Settings > Network > Proxy).
                   A PAC / "automatic configuration script" can't be evaluated:
                   set the URL explicitly, or run a PAC-aware helper such as px.
  none             connect directly.
  http://host:port use this proxy.

`corporate_proxy.ca`:
  system (default) trust the OS certificate store plus Mozilla's bundle when
                   connecting upstream. Needed when the existing proxy inspects
                   TLS (Zscaler, Netskope, Palo Alto, Fortinet, ...).
  certifi          Mozilla's bundle only.
  /path/ca.pem     a bundle you provide.
"""
from __future__ import annotations

import os
import ssl
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


@dataclass
class Upstream:
    url: str | None
    source: str
    warning: str | None = None
    bypass: list[str] = field(default_factory=list)   # the existing proxy's own bypass list

    def describe(self) -> str:
        s = f"{self.url or 'direct'} (from {self.source})"
        return s + (f"; WARNING: {self.warning}" if self.warning else "")


def _normalize(v: str) -> str:
    v = v.strip()
    if "://" not in v:
        v = "http://" + v
    u = urlparse(v)
    if u.scheme not in ("http", "https"):
        raise ValueError(f"unsupported upstream proxy scheme {u.scheme!r} (SOCKS isn't supported)")
    return f"{u.scheme}://{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}"


def _creds_from_url(v: str) -> str | None:
    u = urlparse(v if "://" in v else "http://" + v)
    if u.username:
        from urllib.parse import unquote
        return f"{unquote(u.username)}:{unquote(u.password or '')}"
    return None


def _is_self(v: str, own: set[tuple[str, int]]) -> bool:
    try:
        u = urlparse(v if "://" in v else "http://" + v)
    except ValueError:
        return False
    host = (u.hostname or "").lower()
    return (host in ("127.0.0.1", "localhost", "::1")) and any(p == u.port for _, p in own)


def parse_proxy_server(server: str) -> str | None:
    """Windows ProxyServer value: 'host:port' or 'http=h:p;https=h:p;socks=h:p'."""
    server = server.strip()
    if "=" not in server:
        return server or None
    parts = dict(p.split("=", 1) for p in server.split(";") if "=" in p)
    return parts.get("https") or parts.get("http")


def windows_system_proxy() -> Upstream | None:
    try:
        import winreg  # type: ignore
    except ImportError:
        return None
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
    except OSError:
        return None

    def q(name, default=None):
        try:
            return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return default
    enabled, server = q("ProxyEnable", 0), q("ProxyServer", "")
    pac = q("AutoConfigURL", "")
    bypass = [b.strip() for b in (q("ProxyOverride", "") or "").split(";") if b.strip()]
    if enabled and server:
        hp = parse_proxy_server(server)
        if hp:
            return Upstream(_normalize(hp), "Windows system proxy", bypass=bypass)
    if pac:
        return Upstream(None, "Windows automatic configuration script",
                        warning=f"a PAC script ({pac}) can't be evaluated; set corporate_proxy.url "
                                f"explicitly, or chain through a PAC-aware helper such as px")
    return None


def detect(configured: str | None, own: set[tuple[str, int]]) -> tuple[Upstream, str | None]:
    """Returns (upstream, credentials 'user:pass' or None)."""
    configured = (configured or "auto").strip()
    if configured.lower() in ("none", "direct", "off"):
        return Upstream(None, "config: direct"), None
    if configured.lower() != "auto":
        return Upstream(_normalize(configured), "config"), _creds_from_url(configured)
    for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        v = os.environ.get(k)
        if v and not _is_self(v, own):
            return Upstream(_normalize(v), f"environment {k}"), _creds_from_url(v)
    if os.name == "nt":
        w = windows_system_proxy()
        if w:
            return w, None
    return Upstream(None, "nothing detected: direct"), None


# ------------------------------------------------------------------ CA bundle
def _os_roots_pem() -> list[str]:
    pems: list[str] = []
    if sys.platform == "win32":
        for store in ("ROOT", "CA"):
            try:
                for cert, enc, _trust in ssl.enum_certificates(store):  # type: ignore[attr-defined]
                    if enc == "x509_asn":
                        pems.append(ssl.DER_cert_to_PEM_cert(cert))
            except OSError:
                pass
    elif sys.platform == "darwin":
        for kc in ("/Library/Keychains/System.keychain",
                   "/System/Library/Keychains/SystemRootCertificates.keychain"):
            try:
                out = subprocess.run(["security", "find-certificate", "-a", "-p", kc],
                                     capture_output=True, text=True, timeout=20).stdout
                pems.append(out)
            except Exception:
                pass
    else:
        for f in ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                  "/etc/ssl/cert.pem", "/etc/ssl/ca-bundle.pem"):
            if os.path.isfile(f):
                pems.append(Path(f).read_text(errors="ignore"))
                break
    extra = os.environ.get("SSL_CERT_FILE")
    if extra and os.path.isfile(extra):
        pems.append(Path(extra).read_text(errors="ignore"))
    return pems


def ca_bundle(mode: str | None, out_dir: Path) -> str | None:
    """Path to a PEM bundle for verifying upstream TLS, or None for library defaults."""
    mode = (mode or "system").strip()
    if mode == "certifi":
        return None
    if mode != "system":
        if not os.path.isfile(mode):
            raise FileNotFoundError(f"corporate_proxy.ca: {mode} not found")
        return mode
    import certifi
    pems = [Path(certifi.where()).read_text()] + _os_roots_pem()
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / "upstream-ca-bundle.pem"
    out.write_text("\n".join(p.strip() for p in pems if p.strip()) + "\n")
    return str(out)


def ssl_context(bundle: str | None) -> ssl.SSLContext:
    """Verified TLS context (chain + hostname). Python 3.13 also turns on VERIFY_X509_STRICT,
    which rejects many corporate TLS-inspection CAs (Zscaler, Fortinet, Palo Alto, Trend...)
    with "Basic Constraints of CA cert not marked critical". Those CAs are legitimate, just
    not RFC 5280-strict, so that one flag is cleared; everything else is still checked."""
    ctx = ssl.create_default_context(cafile=bundle) if bundle else ssl.create_default_context()
    ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    return ctx

