import pytest

from redact_guard import upstream as U

OWN = {("127.0.0.1", 8788)}


def test_auto_uses_env(monkeypatch):
    for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://user:p%40ss@corp-proxy.acme.local:8080")
    up, creds = U.detect("auto", OWN)
    assert up.url == "http://corp-proxy.acme.local:8080" and creds == "user:p@ss"


def test_auto_ignores_itself(monkeypatch):
    for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8788")      # Claude Code's setting leaking in
    monkeypatch.setattr(U, "windows_system_proxy", lambda: None)     # no registry proxy on this box
    up, _ = U.detect("auto", OWN)
    assert up.url is None


def test_auto_skips_itself_and_falls_back_to_registry(monkeypatch):
    for k in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:8788")
    monkeypatch.setattr(U, "windows_system_proxy",
                        lambda: U.Upstream("http://proxy.corp.local:8080", "Windows system proxy",
                                           bypass=["*.corp.local"]))
    with monkeypatch.context() as m:                                  # pretend to be Windows just for detect()
        m.setattr(U.os, "name", "nt")
        up, _ = U.detect("auto", OWN)
    assert up.url == "http://proxy.corp.local:8080"


def test_explicit_and_none():
    assert U.detect("corp:3128", OWN)[0].url == "http://corp:3128"
    assert U.detect("none", OWN)[0].url is None
    with pytest.raises(ValueError):
        U.detect("socks5://corp:1080", OWN)


def test_windows_proxy_server_formats():
    assert U.parse_proxy_server("corp:8080") == "corp:8080"
    assert U.parse_proxy_server("http=corp:8080;https=corp:8443;socks=corp:1080") == "corp:8443"
    assert U.parse_proxy_server("http=corp:8080") == "corp:8080"
    assert U.parse_proxy_server("socks=corp:1080") is None


def test_system_bundle_includes_ssl_cert_file(tmp_path, monkeypatch):
    extra = tmp_path / "corp-ca.pem"
    extra.write_text("-----BEGIN CERTIFICATE-----\nCORPCA\n-----END CERTIFICATE-----\n")
    monkeypatch.setenv("SSL_CERT_FILE", str(extra))
    path = U.ca_bundle("system", tmp_path / "out")
    text = open(path).read()
    assert "CORPCA" in text and text.count("BEGIN CERTIFICATE") > 100     # + Mozilla/OS roots


def test_digest_allowlist():
    import hashlib
    import os
    from redact_guard.engine import Redactor
    from redact_guard.vault import Vault
    r = Redactor(Vault(os.urandom(48)))
    t = "API_TOKEN=public-demo-token-123 DB_PASSWORD=Zq8!wLm2#rTyy"
    r.dcfg.allow_digests = {hashlib.sha256(b"public-demo-token-123").hexdigest()}
    out = r.tokenize(t)
    assert "public-demo-token-123" in out and "Zq8!wLm2#rTyy" not in out


def test_gitleaks_all_rules_compile():
    from redact_guard.gitleaks import load
    rules, _, failed = load(None)
    assert len(rules) >= 200 and failed == []


def test_gitleaks_adds_coverage():
    import os
    from redact_guard.engine import Redactor
    from redact_guard.vault import Vault
    r = Redactor(Vault(os.urandom(48)))
    # built at run time so secret scanners (e.g. GitHub push protection) don't flag the fakes
    hexs = "0123456789abcdef"
    for s in ("PULUMI " + "pul" + "-" + hexs * 2 + "01234567",
              "databricks " + "da" + "pi" + hexs * 2):
        assert "RDX_SECRET_" in r.tokenize(s), s


def test_no_proxy_extra_refuses_anthropic():
    import subprocess
    import sys
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    p = subprocess.run([sys.executable, str(root / "scripts" / "render_settings.py"), "--mode", "proxy",
                        "--no-proxy-extra", "mcp.acme.local,api.anthropic.com"], capture_output=True, text=True)
    assert p.returncode != 0 and "refusing" in p.stderr
    p = subprocess.run([sys.executable, str(root / "scripts" / "render_settings.py"), "--mode", "proxy",
                        "--no-proxy-extra", "mcp.acme.local"], capture_output=True, text=True, check=True)
    import json
    # membership, not position: on Windows the system proxy exceptions are appended too
    entries = json.loads(p.stdout)["env"]["no_proxy"].split(",")
    assert "mcp.acme.local" in entries and "localhost" in entries
    assert not any("anthropic" in e or "claude" in e for e in entries)
