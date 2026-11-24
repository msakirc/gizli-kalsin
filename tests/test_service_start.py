"""The service as Windows runs it: a Scheduled Task with no console (sys.stdout/stderr are None).
Before the fix, the proxy logged one line and exited silently."""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.mark.skipif(os.name == "nt", reason="closes fds 0-2 with POSIX preexec_fn")
def test_proxy_starts_and_logs_without_console(tmp_path):
    port = _free_port()
    cfg = tmp_path / "px.yaml"
    cfg.write_text(f"proxy: {{host: 127.0.0.1, port: {port}}}\ncorporate_proxy: {{url: none}}\n"
                   f"vault: {{dir: {tmp_path}/s, key_file: {tmp_path}/s/key}}\nhook_secret_file: {tmp_path}/hs\n")
    subprocess.run([sys.executable, "-m", "redact_guard", "proxy", "--init", "-c", str(cfg)],
                   cwd=ROOT, check=True, capture_output=True)
    log = tmp_path / "proxy.log"
    p = subprocess.Popen([sys.executable, "-m", "redact_guard", "proxy", "-c", str(cfg), "--log-file", str(log)],
                         cwd=ROOT, preexec_fn=lambda: [os.close(i) for i in (0, 1, 2)])
    try:
        op = urllib.request.build_opener(urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{port}"}))
        for _ in range(40):
            time.sleep(0.5)
            try:
                with op.open("http://redact-guard.invalid/healthz", timeout=2) as r:
                    assert json.loads(r.read())["ok"] is True
                    break
            except OSError:
                assert p.poll() is None, "proxy exited:\n" + log.read_text()
        else:
            pytest.fail("proxy never answered:\n" + log.read_text())
        assert "proxy_listening" in log.read_text()
    finally:
        p.terminate()
        p.wait(10)


def test_crash_is_logged(tmp_path, monkeypatch):
    import logging
    from redact_guard import __main__ as M
    log = tmp_path / "x.log"
    M._log_to_file(str(log))
    try:
        @M._logged
        def boom(args):
            raise RuntimeError("kaboom")
        with pytest.raises(RuntimeError):
            boom(None)
        logging.getLogger().handlers[0].flush()
        text = log.read_text()
        assert '"event":"crashed"' in text and "RuntimeError: kaboom" in text
    finally:
        sys.stdout, sys.stderr = sys.__stdout__, sys.__stderr__
        logging.basicConfig(force=True, stream=sys.__stderr__)


def test_ssl_context_accepts_non_strict_corporate_ca_but_still_verifies():
    import ssl
    from redact_guard.upstream import ssl_context
    ctx = ssl_context(None)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert not (ctx.verify_flags & getattr(ssl, "VERIFY_X509_STRICT", 0))
