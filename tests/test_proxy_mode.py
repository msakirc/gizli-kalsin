"""Proxy mode: uplink redaction (Remote Control) and the mitmproxy addon."""
import json
import os

import pytest

pytest.importorskip("mitmproxy")

from mitmproxy.test import tflow  # noqa: E402
from mitmproxy import websocket  # noqa: E402

from redact_guard.engine import LeakDetected  # noqa: E402
from redact_guard.uplink import UplinkRedactor  # noqa: E402
from redact_guard.vault import TOKEN_RE  # noqa: E402

REAL = ["Xk9#mP2$vL8q", "10.0.4.17", "orders_admin", "/home/omer", "ayse.demir@acme-corp.com.tr"]


def _learn(redactor, fixtures):
    for f in ("values.yaml", "app.env", "nginx.log"):
        redactor.tokenize(fixtures[f])
    redactor.tokenize("DB_HOST=10.0.4.17 owner: ayse.demir@acme-corp.com.tr")


def _rc_frames():
    """NDJSON frames shaped like Claude Code's Remote Control uplink (stream-json)."""
    return [
        {"type": "system", "subtype": "init", "session_id": "3f0c2b1e-1111-4a5b-9c7d-0123456789ab",
         "cwd": "/home/omer/work/orders", "model": "claude-sonnet-4-5", "tools": ["Bash", "Edit"]},
        {"type": "stream_event", "uuid": "a1b2", "event": {"type": "content_block_delta", "index": 0,
         "delta": {"type": "text_delta", "text": "The password is Xk9#mP2$vL8q on 10.0.4.17"}}},
        {"type": "assistant", "uuid": "c3d4", "message": {"id": "msg_01AbCdEfGhIjKlMnOpQrStUv", "role": "assistant",
         "content": [{"type": "text", "text": "Editing values.yaml for orders_admin"},
                     {"type": "tool_use", "id": "toolu_01XyZaBcDeFgHiJkLmNoPq", "name": "Edit",
                      "input": {"file_path": "/home/omer/work/orders/values.yaml",
                                "old_string": 'password: "Xk9#mP2$vL8q"',
                                "new_string": 'password: "Xk9#mP2$vL8q"\n    sslMode: require'}}]}},
        {"type": "control_request", "request_id": "req_9f8e7d6c5b4a", "request": {
            "subtype": "can_use_tool", "tool_name": "Bash",
            "input": {"command": "ssh deploy@10.0.4.17 uptime"}, "tool_use_id": "toolu_01XyZaBcDeFgHiJkLmNoPq"}},
        {"type": "user", "uuid": "e5f6", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "toolu_01XyZaBcDeFgHiJkLmNoPq",
             "content": "Author: Ayşe Demir <ayse.demir@acme-corp.com.tr>\nDB_PASSWORD=Xk9#mP2$vL8q"}]}},
        {"type": "result", "subtype": "success", "session_id": "3f0c2b1e-1111-4a5b-9c7d-0123456789ab",
         "result": "Done: 10.0.4.17 now uses sslMode", "duration_ms": 1234},
    ]


def test_rc_uplink_redacts_content_keeps_protocol(redactor, fixtures):
    _learn(redactor, fixtures)
    up = UplinkRedactor(redactor)
    frames = _rc_frames()
    raw = "\n".join(json.dumps(f, ensure_ascii=False) for f in frames) + "\n"
    out = up.ws_text(raw)
    for leak in REAL + ["Ayşe Demir"]:
        assert leak not in out, (leak, out)
    lines = [json.loads(ln) for ln in out.split("\n") if ln.strip()]
    assert len(lines) == len(frames) and out.endswith("\n")
    # protocol fields untouched
    assert lines[0]["session_id"] == frames[0]["session_id"] and lines[0]["model"] == "claude-sonnet-4-5"
    assert lines[2]["message"]["content"][1]["id"] == "toolu_01XyZaBcDeFgHiJkLmNoPq"
    assert lines[3]["request_id"] == "req_9f8e7d6c5b4a"
    assert lines[3]["request"]["tool_name"] == "Bash"
    assert lines[5]["duration_ms"] == 1234
    # the phone sees placeholders that the local session can still restore
    assert TOKEN_RE.search(lines[1]["event"]["delta"]["text"])


def test_uplink_never_touches_credentials(redactor):
    up = UplinkRedactor(redactor)
    body = {"grant_type": "refresh_token", "refresh_token": "sk-ant-ort01-AbCdEfGhIjKlMnOpQrStUvWxYz0123",
            "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e"}
    out = json.loads(up.body(json.dumps(body).encode(), "application/json"))
    assert out == body


def test_uplink_refuses_binary_and_unknown(redactor):
    up = UplinkRedactor(redactor)
    with pytest.raises(ValueError):
        up.body(b"\x89PNG\r\n\x1a\n\x00\x00", "application/octet-stream")
    with pytest.raises(ValueError):
        up.body(b"some=thing", "application/x-protobuf")


def test_uplink_canary(redactor, fixtures):
    _learn(redactor, fixtures)
    up = UplinkRedactor(redactor)
    up.walk = lambda obj, key=None: obj          # simulate a walker bug
    with pytest.raises(LeakDetected):
        up.ws_text(json.dumps({"type": "user", "x": "Xk9#mP2$vL8q"}))


# ------------------------------------------------------------------ addon
@pytest.fixture
def addon(tmp_path, monkeypatch):
    monkeypatch.setenv("REDACT_GUARD_EPHEMERAL", "1")
    monkeypatch.delenv("REDACT_GUARD_CONFIG", raising=False)
    monkeypatch.delenv("REDACT_GUARD_TEST_UPSTREAM", raising=False)
    from redact_guard.mitm_addon import RedactGuardAddon
    a = RedactGuardAddon()
    a.audit = None
    return a


def _req_flow(host, path, body: dict | bytes, ctype="application/json", method="POST"):
    f = tflow.tflow()
    f.request.host = host
    f.request.headers["host"] = host
    f.request.path = path
    f.request.method = method
    f.request.headers["content-type"] = ctype
    f.request.content = body if isinstance(body, bytes) else json.dumps(body).encode()
    return f


def test_addon_redacts_messages(addon, fixtures):
    f = _req_flow("api.anthropic.com", "/v1/messages?beta=true", {
        "model": "x", "messages": [{"role": "user", "content": fixtures["app.env"]}]})
    addon.request(f)
    assert f.response is None
    sent = f.request.get_text()
    assert "S3cr3t!Pass" not in sent and "RDX_SECRET_" in sent
    assert f.metadata["rg_messages"]


def test_addon_redacts_rc_post_uplink(addon, fixtures):
    _learn(addon.redactor, fixtures)
    frames = "\n".join(json.dumps(x) for x in _rc_frames())
    f = _req_flow("api.anthropic.com", "/v1/sessions/abc/worker/events", frames.encode(),
                  "application/x-ndjson")
    addon.request(f)
    assert f.response is None
    for leak in REAL:
        assert leak not in f.request.get_text()


def test_addon_leaves_auth_alone(addon):
    body = {"grant_type": "refresh_token", "refresh_token": "sk-ant-ort01-AbCdEfGhIjKlMnOpQrStUvWxYz0123"}
    f = _req_flow("platform.claude.com", "/v1/oauth/token", body)
    addon.request(f)
    assert json.loads(f.request.get_text()) == body


def test_addon_ignores_other_hosts(addon):
    f = _req_flow("registry.npmjs.org", "/-/v1/login", {"password": "Xk9#mP2$vL8q"})
    addon.request(f)
    assert "Xk9#mP2$vL8q" in f.request.get_text()   # not ours to touch (and not decrypted in practice)


def test_addon_refuses_uninspectable_upload(addon):
    f = _req_flow("api.anthropic.com", "/v1/files", b"\x00\x01\x02binary", "application/octet-stream")
    addon.request(f)
    assert f.response is not None and f.response.status_code == 403


def test_addon_health(addon):
    f = _req_flow("redact-guard.invalid", "/healthz", b"", method="GET")
    addon.request(f)
    assert f.response.status_code == 200 and json.loads(f.response.get_text())["mode"] == "proxy"


def test_addon_websocket_frames(addon, fixtures):
    _learn(addon.redactor, fixtures)
    f = tflow.twebsocketflow()
    f.request.host = "api.anthropic.com"
    f.request.headers["host"] = "api.anthropic.com"
    raw = "\n".join(json.dumps(x, ensure_ascii=False) for x in _rc_frames()) + "\n"
    f.websocket.messages.append(websocket.WebSocketMessage(1, True, raw.encode()))   # 1 = text
    addon.websocket_message(f)
    out = f.websocket.messages[-1].text
    for leak in REAL:
        assert leak not in out
    # frames from the server (your phone's messages) are not modified
    f.websocket.messages.append(websocket.WebSocketMessage(1, False, b'{"type":"user","text":"10.0.4.17"}'))
    addon.websocket_message(f)
    assert "10.0.4.17" in f.websocket.messages[-1].text


def test_addon_kills_ws_on_binary_frame(addon):
    f = tflow.twebsocketflow()
    f.request.host = "api.anthropic.com"
    f.request.headers["host"] = "api.anthropic.com"
    f.websocket.messages.append(websocket.WebSocketMessage(2, True, b"\x00\x01"))   # 2 = binary
    addon.websocket_message(f)
    assert f.websocket.messages[-1].dropped
    assert f.error is not None or f.killable is False


def test_addon_streams_and_restores(addon):
    view = addon.redactor.tokenize("DB_PASSWORD=Zq8!wLm2#rTyy")
    tok = TOKEN_RE.search(view).group(0)
    f = _req_flow("api.anthropic.com", "/v1/messages", {"model": "x", "messages": []})
    addon.request(f)
    f.response = tflow.tresp()
    f.response.headers["content-type"] = "text/event-stream"
    addon.responseheaders(f)
    ev = {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}
    d = {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": f"pw {tok}"}}
    st = {"type": "content_block_stop", "index": 0}
    raw = b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in (ev, d, st))
    out = b"".join(f.response.stream(raw)) + f.response.stream(b"")
    assert b"Zq8!wLm2#rTyy" in out


def test_addon_drops_stale_content_length(addon):
    """Field report: replies arrived whole with a Content-Length; after restoring, the body
    length no longer matched and Claude Code hung on the connection after every reply."""
    view = addon.redactor.tokenize("DB_PASSWORD=Zq8!wLm2#rTyy")
    tok = TOKEN_RE.search(view).group(0)
    f = _req_flow("api.anthropic.com", "/v1/messages", {"model": "x", "messages": []})
    addon.request(f)
    ev = {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}}
    d = {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": f"pw {tok}"}}
    st = {"type": "message_stop"}
    raw = b"".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n".encode() for e in (ev, d, st))
    f.response = tflow.tresp(content=raw)
    f.response.headers["content-type"] = "text/event-stream; charset=utf-8"
    f.response.headers["content-length"] = str(len(raw))
    addon.responseheaders(f)
    assert "content-length" not in f.response.headers
    assert f.response.headers["transfer-encoding"] == "chunked"
    # nothing ready yet must yield no chunk at all: an empty chunk is the chunked end marker
    assert f.response.stream(raw[:5]) == []
    parts = f.response.stream(raw[5:])
    assert all(parts)
    out = b"".join(parts) + f.response.stream(b"")
    assert b"Zq8!wLm2#rTyy" in out and len(out) != len(raw)
    # HTTP/2 to the client: no length and no transfer-encoding
    f2 = _req_flow("api.anthropic.com", "/v1/messages", {"model": "x", "messages": []})
    f2.request.http_version = "HTTP/2.0"
    addon.request(f2)
    f2.response = tflow.tresp(content=raw)
    f2.response.headers["content-length"] = str(len(raw))
    f2.response.headers["content-type"] = "text/event-stream"
    addon.responseheaders(f2)
    assert "content-length" not in f2.response.headers and "transfer-encoding" not in f2.response.headers


# ------------------------------------------------------------- settings / hook
import subprocess  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _render(*args):
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "render_settings.py"), *args],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


@pytest.mark.parametrize("platform", ["posix", "windows"])
def test_render_proxy_mode(platform):
    s = _render("--mode", "proxy", "--platform", platform, "--ca", "/x/ca.pem")
    env = s["env"]
    assert "ANTHROPIC_BASE_URL" not in env and "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC" not in env
    assert env["https_proxy"] == env["HTTPS_PROXY"] == "http://127.0.0.1:8788"
    assert env["NODE_EXTRA_CA_CERTS"] == "/x/ca.pem" and env["REDACT_GUARD_MODE"] == "proxy"
    assert "disableRemoteControl" not in s
    # a proxy that holds replies until complete must not make Claude Code abort long replies
    fb, api = int(env["CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS"]), int(env["API_TIMEOUT_MS"])
    assert 300_000 <= fb <= 1_800_000 and api > fb + 1000
    m = _render("--mode", "proxy", "--platform", platform, "--managed")
    assert "allowedProviders" not in m and m["allowManagedHooksOnly"] is True


def _hook(env):
    base = {k: os.environ[k] for k in ("SYSTEMROOT", "SystemRoot", "WINDIR", "COMSPEC", "TEMP", "TMP",
                                       "SYSTEMDRIVE") if k in os.environ}
    base |= {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "REDACT_GUARD_MODE": "proxy",
             "REDACT_GUARD_URL": "http://127.0.0.1:1", "HOME": "/nonexistent-home",
             "USERPROFILE": "C:\\nonexistent-home"}
    base.update(env)
    return subprocess.run([sys.executable, str(ROOT / "hooks" / "guard.py"), "prompt-submit"],
                          input=b'{"prompt":"x"}', env=base, capture_output=True)


def test_proxy_hook_blocks_bypasses(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    good = {"HTTPS_PROXY": "http://127.0.0.1:1", "NODE_EXTRA_CA_CERTS": str(ca)}
    for bad in ({**good, "https_proxy": "http://evil:3128"},
                {**good, "NO_PROXY": "localhost,.anthropic.com"},
                {**good, "no_proxy": "*"},
                {**good, "ANTHROPIC_BASE_URL": "http://127.0.0.1:8787"},
                {**good, "NODE_EXTRA_CA_CERTS": str(tmp_path / "missing.pem")},
                {**good, "NODE_TLS_REJECT_UNAUTHORIZED": "0"},
                good):                                   # good config, but the proxy is down
        p = _hook(bad)
        assert p.returncode == 2 and b"Prompt NOT sent" in p.stderr, bad


@pytest.fixture
def egress_addon(tmp_path, monkeypatch):
    cfg = tmp_path / "rg.yaml"
    cfg.write_text(f"vault: {{dir: {tmp_path}/s, key_file: {tmp_path}/s/key}}\n"
                   f"hook_secret_file: {tmp_path}/hs\n"
                   "egress: {enabled: true, ports: [443], allow: [registry.npmjs.org, '*.pythonhosted.org']}\n")
    monkeypatch.setenv("REDACT_GUARD_CONFIG", str(cfg))
    import importlib
    import redact_guard.mitm_addon as M
    importlib.reload(M)
    return M.RedactGuardAddon()


@pytest.mark.parametrize("host,port,ok", [("registry.npmjs.org", 443, True),
                                          ("files.pythonhosted.org", 443, True),
                                          ("api.anthropic.com", 443, True),     # redacted, not filtered
                                          ("claude.ai", 443, True),
                                          ("attacker.example", 443, False),
                                          ("registry.npmjs.org", 22, False)])
def test_egress_allowlist_in_proxy_mode(egress_addon, host, port, ok):
    f = tflow.tflow()
    f.request.host, f.request.port = host, port
    egress_addon.http_connect(f)
    assert (f.response is None) == ok


def test_egress_off_by_default(addon):
    f = tflow.tflow()
    f.request.host, f.request.port = "attacker.example", 443
    addon.http_connect(f)
    assert f.response is None


def test_doctor_reports_held_replies(monkeypatch):
    from redact_guard import doctor

    class R:
        def __init__(self):
            self.rows = []

        def add(self, *a):
            self.rows.append(a)

    held = json.dumps({"event": "model_stream_start", "transfer": "length", "first_byte_ms": 7053})
    live = json.dumps({"event": "model_stream_start", "transfer": "chunked", "first_byte_ms": 900})
    monkeypatch.setattr(doctor, "_claude_settings", lambda: ({"env": {}}, []))
    r = R()
    doctor._stream_check(r, [live, held])
    assert r.rows[0][0] == "WARN" and "1 of the last 2" in r.rows[0][2] and "7.1s" in r.rows[0][2]
    monkeypatch.setattr(doctor, "_claude_settings",
                        lambda: ({"env": {"CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS": "600000"}}, []))
    r = R()
    doctor._stream_check(r, [held])
    assert r.rows[0][0] == "INFO"
    r = R()
    doctor._stream_check(r, [live])
    assert r.rows[0][0] == "PASS"
    r = R()
    doctor._stream_check(r, ['{"event": "request"}'])
    assert r.rows == []


def test_doctor_flags_stale_shell_ca(monkeypatch, tmp_path):
    from redact_guard import doctor

    class R:
        def __init__(self):
            self.rows = []

        def add(self, *a):
            self.rows.append(a)

    monkeypatch.setenv("NODE_EXTRA_CA_CERTS", str(tmp_path / "corp-ca.pem"))
    r = R()
    doctor._shell_ca_check(r, {"NODE_EXTRA_CA_CERTS": "/x/ca.pem"})
    assert r.rows[0][0] == "WARN" and "file missing" in r.rows[0][2]
    (tmp_path / "corp-ca.pem").write_text("x")
    r = R()
    doctor._shell_ca_check(r, {"NODE_EXTRA_CA_CERTS": "/x/ca.pem"})
    assert r.rows[0][0] == "INFO"
    r = R()
    doctor._shell_ca_check(r, {"NODE_EXTRA_CA_CERTS": str(tmp_path / "corp-ca.pem")})
    assert r.rows == []


def test_uplink_keeps_dictionary_words(redactor):
    """Field report: a DB password "root" turned "the root pom.xml" into a token on the phone."""
    redactor.tokenize("DB_USER=root\nDB_PASSWORD=root\nKAFKA=http://kafka:9092\nAPI_PASSWORD=Xk9#mP2$vL8q")
    u = UplinkRedactor(redactor)
    assert u.text("build from the root pom.xml") == "build from the root pom.xml"
    assert u.text("kafka topic orders") == "kafka topic orders"
    assert "root" not in u.text("password: root") and "root" not in u.text("DB_PASSWORD=root")
    assert "Xk9#mP2$vL8q" not in u.text("the password is Xk9#mP2$vL8q")


def test_downlink_is_traced_not_changed(addon):
    """Field report: phone messages had no effect and left no trace. The audit log now shows
    what arrives from the phone (type names and sizes only); nothing is modified."""
    seen = []
    addon._audit = lambda **rec: seen.append(rec)
    secret_msg = b'{"type":"user","message":{"content":"password is Zq8!wLm2#rTyy"}}'
    # SSE downlink stream
    f = tflow.tflow(resp=True)
    f.request.host = "api.anthropic.com"
    f.request.headers["host"] = "api.anthropic.com"
    f.request.method = "GET"
    f.request.path = "/v1/code/sessions/cse_01ABCdefGHIjkl/worker/events/stream"
    f.response.headers["content-type"] = "text/event-stream"
    addon.responseheaders(f)
    raw = b"event: message\ndata: " + secret_msg + b"\n\nevent: ping\ndata: {\"type\":\"ping\"}\n\n"
    out = b"".join(f.response.stream(raw[:30])) + b"".join(f.response.stream(raw[30:])) + f.response.stream(b"")
    assert out == raw
    assert seen[0]["event"] == "downlink_open"
    dl = [r for r in seen if r["event"] == "downlink"]
    assert len(dl) == 1 and dl[0]["types"] == ["user"] and dl[0]["via"] == "stream"
    # polled JSON
    seen.clear()
    g = tflow.tflow(resp=True)
    g.request.host = "api.anthropic.com"
    g.request.headers["host"] = "api.anthropic.com"
    g.request.method = "GET"
    g.request.path = "/v1/code/sessions/cse_01ABCdefGHIjkl/worker/events?after=1"
    g.response = tflow.tresp(content=b'{"data":[' + secret_msg + b']}')
    addon.response(g)
    assert seen and seen[0]["types"] == ["user"] and seen[0]["via"] == "poll"
    # WebSocket frame from the server
    seen.clear()
    w = tflow.twebsocketflow()
    w.request.host = "api.anthropic.com"
    w.request.headers["host"] = "api.anthropic.com"
    w.request.path = "/v1/code/sessions/cse_01ABCdefGHIjkl/ws"
    w.websocket.messages.append(websocket.WebSocketMessage(1, False, secret_msg))
    addon.websocket_message(w)
    assert w.websocket.messages[-1].content == secret_msg
    assert seen[0]["types"] == ["user"] and seen[0]["via"] == "ws"
    assert "Zq8" not in json.dumps(seen)
