"""The redacting gateway. Point Claude Code at it with ANTHROPIC_BASE_URL.

Fail-closed: if anything goes wrong while redacting, the request is refused,
never forwarded as-is.
"""
from __future__ import annotations

import asyncio
import gzip
import json
import logging
import time
import uuid
import zlib

from aiohttp import ClientSession, ClientTimeout, web

from .engine import LeakDetected, Redactor
from .sse import StreamRestorer

log = logging.getLogger("redact_guard")

REDACT_PATHS = {"/v1/messages", "/v1/messages/count_tokens"}
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
              "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
              "accept-encoding", "content-encoding"}
KEEPALIVE_EVERY = 10.0


def _error(status: int, message: str, etype: str = "api_error") -> web.Response:
    return web.json_response({"type": "error", "error": {"type": etype, "message": message}},
                             status=status)


class Gateway:
    def __init__(self, redactor: Redactor, upstream: str = "https://api.anthropic.com",
                 api_key: str | None = None, unknown_post: str = "block",
                 audit_log=None, upstream_proxy: str | None = None,
                 proxy_auth: str | None = None, ca_bundle: str | None = None,
                 health_secret: bytes | None = None):
        self.redactor = redactor
        self.health_secret = health_secret
        self.upstream = upstream.rstrip("/")
        self.api_key = api_key
        self.unknown_post = unknown_post
        self.audit_log = audit_log
        self.session: ClientSession | None = None
        # chain behind the machine's existing proxy, trusting its TLS-inspection CA
        self.upstream_proxy = upstream_proxy
        self.proxy_auth = None
        if proxy_auth:
            from aiohttp import BasicAuth
            u, _, pw = proxy_auth.partition(":")
            self.proxy_auth = BasicAuth(u, pw)
        from .upstream import ssl_context
        self.ssl_ctx = ssl_context(ca_bundle)

    def app(self) -> web.Application:
        app = web.Application(client_max_size=256 * 1024 * 1024)
        app.router.add_get("/healthz", self.healthz)
        app.router.add_route("*", "/{tail:.*}", self.handle)
        app.on_startup.append(self._start)
        app.on_cleanup.append(self._stop)
        return app

    async def _start(self, app):
        self.session = ClientSession(timeout=ClientTimeout(total=None, sock_connect=30, sock_read=900),
                                     auto_decompress=True)

    async def _stop(self, app):
        if self.session:
            await self.session.close()

    async def healthz(self, request: web.Request) -> web.Response:
        from . import __version__
        out = {"ok": True, "service": "redact-guard", "mode": "gateway", "version": __version__,
               "vault_entries": len(self.redactor.vault)}
        nonce = request.query.get("nonce")
        if nonce and self.health_secret:
            from .healthproof import proof
            out["proof"] = proof(self.health_secret, nonce)
        return web.json_response(out)

    def _net(self) -> dict:
        kw = {"ssl": self.ssl_ctx}
        if self.upstream_proxy:
            kw["proxy"] = self.upstream_proxy
            if self.proxy_auth:
                kw["proxy_auth"] = self.proxy_auth
        return kw

    # ------------------------------------------------------------------
    def _headers(self, request: web.Request) -> dict:
        h = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
        h["Accept-Encoding"] = "identity"
        if self.api_key:
            # proxy-held key: the client's credential (if any) never reaches upstream
            h.pop("Authorization", None)
            h.pop("authorization", None)
            for k in list(h):
                if k.lower() == "x-api-key":
                    h.pop(k)
            h["x-api-key"] = self.api_key
        return h

    def _audit(self, rec: dict) -> None:
        rec["ts"] = round(time.time(), 3)
        line = json.dumps(rec, ensure_ascii=False)
        log.info(line)
        if self.audit_log:
            self.audit_log.write(line + "\n")
            self.audit_log.flush()

    async def handle(self, request: web.Request) -> web.StreamResponse:
        rid = uuid.uuid4().hex[:12]
        path = request.path
        if request.method == "POST" and path in REDACT_PATHS:
            return await self._messages(request, rid)
        if request.method in ("GET", "HEAD") and not request.can_read_body:
            return await self._passthrough(request, rid)
        if self.unknown_post == "passthrough":
            return await self._passthrough(request, rid)
        self._audit({"id": rid, "event": "blocked_unknown_request", "method": request.method,
                     "path": path})
        return _error(403, f"redact-guard: {request.method} {path} is not on the redaction "
                           f"allowlist and was not forwarded", "permission_error")

    async def _passthrough(self, request: web.Request, rid: str) -> web.StreamResponse:
        assert self.session
        url = self.upstream + request.path_qs
        async with self.session.request(request.method, url, headers=self._headers(request),
                                        allow_redirects=False, **self._net()) as up:
            body = await up.read()
            hdrs = {k: v for k, v in up.headers.items() if k.lower() not in HOP_BY_HOP}
            self._audit({"id": rid, "event": "passthrough", "method": request.method,
                         "path": request.path, "status": up.status})
            return web.Response(status=up.status, body=body, headers=hdrs)

    async def _read_json(self, request: web.Request) -> dict:
        raw = await request.read()
        enc = request.headers.get("Content-Encoding", "").lower()
        if enc == "gzip":
            raw = gzip.decompress(raw)
        elif enc == "deflate":
            raw = zlib.decompress(raw)
        elif enc not in ("", "identity"):
            raise ValueError(f"unsupported request Content-Encoding {enc}")
        return json.loads(raw)

    async def _messages(self, request: web.Request, rid: str) -> web.StreamResponse:
        assert self.session
        t0 = time.monotonic()
        try:
            body = await self._read_json(request)
            body, stats = self.redactor.redact_request(body)
        except LeakDetected as e:
            self._audit({"id": rid, "event": "canary_blocked", "path": request.path, "reason": str(e)})
            return _error(500, f"redact-guard refused to forward the request: {e}")
        except Exception as e:  # fail closed
            log.exception("redaction failed")
            self._audit({"id": rid, "event": "redaction_error", "path": request.path,
                         "error": type(e).__name__})
            return _error(500, f"redact-guard: redaction failed ({type(e).__name__}); "
                               f"request was NOT forwarded")
        payload = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
        headers = self._headers(request)
        headers["Content-Type"] = "application/json"
        url = self.upstream + request.path_qs
        self._audit({"id": rid, "event": "request", "path": request.path,
                     "session": request.headers.get("x-claude-code-session-id"),
                     "redact_ms": round((time.monotonic() - t0) * 1000, 1), **stats.as_dict()})

        up = await self.session.post(url, data=payload, headers=headers, allow_redirects=False,
                                     **self._net())
        try:
            ctype = up.headers.get("Content-Type", "")
            hdrs = {k: v for k, v in up.headers.items() if k.lower() not in HOP_BY_HOP}
            if "text/event-stream" in ctype and up.status == 200:
                return await self._stream(request, up, hdrs, rid)
            raw = await up.read()
            if up.status == 200 and "application/json" in ctype and request.path == "/v1/messages":
                try:
                    data = json.loads(raw)
                    data = self.redactor.process_response_json(data)
                    raw = json.dumps(data, ensure_ascii=False).encode()
                except Exception as e:
                    # fail closed: an unchecked response could carry a database command
                    log.exception("response restore failed; refusing")
                    return web.json_response({"type": "error", "error": {
                        "type": "api_error", "message": f"redact-guard: model response couldn't be "
                                                        f"checked ({type(e).__name__})"}}, status=502)
            # errors are forwarded unmodified (Claude Code's retry logic reads them)
            return web.Response(status=up.status, body=raw, headers=hdrs)
        finally:
            up.release()

    async def _stream(self, request, up, hdrs, rid) -> web.StreamResponse:
        resp = web.StreamResponse(status=up.status, headers=hdrs)
        await resp.prepare(request)
        restorer = StreamRestorer(self.redactor)
        queue: asyncio.Queue = asyncio.Queue()

        async def pump():
            try:
                async for chunk in up.content.iter_any():
                    await queue.put(chunk)
            finally:
                await queue.put(None)

        task = asyncio.create_task(pump())
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(queue.get(), timeout=KEEPALIVE_EVERY)
                except asyncio.TimeoutError:
                    # we may be holding a tool_use block; keep Claude Code's
                    # stream watchdog fed with an SSE comment line
                    await resp.write(b": redact-guard keepalive\n\n")
                    continue
                if chunk is None:
                    break
                out = restorer.feed(chunk)
                if out:
                    await resp.write(out)
            tail = restorer.flush()
            if tail:
                await resp.write(tail)
        finally:
            task.cancel()
        if restorer.stats.blocked_tools:
            self._audit({"id": rid, "event": "response_blocked_tools",
                         "tools": restorer.stats.blocked_tools})
        await resp.write_eof()
        return resp
