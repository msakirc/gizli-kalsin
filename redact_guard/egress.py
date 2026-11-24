"""Tiny HTTPS CONNECT proxy with a host allowlist (container mode).

The dev container has no route to the internet or your databases. Package
registries etc. are reached through this proxy, which only tunnels to
allowlisted hosts on allowlisted ports. api.anthropic.com is refused here
unconditionally: model traffic must go through the redacting gateway.
"""
from __future__ import annotations

import asyncio
import fnmatch
import logging

log = logging.getLogger("redact_guard.egress")

HARD_DENY = ("api.anthropic.com", "*.anthropic.com")


class EgressProxy:
    def __init__(self, allow: list[str], ports: list[int] | None = None):
        self.allow = [a.lower() for a in allow]
        self.ports = set(ports or [443])

    def allowed(self, host: str, port: int) -> bool:
        h = host.lower().rstrip(".")
        if any(fnmatch.fnmatchcase(h, d) for d in HARD_DENY):
            return False
        if port not in self.ports:
            return False
        return any(h == a or (a.startswith("*.") and (h.endswith(a[1:]) or h == a[2:]))
                   for a in self.allow)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15)
        except Exception:
            writer.close()
            return
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split()
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        host, _, port_s = parts[1].rpartition(":")
        host = host.strip("[]")
        try:
            port = int(port_s)
        except ValueError:
            port = -1
        if not self.allowed(host, port):
            log.warning('{"event":"egress_denied","host":"%s","port":%s}', host, port)
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        try:
            ur, uw = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=15)
        except Exception:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        log.info('{"event":"egress_allowed","host":"%s","port":%s}', host, port)
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        async def pipe(r, w):
            try:
                while data := await r.read(65536):
                    w.write(data)
                    await w.drain()
            except Exception:
                pass
            finally:
                w.close()
        await asyncio.gather(pipe(reader, uw), pipe(ur, writer))

    async def serve(self, host: str, port: int):
        server = await asyncio.start_server(self.handle, host, port)
        return server
