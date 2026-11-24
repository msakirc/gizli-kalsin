"""Server-sent-event restorer for streamed Messages API responses.

* text blocks: restored as they stream, holding back a tail that might be the
  start of a token split across two chunks.
* tool_use blocks: input is buffered until ``content_block_stop``, then the
  complete JSON is restored per tool policy (and DB/secret checks applied)
  and emitted as one ``input_json_delta``. Working on parsed JSON means
  restored values are always correctly JSON-escaped.
* thinking / signatures / server tools / pings: forwarded byte-for-byte.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import vault as V
from .engine import Redactor, Stats


def _event(name: str, data: dict) -> bytes:
    return f"event: {name}\ndata: {json.dumps(data, ensure_ascii=False, separators=(',', ':'))}\n\n".encode()


def split_safe(buf: str) -> tuple[str, str]:
    """Split ``buf`` into (emit_now, hold_back) so no token is cut in half.
    Holds back from the EARLIEST position in the tail that could start a token
    ("pw is RDX_SECR" holds "RDX_SECR", not just the last "R")."""
    window_start = max(0, len(buf) - 40)
    idx = buf.find("R", window_start)
    while idx != -1:
        tail = buf[idx:]
        if V.TOKEN_RE.fullmatch(tail):
            return buf, ""                       # complete token: fixed-length, emit it
        if V.TOKEN_PREFIX_RE.match(tail):
            return buf[:idx], tail
        idx = buf.find("R", idx + 1)
    return buf, ""


@dataclass
class _Block:
    type: str
    start_event: dict | None = None
    text_buf: str = ""
    json_buf: str = ""
    name: str = ""


@dataclass
class StreamRestorer:
    redactor: Redactor
    stats: Stats = field(default_factory=Stats)
    _raw: bytes = b""
    _blocks: dict = field(default_factory=dict)

    @property
    def holding(self) -> bool:
        return any(b.type == "tool_use" or b.text_buf for b in self._blocks.values())

    def feed(self, chunk: bytes) -> bytes:
        self._raw += chunk
        out = []
        while True:
            # events end with a blank line; tolerate \r\n
            i = self._raw.find(b"\n\n")
            j = self._raw.find(b"\r\n\r\n")
            if i == -1 and j == -1:
                break
            if j != -1 and (i == -1 or j < i):
                ev, self._raw = self._raw[:j], self._raw[j + 4:]
            else:
                ev, self._raw = self._raw[:i], self._raw[i + 2:]
            out.append(self._handle(ev))
        return b"".join(out)

    def flush(self) -> bytes:
        rest, self._raw = self._raw, b""
        return rest

    # ----------------------------------------------------------------------
    def _handle(self, raw_event: bytes) -> bytes:
        text = raw_event.decode("utf-8")
        name, data_lines, others = None, [], []
        for line in text.splitlines():
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip(" "))
            else:
                others.append(line)
        passthrough = raw_event + b"\n\n"
        if not data_lines:
            return passthrough                     # comments / pings without data
        try:
            data = json.loads("\n".join(data_lines))
        except json.JSONDecodeError:
            return passthrough
        etype = data.get("type", name)

        if etype == "content_block_start":
            idx = data.get("index")
            cb = data.get("content_block") or {}
            blk = _Block(type=cb.get("type", ""), name=cb.get("name", ""))
            self._blocks[idx] = blk
            if blk.type == "tool_use":
                blk.start_event = data
                init = cb.get("input")
                if init:
                    blk.json_buf = json.dumps(init)
                return b""                         # held until stop
            if blk.type == "text" and cb.get("text"):
                cb["text"] = self.redactor.restore_text(cb["text"])
                return _event(name or etype, data)
            return passthrough

        if etype == "content_block_delta":
            idx = data.get("index")
            blk = self._blocks.get(idx)
            delta = data.get("delta") or {}
            if blk is None:
                return passthrough
            if blk.type == "tool_use" and delta.get("type") == "input_json_delta":
                blk.json_buf += delta.get("partial_json", "")
                return b""
            if blk.type == "text" and delta.get("type") == "text_delta":
                blk.text_buf += delta.get("text", "")
                emit, blk.text_buf = split_safe(blk.text_buf)
                if not emit:
                    return b""
                delta["text"] = self.redactor.restore_text(emit)
                return _event(name or etype, data)
            return passthrough

        if etype == "content_block_stop":
            idx = data.get("index")
            blk = self._blocks.pop(idx, None)
            if blk is None:
                return passthrough
            out = b""
            if blk.type == "text" and blk.text_buf:
                out += _event("content_block_delta", {
                    "type": "content_block_delta", "index": idx,
                    "delta": {"type": "text_delta", "text": self.redactor.restore_text(blk.text_buf)}})
            elif blk.type == "tool_use":
                try:
                    tool_input = json.loads(blk.json_buf) if blk.json_buf.strip() else {}
                except json.JSONDecodeError:
                    tool_input = None
                if tool_input is None:
                    # unparseable: forward as-is; tokens stay tokens (nothing restored)
                    new_json = blk.json_buf
                else:
                    new_input = self.redactor.process_tool_input(blk.name, tool_input, self.stats)
                    new_json = json.dumps(new_input, ensure_ascii=False)
                start = blk.start_event or {}
                cb = dict(start.get("content_block") or {})
                cb["input"] = {}
                start = dict(start, content_block=cb)
                out += _event("content_block_start", start)
                out += _event("content_block_delta", {
                    "type": "content_block_delta", "index": idx,
                    "delta": {"type": "input_json_delta", "partial_json": new_json}})
            return out + passthrough

        return passthrough
