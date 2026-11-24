"""Redaction for everything Claude Code sends to Anthropic *besides* /v1/messages.

The main case is Remote Control: Claude Code mirrors the session (its cwd,
Claude's replies as shown in your terminal, tool inputs with real values,
command output) to Anthropic over a WebSocket (NDJSON frames) or SSE + POST,
and the transcript is stored server-side so your phone can show it. Those
uploads are built from the *local* session, which holds real values, so they
must be redacted here before they leave.

Rules:
* every string value is redacted with the normal detectors, plus an
  exact-match pass over *every* value the vault knows (any class, len >= 4);
  usernames included, because over-redaction only affects what the phone shows;
* protocol fields (ids, types, signatures, timestamps) are left alone, so
  the phone can still pair tool calls with results;
* Claude Code's own credentials and auth endpoints are never touched;
* bodies that can't be parsed are refused (fail closed);
* a canary re-checks the result and refuses on any surviving vault value.
"""
from __future__ import annotations

import json
import re

from . import vault as V

from .engine import BINARY_BLOCKS, LeakDetected, Redactor, exact_eligible

STRUCTURAL_KEYS = {
    "type", "subtype", "id", "uuid", "session_id", "sessionId", "request_id", "requestId",
    "tool_use_id", "toolUseId", "parent_tool_use_id", "message_id", "messageId", "event_id",
    "index", "model", "role", "stop_reason", "stop_sequence", "signature", "mode", "status",
    "version", "timestamp", "created_at", "updated_at", "ts", "seq", "sequence", "epoch",
    "cursor", "media_type", "cache_control", "permissionMode", "permission_mode",
    "apiKeySource", "output_style", "name", "event", "kind", "level", "code_name",
    "is_error", "isError", "decision", "behavior", "tool_name", "toolName", "subagent_type",
}
CREDENTIAL_KEYS = {
    "access_token", "refresh_token", "id_token", "token", "code", "code_verifier", "state",
    "client_id", "client_secret", "authorization", "Authorization", "session_token",
    "worker_token", "ingress_token", "x-api-key", "api_key", "nonce",
}
_ID_KEY_RE = re.compile(r"(?:^|_)(?:id|ids|uuid)$|[a-z]Id$")
# Paths whose bodies are Claude Code's own auth: forwarded untouched.
AUTH_PATH_RE = re.compile(r"(?i)(?:^|/)(?:oauth|login|logout|auth|token|tokens|refresh)(?:/|$|\?)|"
                          r"^/api/hello$|^/v1/models(?:/[\w.\-]+)?$")


# A structural/ID key keeps its value only when the value LOOKS structural: an id, an enum,
# a timestamp, a tool name. `{"name": "Ayşe Demir"}` or `{"user_id": "a@b.com"}` is redacted.
_STRUCTURAL_VALUE_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"   # uuid
    r"|(?:toolu|srvtoolu|msg|req|sess|session|evt|cse|run|job|tool|file|sub|user|org|env|bridge|"
    r"cc|ws|turn|chat|conv|item|call)_[A-Za-z0-9_\-]{4,80}"                         # prefixed ids
    r"|(?=[0-9a-f]*[a-f])[0-9a-f]{6,64}|\d{1,9}"                                                     # hex, small numbers
    r"|\d{4}-\d{2}-\d{2}[T ][\d:.]+(?:Z|[+\-]\d{2}:?\d{2})?"                      # ISO time
    r"|[a-z][a-z0-9_\-]{0,40}|[A-Z][A-Za-z]{0,30}|mcp__[\w\-]{1,64}__[\w\-]{1,64}"   # enums, tools
    r"|claude-[a-z0-9.\-]{1,40}|[a-z]+/[a-z0-9.+\-]+")                              # models, mime
# Subtrees that carry content (tool inputs, messages, results): no key-based exemption there.
CONTENT_KEYS = {"input", "content", "message", "messages", "text", "result", "tool_input",
                "arguments", "args", "params", "data", "payload", "output", "stdout", "stderr",
                "prompt", "description", "summary", "body", "value", "values", "items"}


class Uninspectable(ValueError):
    """A body we can't parse. Messages are ours and never contain body content."""

    def __init__(self, msg: str, binary: bool = False):
        super().__init__(msg)
        self.binary = binary


class UplinkRedactor:
    def __init__(self, redactor: Redactor, min_len: int = 4, binary: str = "strip"):
        self.r = redactor
        self.min_len = min_len
        self.binary = binary
        self._rx = None
        self._rx_key = None
        self._map: dict[str, str] = {}

    # --------------------------------------------------------------- core
    def _index(self):
        """Every value the vault knows, any class, len >= min_len (incremental)."""
        from .exactindex import ExactIndex
        if not hasattr(self, "_idx"):
            self._idx, self._seen = ExactIndex(), 0
        items = list(self.r.vault._by_token.items())
        for tok, e in items[self._seen:]:
            if len(e.value) < self.min_len or e.value in self.r.dcfg.allow_values:
                continue
            if e.cls in (V.USER,):
                # A username is often also a database, schema or service name ("orders"). Replace
                # it everywhere only when it's distinctive, and never inside a host or path.
                if not re.search(r"[\d._]", e.value):
                    continue        # plain word: hidden by context only, like on the model side
                self._idx.add(e.value, tok, whole_name=True)
            elif e.cls in (V.SECRET, V.CUSTOM, V.HOST) and not exact_eligible(e.value, e.cls):
                # same rule as the model side: a dictionary-like password ("root", "admin") or a
                # single-label host ("kafka") is hidden where it is used as a value (tokenize
                # above), not wherever the word appears ("the root pom.xml")
                continue
            else:
                self._idx.add(e.value, tok)
        self._seen = len(items)
        return self._idx

    def text(self, s: str) -> str:
        if not s:
            return s
        out = self.r.tokenize(s)
        idx = self._index()
        if len(idx):
            parts, pos = [], 0
            for ms, me, got, _ in idx.find(out):
                if "RDX_" in out[max(0, ms - 30):ms] and re.search(r"RDX_[A-Z0-9]*_?[0-9a-f]*$", out[max(0, ms - 30):ms]):
                    continue                     # inside an existing token
                parts += [out[pos:ms], idx.values[got]]
                pos = me
            parts.append(out[pos:])
            out = "".join(parts)
        return out

    def walk(self, obj, key: str | None = None, in_content: bool = False):
        if isinstance(obj, str):
            if key is not None and not in_content and key in CREDENTIAL_KEYS:
                return obj                       # Claude Code's own credentials (protocol level)
            if key is not None and (key in STRUCTURAL_KEYS or _ID_KEY_RE.search(key)) \
                    and _STRUCTURAL_VALUE_RE.fullmatch(obj):
                return obj
            if key is not None:
                obj = self._keyed(key, obj)
            return self.text(obj)
        if isinstance(obj, list):
            return [self.walk(x, key, in_content) for x in obj]
        if isinstance(obj, dict):
            if obj.get("type") in BINARY_BLOCKS and self.binary == "strip":
                return {"type": "text", "text": f"[redact-guard: {obj.get('type')} not mirrored]"}
            return {k: self.walk(v, k, in_content or k in CONTENT_KEYS) for k, v in obj.items()}
        return obj

    def _keyed(self, key: str, value: str) -> str:
        """{"token": "q7Xv..."}: the JSON key says what the value is, even with no `key=`."""
        from . import detectors as D
        cls = D.key_class(key)
        if not cls:
            return value
        spans = D.value_spans(cls, value, 0, self.r.dcfg, unquoted=False, key=key)
        for sp in sorted(spans, key=lambda x: -x.start):
            v = value[sp.start:sp.end]
            value = value[:sp.start] + self.r.vault.token_for(v, sp.cls) + value[sp.end:]
        return value

    # ----------------------------------------------------------- formats
    def json_text(self, raw: str) -> str:
        """JSON document or NDJSON (one JSON value per line, as Remote Control sends)."""
        lines = raw.split("\n")
        out = []
        for ln in lines:
            if not ln.strip():
                out.append(ln)
                continue
            try:
                val = json.loads(ln)
            except json.JSONDecodeError:
                return self._whole_json(raw)
            out.append(json.dumps(self.walk(val), ensure_ascii=False, separators=(",", ":")))
        return "\n".join(out)

    def _whole_json(self, raw: str) -> str:
        try:
            val = json.loads(raw)
        except ValueError:
            raise Uninspectable("body is not valid JSON/NDJSON") from None
        return json.dumps(self.walk(val), ensure_ascii=False, separators=(",", ":"))

    def body(self, content: bytes, content_type: str = "") -> bytes:
        """Redact a request body. Raises ValueError if it can't be inspected."""
        if not content:
            return content
        ct = content_type.lower()
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as e:
            raise Uninspectable(f"binary body ({ct or 'no content-type'}) can't be inspected", binary=True) from e
        stripped = text.lstrip()
        if "json" in ct or stripped[:1] in ("{", "["):
            out = self.json_text(text)
        elif "x-www-form-urlencoded" in ct:
            from urllib.parse import parse_qsl, urlencode
            pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=False)
            out = urlencode([(k, v if k in CREDENTIAL_KEYS else self.text(v)) for k, v in pairs])
            self.canary(out)
            self.canary("\n".join(v for _, v in parse_qsl(out, keep_blank_values=True)))
            return out.encode("utf-8")
        elif ct.startswith("text/"):
            out = self.text(text)
        else:
            raise Uninspectable(f"body of type {ct or 'unknown'} can't be inspected")
        self.canary(out)
        return out.encode("utf-8")

    def ws_text(self, frame: str) -> str:
        out = self.json_text(frame) if frame.strip()[:1] in ("{", "[") else self.text(frame)
        self.canary(out)
        return out

    def canary(self, out: str) -> None:
        idx = self._index()
        for ms, me, got, _ in idx.find(out):
            if not re.search(r"RDX_[A-Z0-9]*_?[0-9a-f]*$", out[max(0, ms - 30):ms]):
                raise LeakDetected("a vaulted value survived uplink redaction")
