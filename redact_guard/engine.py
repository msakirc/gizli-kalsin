"""Redaction engine: tokenize outgoing requests, restore incoming responses."""
from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import Counter, OrderedDict
from dataclasses import dataclass, field

from . import detectors as D
from . import policy as P
from . import vault as V
from .exactindex import ExactIndex

log = logging.getLogger("redact_guard")

# Block types whose fields we never touch (signatures / server-side state).
PASSTHROUGH_BLOCKS = {"thinking", "redacted_thinking", "server_tool_use",
                      "web_search_tool_result", "web_fetch_tool_result",
                      "code_execution_tool_result", "bash_code_execution_tool_result",
                      "text_editor_code_execution_tool_result", "mcp_tool_use",
                      "mcp_tool_result", "container_upload", "tool_reference"}
BINARY_BLOCKS = {"image", "document"}


class LeakDetected(Exception):
    """Raised when the canary finds a known secret in an outgoing body."""


@dataclass
class Stats:
    counts: Counter = field(default_factory=Counter)
    blocked_tools: list[str] = field(default_factory=list)
    stripped_binary: int = 0

    def as_dict(self) -> dict:
        return {"redacted": dict(self.counts), "blocked_tools": self.blocked_tools,
                "stripped_binary": self.stripped_binary}


@dataclass
class EngineConfig:
    binary_blocks: str = "strip"         # strip | allow
    restore_in_text: bool = True
    restore: dict = field(default_factory=lambda: dict(P.DEFAULT_RESTORE))
    block_db_in_responses: bool = True
    canary: bool = True
    canary_min_len: int = 8
    cache_size: int = 20000


class Redactor:
    def __init__(self, vault: V.Vault, dcfg: D.DetectorConfig | None = None,
                 ecfg: EngineConfig | None = None):
        self.vault = vault
        self.dcfg = dcfg or D.DetectorConfig()
        self.ecfg = ecfg or EngineConfig()
        self._cache: OrderedDict[tuple[int, str], tuple[str, Counter]] = OrderedDict()
        self._index = ExactIndex()
        self._indexed = 0
        self._exact_ver = -1

    # ------------------------------------------------------------ tokenize
    def tokenize(self, text: str, stats: Stats | None = None) -> str:
        if not text:
            return text
        key = (self.vault.version, text)
        hit = self._cache.get(key)
        if hit is not None:
            self._cache.move_to_end(key)
            out, counts = hit
        else:
            out, counts = self._tokenize_uncached(text)
            # the vault may have grown while tokenizing; key by the new version
            self._cache[(self.vault.version, text)] = (out, counts)
            if len(self._cache) > self.ecfg.cache_size:
                self._cache.popitem(last=False)
        if stats is not None:
            stats.counts.update(counts)
        return out

    def _tokenize_uncached(self, text: str) -> tuple[str, Counter]:
        split = _split_line_prefixes(text)
        if split is not None and any(p and not _READ_PREFIX_RE.fullmatch(p) for p in split[0]):
            # `host:port:db:user:pw` (.pgpass) looks like grep -n output: catch whole-line
            # formats on the unsplit text first, then split what's left.
            text, pre = self._tokenize_plain(text, (D.structured_pairs,))
            split = _split_line_prefixes(text)
        else:
            pre = Counter()
        if split is not None:
            # Read / grep -n output: detect on the file content, keep the prefixes.
            prefixes, lines = split
            body = "\n".join(lines)
            out, counts = self._tokenize_plain(body)
            counts += pre
            out_lines = out.split("\n")
            if len(out_lines) == len(lines):
                # grep prefixes are file paths: they can hold a home dir or a hostname too
                done: dict[str, str] = {}
                for p in prefixes:
                    if p and p not in done and not _READ_PREFIX_RE.fullmatch(p):
                        done[p] = self._tokenize_plain(p)[0]
                return "\n".join(done.get(p, p) + l for p, l in zip(prefixes, out_lines)), counts
            # a multi-line value (e.g. a private key) collapsed into one token:
            # fall back to the prefixed text; values learned above still apply.
        return self._tokenize_plain(text)

    def _tokenize_plain(self, text: str, pipeline=None) -> tuple[str, Counter]:
        counts: Counter = Counter()
        hidden = self._obfuscated_values(text) if pipeline is None else []
        for det in (pipeline or D.PIPELINE):
            spans = list(det(text, self.dcfg))
            if not spans:
                continue
            taken = [m.span() for m in V.TOKEN_RE.finditer(text)]
            spans.sort(key=lambda s: (s.start, -(s.end - s.start)))
            chosen: list[D.Span] = []
            last_end = -1
            for s in spans:
                if s.start >= s.end or s.start < last_end:
                    continue
                if any(s.start < te and ts < s.end for ts, te in taken):
                    continue
                val = text[s.start:s.end]
                if val in self.dcfg.allow_values or not val.strip():
                    continue
                if self.dcfg.allow_digests and \
                        hashlib.sha256(val.encode()).hexdigest() in self.dcfg.allow_digests:
                    continue
                chosen.append(s)
                last_end = s.end
            if not chosen:
                continue
            parts, prev = [], 0
            for s in chosen:
                val = text[s.start:s.end]
                tok = self.vault.token_for(val, s.cls, exact=exact_eligible(val, s.cls))
                for lv, lc in s.learn:
                    self.vault.token_for(lv, lc, exact=exact_eligible(lv, lc))
                parts.append(text[prev:s.start])
                parts.append(tok)
                prev = s.end
                counts[s.cls] += 1
            parts.append(text[prev:])
            text = "".join(parts)
        # exact-match pass: every value the vault has ever seen, anywhere.
        for v, cls in hidden:
            if v in text:
                text = text.replace(v, self.vault.token_for(v, cls, exact=exact_eligible(v, cls)))
                counts[cls] += 1
        idx = self._exact_index()
        if len(idx):
            out, pos = [], 0
            # never match inside an existing token
            bounds = [(m.start(), m.end()) for m in V.TOKEN_RE.finditer(text)] + [(len(text), len(text))]
            for ts, te in bounds:
                for ms, me, got, strong in idx.find(text, pos, ts):
                    out.append(text[pos:ms])
                    tok = idx.values.get(got)
                    if tok is None:          # case variant of a strong secret: its own token
                        tok = self.vault.token_for(got, V.SECRET, exact=False)
                    out.append(tok)
                    counts["EXACT"] += 1
                    pos = me
                out.append(text[pos:te])
                pos = te
            text = "".join(out)
        return text, counts

    # Obfuscated keys: pass\u200bword, pаssword (Cyrillic a), password&#61;x, "pa\u0073s": x.
    _ZW_RE = re.compile("[\u200b-\u200f\u2060\ufeff\u00ad]")
    _HOMOGLYPHS = str.maketrans("аеорсухіѕјАВЕКМНОРСТХІЅЈԁԛԝαοτνκρεΑΒΕΗΙΚΜΝΟΡΤΧΥΖ",
                                "aeopcyxisjABEKMHOPCTXISJdqwaotvkpeABEHIKMNOPTXYZ")
    _OBFUSCATION_HINT = re.compile("[\u200b-\u200f\u2060\ufeff\u00ad\u0370-\u04ff]|&#|\\\\u00|\"\\s*\\+\\s*\"")

    def _obfuscated_values(self, text: str) -> list[tuple[str, str]]:
        if not self._OBFUSCATION_HINT.search(text):
            return []
        norm = self._ZW_RE.sub("", text).translate(self._HOMOGLYPHS)
        norm = re.sub(r"&#(\d{1,7});", lambda m: chr(int(m.group(1))) if int(m.group(1)) < 0x110000 else m.group(0), norm)
        norm = re.sub(r"&#x([0-9a-fA-F]{1,6});", lambda m: chr(int(m.group(1), 16)), norm)
        norm = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), norm)
        pieces: dict[str, list[str]] = {}

        def join(m: re.Match) -> str:
            a, b = m.group(1), m.group(2)
            pieces[a + b] = pieces.pop(a, [a]) + [b]
            return f'"{a}{b}"'
        for _ in range(8):                        # "Hunt" + "er2" + "Plain0ld"
            new = re.sub(r'"([^"\n]{1,200})"\s*\+\s*"([^"\n]{1,200})"', join, norm, count=1)
            if new == norm:
                break
            norm = new
        if norm == text:
            return []
        found: list[tuple[str, str]] = []
        for det in (D.keyed_values, D.structured_pairs, D.prose_secrets):
            for sp in det(norm, self.dcfg):
                v = norm[sp.start:sp.end]
                found += [(x, sp.cls) for x in pieces.get(v, [v])]
        return [(v, cls) for v, cls in sorted(set(found), key=lambda x: -len(x[0]))
                if len(v) >= 3 and v in text and not V.TOKEN_RE.search(v)
                and v not in self.dcfg.allow_values]

    def _exact_index(self) -> ExactIndex:
        """Incrementally add values the vault learned since the last call."""
        if self._exact_ver != self.vault.version:
            items = list(self.vault.exact_values().items())
            for v, tok in items[self._indexed:]:      # the vault only ever appends
                if v in self._index.values or v in self.dcfg.allow_values:
                    continue
                e = self.vault.lookup(tok)
                strong = bool(e and e.cls in (V.SECRET, V.PRIVKEY, V.CUSTOM) and len(v) >= 8
                              and D.looks_random(v))
                self._index.add(v, tok, strong)
            self._indexed = len(items)
            self._exact_ver = self.vault.version
        return self._index

    # ------------------------------------------------------------- restore
    def restore(self, text: str, allowed: frozenset | set,
                strict: bool | None = None) -> tuple[str, list[str]]:
        """Replace tokens whose class is in ``allowed``. Returns (text, withheld tokens).
        ``strict`` (default: when secrets aren't allowed) also withholds identity tokens whose
        value looks like a credential, whatever detector classified it."""
        if strict is None:
            strict = V.SECRET not in allowed
        withheld: list[str] = []
        if "RDX_" not in text:
            return text, withheld

        def sub(m: re.Match) -> str:
            e = self.vault.lookup(m.group(0))
            if e is None:
                return m.group(0)
            if e.cls in allowed and not (strict and e.cls not in (V.SECRET, V.PRIVKEY)
                                         and D.looks_like_secret(e.value)):
                return e.value
            withheld.append(m.group(0))
            return m.group(0)
        return V.TOKEN_RE.sub(sub, text), withheld

    # ------------------------------------------------------ request side
    def redact_request(self, body: dict) -> tuple[dict, Stats]:
        stats = Stats()
        if "system" in body:
            body["system"] = self._system(body["system"], stats)
        for msg in body.get("messages", []) or []:
            c = msg.get("content")
            if isinstance(c, str):
                msg["content"] = self.tokenize(c, stats)
            elif isinstance(c, list):
                msg["content"] = [b for b in (self._block(b, stats) for b in c) if b is not None]
        if isinstance(body.get("tools"), list):
            body["tools"] = self._tools(body["tools"], stats)
        if self.ecfg.canary:
            self.canary(_canary_view(body))
        return body, stats

    def _system(self, system, stats: Stats):
        if isinstance(system, str):
            return self.tokenize(system, stats)
        if isinstance(system, list):
            for i, b in enumerate(system):
                if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str):
                    if i == 0 and _is_attribution_block(b["text"]):
                        continue  # forward unchanged: API strips it positionally
                    b["text"] = self.tokenize(b["text"], stats)
        return system

    def _block(self, b, stats: Stats):
        if not isinstance(b, dict):
            return b
        t = b.get("type")
        if t in PASSTHROUGH_BLOCKS:
            return b
        if t in BINARY_BLOCKS:
            src = b.get("source") or {}
            if src.get("type") == "text" and isinstance(src.get("data"), str):
                src["data"] = self.tokenize(src["data"], stats)
                return b
            if self.ecfg.binary_blocks == "strip":
                stats.stripped_binary += 1
                return {"type": "text", "text": f"[redact-guard: {t} removed - binary content "
                                                f"cannot be redacted. Ask the user to describe it.]"}
            return b
        if t == "text":
            if isinstance(b.get("text"), str):
                b["text"] = self.tokenize(b["text"], stats)
            return b
        if t == "tool_use":
            b["input"] = self._walk(b.get("input"), stats)
            return b
        if t == "tool_result":
            c = b.get("content")
            if isinstance(c, str):
                b["content"] = self.tokenize(c, stats)
            elif isinstance(c, list):
                b["content"] = [x for x in (self._block(x, stats) for x in c) if x is not None]
            return b
        # unknown block types (search_result, document-like, future types): every string
        # value except protocol fields, recursively
        return self._walk_content(b, stats)

    _PROTOCOL_KEYS = {"type", "id", "tool_use_id", "signature", "cache_control", "media_type",
                      "role", "name", "citations_enabled", "encrypted_content", "encrypted_index"}

    def _walk_content(self, obj, stats: Stats, key: str | None = None):
        if isinstance(obj, str):
            return obj if key in self._PROTOCOL_KEYS else self.tokenize(obj, stats)
        if isinstance(obj, list):
            return [self._walk_content(x, stats, key) for x in obj]
        if isinstance(obj, dict):
            if obj.get("type") in PASSTHROUGH_BLOCKS:
                return obj
            return {k: self._walk_content(v, stats, k) for k, v in obj.items()}
        return obj

    _SCHEMA_TEXT_KEYS = {"description", "default", "examples", "example", "title"}

    def _tools(self, tools, stats: Stats):
        """Tool definitions: MCP servers' descriptions can name internal hosts or people. Only
        prose is redacted (description/default/examples), never names, enums or types, so
        tool calls keep working."""
        def schema(o, key=None):
            if isinstance(o, str):
                return self.tokenize(o, stats) if key in self._SCHEMA_TEXT_KEYS else o
            if isinstance(o, list):
                return [schema(x, key if key in ("examples",) else None) for x in o]
            if isinstance(o, dict):
                return {k: schema(v, k) for k, v in o.items()}
            return o
        out = []
        for t in tools if isinstance(tools, list) else []:
            if isinstance(t, dict):
                t = dict(t)
                if isinstance(t.get("description"), str):
                    t["description"] = self.tokenize(t["description"], stats)
                if isinstance(t.get("input_schema"), dict):
                    t["input_schema"] = schema(t["input_schema"])
            out.append(t)
        return out

    def _walk(self, obj, stats: Stats):
        if isinstance(obj, str):
            return self.tokenize(obj, stats)
        if isinstance(obj, list):
            return [self._walk(x, stats) for x in obj]
        if isinstance(obj, dict):
            return {k: self._walk(v, stats) for k, v in obj.items()}
        return obj

    def canary(self, body: dict) -> None:
        """Fail closed if any known value still appears in the outgoing body."""
        serialized = json.dumps(body, ensure_ascii=False)
        if re.search(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY", serialized):
            raise LeakDetected("private key header in outgoing body")
        compact_hex = re.sub(r"[^0-9a-f]", "", serialized.lower())
        if any(mk in compact_hex for mk in getattr(self.vault, "key_hex_markers", ())) or \
                any(mk in serialized for mk in getattr(self.vault, "key_b64_markers", ())):
            raise LeakDetected("bytes of the redact-guard vault key in outgoing body")
        for ms, me, got, strong in self._exact_index().find(serialized):
            if strong or me - ms >= self.ecfg.canary_min_len:
                raise LeakDetected(f"a vaulted value survived redaction (len={me - ms})")
        # values whose JSON form differs (quotes, backslashes, newlines)
        for v in self.vault.exact_values():
            esc = json.dumps(v, ensure_ascii=False)[1:-1]
            if esc != v and len(v) >= self.ecfg.canary_min_len and esc in serialized:
                raise LeakDetected("a vaulted value survived redaction (escaped form)")

    # ----------------------------------------------------- response side
    def process_tool_input(self, name: str, tool_input, stats: Stats | None = None):
        """Restore tokens per policy and enforce DB/secret blocks. Returns new input."""
        cat = P.tool_category(name)
        allowed = self.ecfg.restore.get(cat, frozenset())
        withheld: list[str] = []

        def walk(o, allow):
            if isinstance(o, str):
                s, w = self.restore(o, allow)
                withheld.extend(w)
                return s
            if isinstance(o, list):
                return [walk(x, allow) for x in o]
            if isinstance(o, dict):
                return {k: walk(v, allow) for k, v in o.items()}
            return o
        src = tool_input if tool_input is not None else {}
        if cat == "shell" and isinstance(src, dict):
            # only the command (and its working directory) runs locally; any other field
            # (Monitor's ws/url, ...) may leave the machine, so it gets nothing back.
            new = {k: walk(v, allowed if k in P.SHELL_LOCAL_FIELDS else frozenset())
                   for k, v in src.items()}
        else:
            new = walk(src, allowed)
        if cat == "shell" and isinstance(new, dict) and isinstance(new.get("command"), str):
            reason = None
            if withheld:
                reason = P.BLOCKED_SECRET_MSG.format(tokens=", ".join(sorted(set(withheld))[:5]))
            elif self.ecfg.block_db_in_responses:
                r = P.check_shell_command(new["command"])
                if r:
                    reason = P.BLOCKED_REASON_MSG.format(reason=r)
            if reason:
                new["command"] = P.blocked_command(reason)
                if stats is not None:
                    stats.blocked_tools.append(name)
                log.warning("blocked %s call: %s", name, reason)
        return new

    def restore_text(self, text: str) -> str:
        if not self.ecfg.restore_in_text:
            return text
        return self.restore(text, V.ALL_CLASSES)[0]

    def process_response_json(self, body: dict) -> dict:
        stats = Stats()
        for b in body.get("content", []) or []:
            if not isinstance(b, dict):
                continue
            if b.get("type") == "text" and isinstance(b.get("text"), str):
                b["text"] = self.restore_text(b["text"])
            elif b.get("type") == "tool_use":
                b["input"] = self.process_tool_input(b.get("name", ""), b.get("input"), stats)
        return body


_READ_PREFIX_RE = re.compile(r" *\d+[\t\u2192]")
_LINE_PREFIX_RE = re.compile(r"^( *\d+(?:\t|\u2192)|[^\s:]{1,200}:\d+[:\-])")


def _split_line_prefixes(text: str):
    """Split Claude Code Read output (`12\tline`, `12→line`) or `grep -n` output
    (`file:12:line`) into (prefixes, contents). None if the text isn't like that."""
    if "\t" not in text and "\u2192" not in text and ":" not in text:
        return None
    lines = text.split("\n")
    prefixes, contents, matched, nonempty = [], [], 0, 0
    for ln in lines:
        m = _LINE_PREFIX_RE.match(ln)
        if ln.strip():
            nonempty += 1
        if m:
            matched += 1
            prefixes.append(m.group(1))
            contents.append(ln[m.end():])
        else:
            prefixes.append("")
            contents.append(ln)
    if nonempty == 0 or matched < max(1, int(nonempty * 0.8)):
        return None
    # Read-tool numbers must count up by one (this is what tells it apart from
    # `git shortlog -sn`, whose counts are arbitrary).
    nums = [int(m.group(1)) for m in (re.fullmatch(r" *(\d+)[\t\u2192]", p) for p in prefixes if p) if m]
    if nums and any(b != a + 1 for a, b in zip(nums, nums[1:])):
        return None
    return prefixes, contents


# Classes whose values are distinctive enough to substitute *everywhere* they
# appear (the exact-match pass). Usernames are excluded: "deploy" or "admin"
# are ordinary words.
EXACT_CLASSES = {V.SECRET, V.PRIVKEY, V.EMAIL, V.IP, V.IPPRIV, V.IPV6, V.HOST,
                 V.PHONE, V.TCKN, V.VKN, V.IBAN, V.CARD, V.PERSON, V.CUSTOM}


def exact_eligible(value: str, cls: str) -> bool:
    if cls not in EXACT_CLASSES:
        return False
    if cls == V.HOST and "." not in value:
        # single-label service names (http://kafka:9092, http://eureka:8761) are words that
        # also appear in keys, paths and code; replace them only where they are used as a host.
        return False
    if cls in (V.SECRET, V.CUSTOM):
        # dictionary-like defaults ("postgres", "Welcome") would turn ordinary
        # prose into tokens; keyed detection still catches them in context.
        if re.fullmatch(r"[a-z]+|[A-Z][a-z]+|[A-Z]+", value) or len(value) < 6:
            return False
    return True


def _canary_view(body: dict) -> dict:
    """The parts of a request we redact (excludes tools, thinking, attribution)."""
    view: dict = {"messages": []}
    sysv = body.get("system")
    if isinstance(sysv, list):
        view["system"] = [b for i, b in enumerate(sysv)
                          if not (i == 0 and isinstance(b, dict) and
                                  _is_attribution_block(str(b.get("text", ""))))]
    else:
        view["system"] = sysv
    for m in body.get("messages", []) or []:
        c = m.get("content")
        if isinstance(c, list):
            c = [b for b in c if not (isinstance(b, dict) and b.get("type") in PASSTHROUGH_BLOCKS)]
        view["messages"].append(c)
    tools = body.get("tools")
    if isinstance(tools, list):
        view["tools"] = [{"description": t.get("description"), "schema": _schema_text(t.get("input_schema"))}
                         for t in tools if isinstance(t, dict)]
    return view


def _schema_text(o, key=None):
    if isinstance(o, str):
        return o if key in ("description", "default", "examples", "example", "title") else None
    if isinstance(o, list):
        return [_schema_text(x, key) for x in o]
    if isinstance(o, dict):
        return {k: _schema_text(v, k) for k, v in o.items()}
    return None


def _is_attribution_block(text: str) -> bool:
    head = text[:300]
    return head.startswith("x-anthropic-billing-header") or "cc_version=" in head
