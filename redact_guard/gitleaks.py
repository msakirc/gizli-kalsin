"""Gitleaks community rules as an extra detector.

The same rule set KeyClaw, mirage-proxy and agent-proxy build on: ~220 provider
token formats (cloud, CI, SaaS, payment, messaging, ...). The bundled file is
`rules/gitleaks.toml` (MIT, see rules/LICENSE-gitleaks); point
`detectors.gitleaks_rules` at your own file to override.

Rules are Go (RE2) regexes; the few Go-only constructs are translated, and
any rule that still doesn't compile is skipped and reported by `doctor`.
"""
from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

BUNDLED = Path(__file__).with_name("rules") / "gitleaks.toml"

_POSIX = {"[:alnum:]": "A-Za-z0-9", "[:alpha:]": "A-Za-z", "[:digit:]": "0-9", "[:upper:]": "A-Z",
          "[:lower:]": "a-z", "[:space:]": r"\s", "[:xdigit:]": "0-9A-Fa-f", "[:word:]": r"\w",
          "[:punct:]": r"!-/:-@\[-`{-~", "[:blank:]": r" \t", "[:cntrl:]": r"\x00-\x1f\x7f"}


def _scope_inline_flags(rx: str) -> str:
    """Go allows `(?i)` mid-pattern (applies to the rest of the enclosing group);
    Python only at the start. Rewrite `X(?i)Y)` as `X(?i:Y))`."""
    out, i, n = [], 0, len(rx)
    stack: list[int] = []          # per open group: number of scoped flags to close at its end
    pending_top = 0
    in_class = False
    while i < n:
        c = rx[i]
        if c == "\\" and i + 1 < n:
            out.append(rx[i:i + 2])
            i += 2
            continue
        if in_class:
            out.append(c)
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "[":
            in_class = True
            out.append(c)
            if rx[i + 1:i + 2] == "]":
                out.append("]")
                i += 1
            i += 1
            continue
        m = re.match(r"\(\?([a-zA-Z]+)\)", rx[i:])
        if m and (i > 0 or stack):
            out.append(f"(?{m.group(1)}:")
            if stack:
                stack[-1] += 1
            else:
                pending_top += 1
            i += m.end()
            continue
        if c == "(":
            stack.append(0)
            out.append(c)
        elif c == ")":
            closes = stack.pop() if stack else 0
            out.append(")" * closes + ")")
        elif c == "|" :
            # a scoped flag ends at an alternation branch in Go as well
            closes = stack[-1] if stack else pending_top
            out.append(")" * closes + "|")
            if stack:
                stack[-1] = 0
            else:
                pending_top = 0
        else:
            out.append(c)
        i += 1
    out.append(")" * pending_top)
    return "".join(out)


def go_to_python(rx: str) -> str:
    rx = _scope_inline_flags(rx)
    for k, v in _POSIX.items():
        rx = rx.replace(k, v)
    rx = rx.replace(r"\z", r"\Z")
    rx = re.sub(r"\\p\{L\}", r"[^\\W\\d_]", rx)
    rx = re.sub(r"\\x\{([0-9A-Fa-f]{1,4})\}", lambda m: "\\u" + m.group(1).zfill(4), rx)
    return rx


@dataclass
class Allow:
    regexes: list[re.Pattern] = field(default_factory=list)
    stopwords: list[str] = field(default_factory=list)
    target: str = "secret"            # secret | match | line
    condition: str = "OR"

    def hit(self, secret: str, match: str, line: str) -> bool:
        subject = {"match": match, "line": line}.get(self.target, secret)
        rx_hit = any(r.search(subject) for r in self.regexes) if self.regexes else None
        sw_hit = any(w in secret.lower() for w in self.stopwords) if self.stopwords else None
        checks = [c for c in (rx_hit, sw_hit) if c is not None]
        if not checks:
            return False
        return all(checks) if self.condition.upper() == "AND" else any(checks)


@dataclass
class Rule:
    id: str
    rx: re.Pattern
    keywords: tuple[str, ...]
    entropy: float | None
    secret_group: int | None
    allows: list[Allow]


def _allow(d: dict) -> Allow:
    regs = []
    for r in d.get("regexes", []) or []:
        try:
            regs.append(re.compile(go_to_python(r)))
        except re.error:
            pass
    return Allow(regs, [w.lower() for w in d.get("stopwords", []) or []],
                 d.get("regexTarget", "secret"), d.get("condition", "OR"))


@lru_cache(maxsize=4)
def load(path: str | None = None) -> tuple[list[Rule], list[Allow], list[str]]:
    data = tomllib.loads(Path(path or BUNDLED).read_text(encoding="utf-8"))
    glob = data.get("allowlist")
    global_allows = [_allow(glob)] if isinstance(glob, dict) else [_allow(a) for a in data.get("allowlists", []) or []]
    rules, failed = [], []
    for r in data.get("rules", []):
        if "regex" not in r:
            continue                      # path-only rules (file names) don't apply to text
        try:
            rx = re.compile(go_to_python(r["regex"]))
        except re.error:
            failed.append(r.get("id", "?"))
            continue
        rules.append(Rule(r.get("id", "?"), rx, tuple(k.lower() for k in r.get("keywords", []) or []),
                          r.get("entropy"), r.get("secretGroup"),
                          [_allow(a) for a in r.get("allowlists", []) or []]))
    return rules, global_allows, failed
