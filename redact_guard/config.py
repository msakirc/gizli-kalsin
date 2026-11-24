"""Configuration loading (YAML). Every key is optional; see config/redact-guard.yaml."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from . import detectors as D
from . import vault as V
from .engine import EngineConfig


@dataclass
class Settings:
    upstream: str = "https://api.anthropic.com"
    host: str = "127.0.0.1"
    port: int = 8787
    api_key_env: str | None = None
    unknown_post: str = "block"
    vault_dir: Path = Path("~/.local/share/redact-guard").expanduser()
    key_file: Path = Path("~/.config/redact-guard/key").expanduser()
    persist: bool = True
    min_exact_len: int = 6
    audit_log: Path | None = None
    corp_url: str = "auto"
    corp_auth_env: str | None = None
    corp_ca: str = "system"
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8788
    proxy_confdir: Path | None = None          # default: <vault_dir>/mitm
    hook_secret_file: Path = Path("~/.config/redact-guard/hook-secret").expanduser()
    egress_enabled: bool = False
    egress_port: int = 8788
    egress_allow: list[str] = field(default_factory=list)
    egress_ports: list[int] = field(default_factory=lambda: [443])
    detector: D.DetectorConfig = field(default_factory=D.DetectorConfig)
    engine: EngineConfig = field(default_factory=EngineConfig)


def _auto_usernames() -> list[str]:
    """The account running redact-guard, when it's distinctive enough to hide everywhere
    (contains a digit, '.', '_' or is 8+ characters). Service accounts are skipped; the
    isolated installers write the real user into `own_usernames` instead."""
    import getpass
    try:
        u = getpass.getuser()
    except Exception:
        return []
    if not u or u.lower() in ("system", "root", "redact-guard", "nobody", "administrator") or u.endswith("$"):
        return []
    return [u] if (re.search(r"[\d._]", u) or len(u) >= 8) else []


def _p(v) -> Path:
    return Path(os.path.expandvars(str(v))).expanduser()


def load(path: str | None) -> Settings:
    s = Settings()
    if not path:
        return s
    raw = yaml.safe_load(Path(path).read_text()) or {}
    s.upstream = raw.get("upstream", s.upstream)
    lst = raw.get("listen", {}) or {}
    s.host, s.port = lst.get("host", s.host), int(lst.get("port", s.port))
    s.api_key_env = raw.get("api_key_env")
    s.unknown_post = raw.get("unknown_post", s.unknown_post)
    vv = raw.get("vault", {}) or {}
    if "dir" in vv:
        s.vault_dir = _p(vv["dir"])
    if "key_file" in vv:
        s.key_file = _p(vv["key_file"])
    s.persist = bool(vv.get("persist", s.persist))
    s.min_exact_len = int(vv.get("min_exact_len", s.min_exact_len))
    if raw.get("audit_log"):
        s.audit_log = _p(raw["audit_log"])
    cp = raw.get("corporate_proxy", {}) or {}
    s.corp_url = str(cp.get("url", s.corp_url))
    s.corp_auth_env = cp.get("auth_env")
    s.corp_ca = str(cp.get("ca", s.corp_ca))
    px = raw.get("proxy", {}) or {}
    s.proxy_host = px.get("host", s.proxy_host)
    s.proxy_port = int(px.get("port", s.proxy_port))
    if px.get("confdir"):
        s.proxy_confdir = _p(px["confdir"])
    if raw.get("hook_secret_file"):
        s.hook_secret_file = _p(raw["hook_secret_file"])
    eg = raw.get("egress", {}) or {}
    s.egress_enabled = bool(eg.get("enabled", False))
    s.egress_port = int(eg.get("port", s.egress_port))
    s.egress_allow = list(eg.get("allow", []) or [])
    s.egress_ports = [int(x) for x in (eg.get("ports") or [443])]

    d = raw.get("detectors", {}) or {}
    dc = s.detector
    if "internal_domains" in d:
        dc.internal_domains = list(d["internal_domains"] or [])
    dc.internal_domains += list(d.get("extra_internal_domains", []) or [])
    dc.allow_values |= set(d.get("allow_values", []) or [])
    dc.allow_emails |= {e.lower() for e in d.get("allow_emails", []) or []}
    dc.allow_email_domains |= {e.lower() for e in d.get("allow_email_domains", []) or []}
    dc.allow_users |= set(d.get("allow_users", []) or [])
    dc.own_usernames = [str(u) for u in (d.get("own_usernames") or []) if str(u).strip()]
    if d.get("own_usernames_auto", True):
        dc.own_usernames += [u for u in _auto_usernames() if u not in dc.own_usernames]
    if d.get("names_file"):
        dc.names = [ln.strip() for ln in _p(d["names_file"]).read_text().splitlines()
                    if ln.strip() and not ln.startswith("#")]
    for c in d.get("custom", []) or []:
        cls = c.get("class", V.CUSTOM)
        if cls not in V.ALL_CLASSES:
            raise ValueError(f"custom detector class {cls!r} unknown")
        dc.custom.append((re.compile(c["pattern"]), cls))
    dc.allow_names |= set(d.get("allow_names", []) or [])
    dc.allow_digests |= {x.lower() for x in d.get("allow_digests", []) or []}
    if d.get("gitleaks_rules"):
        dc.gitleaks_rules = str(_p(d["gitleaks_rules"]))
    dc.public_hosts |= {h.lower() for h in d.get("public_hosts", []) or []}
    for k in ("entropy", "phones", "turkish_ids", "cards", "vkn_unkeyed", "git_identities", "gitleaks"):
        if k in d:
            setattr(dc, k, bool(d[k]))
    if "entropy_threshold" in d:
        dc.entropy_threshold = float(d["entropy_threshold"])

    e = s.engine
    e.binary_blocks = raw.get("binary_blocks", e.binary_blocks)
    e.restore_in_text = bool(raw.get("restore_in_text", e.restore_in_text))
    e.canary = bool(raw.get("canary", e.canary))
    for cat, classes in (raw.get("restore", {}) or {}).items():
        if classes == "ALL":
            e.restore[cat] = V.ALL_CLASSES
        else:
            bad = set(classes) - V.ALL_CLASSES
            if bad:
                raise ValueError(f"restore.{cat}: unknown classes {bad}")
            e.restore[cat] = frozenset(classes)
    return s
