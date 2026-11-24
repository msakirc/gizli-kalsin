#!/usr/bin/env python3
"""Claude Code hooks for redact-guard. Run with `python -I` (ignore PYTHON* env vars).

  guard.py pre-tool-use    PreToolUse: deny database access, vault access, secret-store
                           reads, DB MCP tools.
  guard.py prompt-submit   UserPromptSubmit: refuse to send anything unless Claude Code's
                           traffic provably goes through redact-guard.

Fail closed: any internal error, unreadable input or unknown mode blocks (exit 2).

prompt-submit trusts nothing in the environment as proof (a repository's .claude/settings.json
can set any env var). It works out where Claude Code will actually send the request
(ANTHROPIC_BASE_URL, or the effective HTTPS proxy and NO_PROXY), sends a fresh nonce there,
and requires HMAC(secret, nonce) back, with the secret read from a fixed local path.
"""
from __future__ import annotations

import ipaddress
import json
import os
import secrets
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ANTHROPIC_DOMAINS = ("anthropic.com", "claude.ai", "claude.com")
LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1", "[::1]", "localhost.localdomain"}
# env a project's settings must not set: they decide where traffic goes or what runs
DANGEROUS_ENV_PREFIXES = ("ANTHROPIC_", "REDACT_GUARD_", "OTEL_", "PYTHON", "NODE_", "DYLD_",
                          "CLAUDE_CODE_")
DANGEROUS_ENV = {"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE",
                 "SSL_CERT_DIR", "PATH", "BASH_ENV", "ENV", "LD_PRELOAD", "LD_LIBRARY_PATH",
                 "CLAUDE_CONFIG_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PATHEXT",
                 "COMSPEC", "PSMODULEPATH", "DISABLE_TELEMETRY"}
DANGEROUS_KEYS = ("hooks", "disableAllHooks", "apiKeyHelper", "awsAuthRefresh",
                  "awsCredentialExport", "otelHeadersHelper", "statusLine", "forceLoginMethod")


def _deny_pre_tool(reason: str) -> None:
    _CTX["reason"] = reason
    _CTX["decision"] = "deny"
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": f"redact-guard: {reason}. Do not retry this another way; "
                                    f"ask the user if you need this data."}}))
    sys.exit(0)


def pre_tool_use(event: dict) -> None:
    from redact_guard import policy as P
    name = event.get("tool_name")
    tool_input = event.get("tool_input")
    if not isinstance(name, str) or not isinstance(tool_input, (dict, type(None))):
        _deny_pre_tool("unexpected hook input")
    reason = P.check_tool(name, tool_input or {})
    if reason is None:
        reason = P.check_local_files(name, tool_input or {})
    if reason:
        _deny_pre_tool(reason)
    sys.exit(0)


_CTX: dict = {}


def _log_path() -> Path:
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "redact-guard" / "hook.log"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "redact-guard" / "hook.log"


def _hook_log(mode: str, decision: str, event: dict) -> None:
    """One local line per prompt decision and per denied tool, so a prompt that never reached
    the model (e.g. sent from your phone, where the hook's message isn't shown) leaves a
    trace. Never the prompt or tool input itself; never fails the hook."""
    try:
        path = _log_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size > 1_000_000:
            path.replace(path.with_suffix(".log.1"))
        import time
        rec = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "hook": mode, "decision": decision,
               "session": str(event.get("session_id", ""))[:40], "reason": _CTX.get("reason", "")[:300]}
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _block(msg: str) -> None:
    _CTX["reason"] = msg
    print(f"redact-guard: {msg} Prompt NOT sent.", file=sys.stderr)
    sys.exit(2)


# ----------------------------------------------------------------- NO_PROXY
def _norm_no_proxy_entry(e: str) -> str:
    e = e.strip().lower()
    if e.startswith("[") and "]" in e:
        return e[1:e.index("]")]
    if e.count(":") == 1:                       # host:port (IPv6 has more colons)
        e = e.split(":", 1)[0]
    return e.lstrip("*").lstrip(".").rstrip(".")


def no_proxy_problem(value: str) -> str | None:
    """NO_PROXY may hold loopback and ordinary hostnames (an internal MCP server), but nothing
    that matches every host, an Anthropic host, or an address range."""
    for raw in value.replace(" ", ",").split(","):
        if not raw.strip():
            continue
        e = _norm_no_proxy_entry(raw)
        if e in ("", "*"):
            return f"entry {raw.strip()!r} matches every host"
        if e in LOOPBACK_NAMES:
            continue
        try:
            net = ipaddress.ip_network(e, strict=False)
        except ValueError:
            net = None
        if net is not None:
            if net.is_loopback or (net.is_private and net.prefixlen >= 8):
                continue                    # internal ranges (10.20.0.0/16) can't cover Anthropic
            return f"entry {raw.strip()!r} is a public IP range (could cover Anthropic's addresses)"
        if any(e == d or e.endswith("." + d) or d.endswith("." + e) or d == e for d in ANTHROPIC_DOMAINS):
            return f"entry {raw.strip()!r} covers an Anthropic host"
    return None


def _env(k: str) -> str:
    return os.environ.get(k) or ""


def effective_proxy() -> str:
    # Claude Code (undici) prefers the lowercase spelling, then uppercase
    for k in ("https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY"):
        if _env(k):
            return _env(k)
    return ""


def _is_loopback_url(url: str) -> bool:
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# ----------------------------------------------------------------- checks
def project_settings_problem() -> str | None:
    """A repository's .claude/settings*.json may not re-route traffic or add hooks."""
    proj = _env("CLAUDE_PROJECT_DIR") or os.getcwd()
    for name in ("settings.json", "settings.local.json"):
        p = Path(proj) / ".claude" / name
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            continue
        except Exception:
            return f"{p} can't be parsed (refusing to guess what it changes)"
        if not isinstance(data, dict):
            continue
        bad = [k for k in DANGEROUS_KEYS if k in data]
        env = data.get("env") if isinstance(data.get("env"), dict) else {}
        bad += [f"env.{k}" for k in env
                if k.upper() in DANGEROUS_ENV or k.upper().startswith(DANGEROUS_ENV_PREFIXES)]
        if bad:
            return (f"{p} sets {', '.join(sorted(bad)[:6])}. Project settings may not change where "
                    f"traffic goes or what runs; move what you need to your user settings")
    return None


def telemetry_problem() -> str | None:
    if _env("CLAUDE_CODE_ENABLE_TELEMETRY") in ("1", "true") and (
            _env("OTEL_LOG_USER_PROMPTS") in ("1", "true") or _env("OTEL_LOG_TOOL_DETAILS") in ("1", "true")):
        return ("OpenTelemetry export with OTEL_LOG_USER_PROMPTS/OTEL_LOG_TOOL_DETAILS would send "
                "unredacted prompts to the collector")
    return None


def _health(url: str, via_proxy: str | None) -> dict:
    from redact_guard.healthproof import get_json
    return get_json(url, via_proxy)


def verified(url: str, via_proxy: str | None) -> tuple[bool, str]:
    from redact_guard import healthproof
    secret = healthproof.load()
    if not secret:
        return False, "no hook secret found (start redact-guard once, or re-run the installer)"
    nonce = secrets.token_hex(16)
    sep = "&" if "?" in url else "?"
    try:
        info = _health(f"{url}{sep}nonce={nonce}", via_proxy)
    except Exception as e:
        return False, f"not reachable ({type(e).__name__})"
    if info.get("ok") is not True:
        return False, "not healthy"
    if not healthproof.verify(secret, nonce, info.get("proof")):
        return False, "answered without a valid proof: this is not your redact-guard"
    return True, ""


def prompt_submit(event: dict) -> None:
    for problem in (project_settings_problem(), telemetry_problem()):
        if problem:
            _block(problem + ".")
    if _env("NODE_TLS_REJECT_UNAUTHORIZED") == "0":
        _block("NODE_TLS_REJECT_UNAUTHORIZED=0 is set.")
    base = _env("ANTHROPIC_BASE_URL").rstrip("/")
    proxy = effective_proxy().rstrip("/")
    if base and not any(base.lower().startswith(f"https://{d}") or f".{d}" in base.lower()
                        for d in ANTHROPIC_DOMAINS):
        # gateway mode: the base URL must be a verified redact-guard, reached directly
        if proxy:
            host = (urllib.parse.urlsplit(base).hostname or "").lower()
            np = {_norm_no_proxy_entry(x) for x in (_env("no_proxy") or _env("NO_PROXY")).split(",")}
            if host not in np and "*" not in np:
                _block(f"a proxy ({proxy}) is set and NO_PROXY doesn't exclude {host}, so the "
                       f"unredacted request would go to that proxy first.")
        ok, why = verified(base + "/healthz", None)
        if not ok:
            _block(f"ANTHROPIC_BASE_URL {base!r}: {why}. Start it with: python -m redact_guard serve")
        sys.exit(0)
    # proxy mode: Anthropic hosts, reached only through a verified redact-guard proxy
    if not proxy:
        _block("neither ANTHROPIC_BASE_URL nor an HTTPS proxy points at redact-guard.")
    if not _is_loopback_url(proxy):
        _block(f"the HTTPS proxy is {proxy!r}; redact-guard listens on loopback.")
    for k in ("no_proxy", "NO_PROXY"):
        p = no_proxy_problem(_env(k))
        if p:
            _block(f"{k}: {p}.")
    ca = _env("NODE_EXTRA_CA_CERTS")
    if not ca or not os.path.isfile(ca):
        _block(f"NODE_EXTRA_CA_CERTS ({ca or 'unset'}) is not the redact-guard CA file.")
    ok, why = verified("http://redact-guard.invalid/healthz", proxy)
    if not ok:
        _block(f"proxy {proxy}: {why}. Start it with: python -m redact_guard proxy")
    sys.exit(0)


def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        raw = sys.stdin.buffer.read()
        # Claude Code sends UTF-8; don't rely on the Windows console code page
        event = json.loads(raw.decode("utf-8")) if raw.strip() else {}
        if not isinstance(event, dict):
            raise ValueError("hook input is not an object")
    except Exception:
        print("redact-guard: unreadable hook input; blocking to be safe", file=sys.stderr)
        sys.exit(2)
    try:
        if mode == "pre-tool-use":
            pre_tool_use(event)
        elif mode == "prompt-submit":
            prompt_submit(event)
        else:
            print(f"unknown mode {mode!r}", file=sys.stderr)
            sys.exit(2)
    except SystemExit as e:
        if mode == "prompt-submit":
            _hook_log(mode, "sent" if e.code in (0, None) else "BLOCKED", event)
        elif _CTX.get("decision") == "deny" or e.code not in (0, None):
            _hook_log(mode, "deny", event)
        raise
    except BaseException as e:  # fail closed
        tail = " Prompt NOT sent." if mode == "prompt-submit" else ""
        _CTX["reason"] = f"hook error {type(e).__name__}"
        _hook_log(mode, "BLOCKED" if mode == "prompt-submit" else "deny", event)
        print(f"redact-guard hook error ({type(e).__name__}): blocking to be safe.{tail}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
