#!/usr/bin/env python3
"""Render Claude Code settings for redact-guard.

  scripts/render_settings.py                 # print user settings to stdout
  scripts/render_settings.py --apply         # merge into ~/.claude/settings.json (backup first)
                                             # and add the placeholder note to ~/.claude/CLAUDE.md
  scripts/render_settings.py --managed > managed-settings.json
        Linux:   sudo install -m 644 managed-settings.json /etc/claude-code/
        Windows: copy to C:\\Program Files\\ClaudeCode\\managed-settings.json (admin)
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


DEFAULT_CA = Path("~/.local/share/redact-guard/mitm/mitmproxy-ca-cert.pem").expanduser()


ANTHROPIC_HOSTS = ("anthropic.com", "claude.ai", "claude.com")


def bypass_to_no_proxy(entries: list[str]) -> list[str]:
    """Turn a Windows proxy bypass list (ProxyOverride) into NO_PROXY entries that Node, Python,
    Go, curl and git understand:  *.corp.example -> .corp.example   10.20.* -> 10.20.0.0/16.
    Anthropic hosts, public IP ranges and patterns NO_PROXY can't express are dropped."""
    import ipaddress
    out: list[str] = []
    for raw in entries:
        e = raw.strip().lower()
        if not e or e == "<local>" or any(e.rstrip(".").endswith(d) for d in ANTHROPIC_HOSTS):
            continue
        if e.startswith(("http://", "https://")):
            e = e.split("://", 1)[1]
        e = e.split("/")[0]
        if ":" in e and e.count(":") == 1:
            e = e.split(":")[0]                          # host:port -> host
        octets = e.split(".")
        if all(o.isdigit() or o == "*" for o in octets) and 1 <= len(octets) <= 4 and "*" in octets:
            fixed = [o for o in octets if o != "*"]
            if octets[len(fixed):] != ["*"] * (len(octets) - len(fixed)):
                continue                                 # 10.*.1.* can't be a CIDR
            net = ".".join(fixed + ["0"] * (4 - len(fixed))) + f"/{8 * len(fixed)}"
            try:
                n = ipaddress.ip_network(net)
            except ValueError:
                continue
            if n.is_private and n.prefixlen >= 8:
                out.append(net)
            continue
        try:
            ip = ipaddress.ip_address(e)
            if ip.is_private:
                out.append(e)
            continue
        except ValueError:
            pass
        if e.startswith("*."):
            e = e[1:]
        if "*" in e or not e.strip("."):
            continue                                     # *internal* etc.: not expressible
        out.append(e)
    return list(dict.fromkeys(out))


def system_bypass() -> list[str]:
    """The machine's existing proxy exceptions (Windows system proxy), if any."""
    import sys
    sys.path.insert(0, str(ROOT))
    try:
        from redact_guard import upstream as U
        w = U.windows_system_proxy()
        return list(w.bypass) if w and w.bypass else []
    except Exception:
        return []


STREAM_FIRST_BYTE_MS = 600_000
API_TIMEOUT_MS = 900_000


def proxy_mode(s: dict, proxy_url: str, ca: str) -> dict:
    """Proxy mode: Claude Code keeps api.anthropic.com (Remote Control stays available) and
    reaches it through redact-guard's HTTPS proxy, which redacts Anthropic traffic."""
    env = s.setdefault("env", {})
    env.pop("ANTHROPIC_BASE_URL", None)
    env.pop("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", None)    # would disable Remote Control
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        env[k] = proxy_url        # lowercase wins in Claude Code, so pin both spellings
    env["NO_PROXY"] = "localhost,127.0.0.1,::1"
    env["no_proxy"] = "localhost,127.0.0.1,::1"
    env["NODE_EXTRA_CA_CERTS"] = ca
    env["REDACT_GUARD_URL"] = proxy_url
    env["REDACT_GUARD_MODE"] = "proxy"
    env["DISABLE_TELEMETRY"] = "1"
    env["DISABLE_ERROR_REPORTING"] = "1"
    # A proxy or scanner that holds a streamed reply until it is complete sends no bytes while
    # the model writes. Claude Code then aborts and retries a long reply. Let it wait instead:
    # the first attempt waits up to 10 min for the first byte (Claude Code 2.1.242+), and the
    # per-request limit stays above it. Short replies are unaffected.
    env.setdefault("CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS", str(STREAM_FIRST_BYTE_MS))
    env.setdefault("API_TIMEOUT_MS", str(API_TIMEOUT_MS))
    s.pop("disableRemoteControl", None)
    s.pop("allowedProviders", None)
    return s


def render(url: str, platform: str | None = None, python_cmd: str | None = None,
           guard_root: str | None = None) -> dict:
    plat = platform or ("windows" if os.name == "nt" else "posix")
    root = ROOT.as_posix()
    if python_cmd is None:
        # An absolute interpreter (a repo can't shadow it via PATH) with -I (ignores the
        # PYTHONPATH/PYTHONHOME a repo's settings could set). Prefer the install's venv.
        venv = ROOT / ".venv" / ("Scripts/python.exe" if plat == "windows" else "bin/python")
        if venv.exists():
            python_cmd = f'"{venv.as_posix()}" -I'
        elif plat == "windows":
            python_cmd = "py -3 -I"
        else:
            python_cmd = (shutil.which("python3") or "python3") + " -I"
    elif " -I" not in f" {python_cmd} ":
        python_cmd = f"{python_cmd} -I"
    guard_py = f'"{root}/hooks/guard.py"' if (" " in root or plat == "windows") else f"{root}/hooks/guard.py"
    s = json.loads((ROOT / "settings" / "settings.template.json").read_text())

    def sub(o):
        if isinstance(o, str):
            return (o.replace("{{GATEWAY_URL}}", url).replace("{{GUARD_DIR}}", root)
                     .replace("{{PYTHON}}", python_cmd).replace("{{GUARD_PY}}", guard_py))
        if isinstance(o, list):
            return [sub(x) for x in o]
        if isinstance(o, dict):
            return {k: sub(v) for k, v in o.items()}
        return o
    s = sub(s)
    # Claude must not edit redact-guard itself (hooks, config) to weaken the next session.
    gr = guard_root or root
    rule_root = "//" + (gr[0].lower() + gr[2:] if plat == "windows" and gr[1:2] == ":" else gr.lstrip("/"))
    for tool in ("Edit", "Write"):
        r = f"{tool}({rule_root}/**)"
        if r not in s["permissions"]["deny"]:
            s["permissions"]["deny"].append(r)
    s["env"]["OTEL_LOG_USER_PROMPTS"] = "0"
    s["env"]["OTEL_LOG_TOOL_DETAILS"] = "0"
    if plat == "windows":
        # The Bash sandbox doesn't run on native Windows; with failIfUnavailable it would
        # stop Claude Code from starting. Network isolation comes from Windows Firewall
        # or the hypervisor instead (scripts/windows/firewall-block-db.ps1).
        s.pop("sandbox", None)
        deny = s["permissions"]["deny"]
        ps = [r.replace("Bash(", "PowerShell(", 1) for r in deny if r.startswith("Bash(")]
        ps += ["PowerShell(Invoke-Sqlcmd *)", "PowerShell(Invoke-DbaQuery *)", "PowerShell(cmdkey *)",
               "Bash(psql.exe *)", "Bash(sqlcmd.exe *)", "PowerShell(psql.exe *)", "PowerShell(sqlcmd.exe *)",
               "Read(~/AppData/Roaming/postgresql/**)", "Read(~/AppData/Roaming/MySQL/**)"]
        s["permissions"]["deny"] = deny + [r for r in ps if r not in deny]
    return s


def deep_merge(base: dict, add: dict) -> dict:
    out = dict(base)
    for k, v in add.items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        elif isinstance(v, list) and isinstance(out.get(k), list):
            out[k] = out[k] + [x for x in v if x not in out[k]]
        else:
            out[k] = v
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8787")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--managed", action="store_true")
    ap.add_argument("--platform", choices=["posix", "windows"], help="default: this machine")
    ap.add_argument("--python", help='hook interpreter (default: "py -3" on Windows, python3 elsewhere)')
    ap.add_argument("--mode", choices=["gateway", "proxy"], default="gateway",
                    help="gateway: ANTHROPIC_BASE_URL (no Remote Control); "
                         "proxy: HTTPS_PROXY + local CA (Remote Control works)")
    ap.add_argument("--proxy-url", default="http://127.0.0.1:8788")
    ap.add_argument("--guard-root", help="redact-guard install folder to protect from edits (default: this one)")
    ap.add_argument("--ca", default=None, help=f"CA cert for NODE_EXTRA_CA_CERTS (default {DEFAULT_CA})")
    ap.add_argument("--no-system-bypass", action="store_true",
                    help="proxy mode: don't copy the Windows proxy bypass list into NO_PROXY (by default, "
                         "programs Claude runs reach your internal hosts directly, as before)")
    ap.add_argument("--no-proxy-extra", default="",
                    help="comma-separated hosts Claude Code should reach directly (e.g. an internal "
                         "MCP server your existing proxy bypasses). Anthropic hosts are refused.")
    a = ap.parse_args()
    s = render(a.url, a.platform, a.python, a.guard_root)
    if a.mode == "gateway":
        # C-3: an inherited HTTPS_PROXY must not carry the unredacted request to the
        # corporate proxy before it reaches the local gateway.
        s["env"]["NO_PROXY"] = s["env"]["no_proxy"] = "localhost,127.0.0.1,::1"
    if a.mode == "proxy":
        s = proxy_mode(s, a.proxy_url, (Path(a.ca) if a.ca else DEFAULT_CA).as_posix())
        extra = [h.strip() for h in a.no_proxy_extra.split(",") if h.strip()]
        bad = [h for h in extra if any(d in h.lower() for d in ANTHROPIC_HOSTS)]
        if not a.no_system_bypass:
            sysb = bypass_to_no_proxy(system_bypass())
            if sysb:
                print(f"NO_PROXY: adding your system proxy exceptions: {', '.join(sysb)}", file=sys.stderr)
            extra += [h for h in sysb if h not in extra]
        if bad or "*" in extra:
            raise SystemExit(f"refusing to bypass the proxy for: {bad or ['*']}")
        if extra:
            for k in ("NO_PROXY", "no_proxy"):
                s["env"][k] = ",".join([s["env"][k]] + extra)
    if a.managed:
        s = deep_merge(s, json.loads((ROOT / "settings" / "managed-additions.json").read_text()))
        if a.mode == "proxy":
            s.pop("allowedProviders", None)    # pins ANTHROPIC_BASE_URL; proxy mode pins env instead
            s.pop("disableRemoteControl", None)
        if (a.platform or ("windows" if os.name == "nt" else "posix")) == "windows":
            s.pop("sandbox", None)
        print(json.dumps(s, indent=2))
        return
    if not a.apply:
        print(json.dumps(s, indent=2))
        return
    target = Path("~/.claude/settings.json").expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    current = json.loads(target.read_text()) if target.exists() else {}
    if target.exists():
        backup = target.with_name(f"settings.json.bak-{int(time.time())}")
        shutil.copy2(target, backup)
        print(f"backup: {backup}")
    merged = deep_merge(current, s)
    target.write_text(json.dumps(merged, indent=2) + "\n")
    print(f"wrote {target}")
    # tell Claude what the placeholders are (user-level memory, applies to every project)
    md = Path("~/.claude/CLAUDE.md").expanduser()
    snippet = (ROOT / "settings" / "CLAUDE.md.snippet").read_text()
    existing = md.read_text() if md.exists() else ""
    if "redact-guard:begin" not in existing:
        md.write_text((existing.rstrip() + "\n\n" if existing.strip() else "") + snippet)
        print(f"added redact-guard note to {md}")


if __name__ == "__main__":
    main()
