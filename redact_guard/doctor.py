"""`redact-guard doctor`: check the whole setup. PASS / WARN / FAIL, with a hint each.

Exit code 1 if anything FAILs. Never prints secret values.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path

from . import config as C

ANTHROPIC = ("anthropic.com", "claude.ai", "claude.com")


class Report:
    def __init__(self):
        self.rows: list[tuple[str, str, str, str]] = []

    def add(self, status: str, check: str, detail: str = "", hint: str = ""):
        self.rows.append((status, check, detail, hint))

    def print(self) -> int:
        for st, chk, det, hint in self.rows:
            print(f"{st:4}  {chk}" + (f": {det}" if det else ""))
            if hint and st not in ("PASS",):
                print(f"      hint: {hint}")
        fails = sum(1 for r in self.rows if r[0] == "FAIL")
        warns = sum(1 for r in self.rows if r[0] == "WARN")
        print(f"\n{len(self.rows)} checks: {fails} FAIL, {warns} WARN")
        return 1 if fails else 0


def _claude_settings() -> tuple[dict, list[str]]:
    paths = [Path("~/.claude/settings.json").expanduser()]
    managed = {"win32": Path(r"C:\Program Files\ClaudeCode\managed-settings.json"),
               "darwin": Path("/Library/Application Support/ClaudeCode/managed-settings.json")}.get(
        sys.platform, Path("/etc/claude-code/managed-settings.json"))
    merged: dict = {}
    used = []
    for p in (paths[0], managed):            # managed last: it wins
        if p.exists():
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            used.append(str(p))
            for k, v in d.items():
                if k == "env":
                    merged.setdefault("env", {}).update(v)
                else:
                    merged[k] = v
    return merged, used


def _exists(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return True              # exists but we can't even stat it: isolated


def _tls_check(upstream: str | None, bundle: str | None, host="api.anthropic.com") -> str | None:
    """Can redact-guard reach host:443 through the existing proxy with the CA bundle?"""
    try:
        if upstream:
            from urllib.parse import urlparse
            u = urlparse(upstream)
            sock = socket.create_connection((u.hostname, u.port or 80), timeout=8)
            sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
            resp = sock.recv(4096).decode("latin-1", "replace")
            if " 200" not in resp.split("\r\n", 1)[0]:
                return f"existing proxy answered: {resp.splitlines()[0] if resp else 'nothing'}"
        else:
            sock = socket.create_connection((host, 443), timeout=8)
        from .upstream import ssl_context
        ctx = ssl_context(bundle)              # the same verification the service uses
        with ctx.wrap_socket(sock, server_hostname=host) as t:
            t.getpeercert()
        return None
    except ssl.SSLCertVerificationError as e:
        return f"TLS verification failed ({e.verify_message}) - the existing proxy inspects TLS and " \
               f"its CA isn't in the bundle"
    except Exception as e:
        return f"{type(e).__name__}: {e}"


def _shell_ca_check(r, env: dict) -> None:
    """A NODE_EXTRA_CA_CERTS in the shell/Windows environment is read when the claude process
    starts, before settings.json. If its file is gone, Claude Code prints "Ignoring extra certs
    from ..." at every start; the settings' value still applies afterwards."""
    v = os.environ.get("NODE_EXTRA_CA_CERTS")
    if not v or v == env.get("NODE_EXTRA_CA_CERTS"):
        return
    fix = ('[Environment]::SetEnvironmentVariable("NODE_EXTRA_CA_CERTS", $null, "User")  '
           '(and "Machine" from an admin shell if it is set there), then open a new terminal'
           if os.name == "nt" else "remove the export from your shell profile")
    if not os.path.isfile(v):
        r.add("WARN", "shell NODE_EXTRA_CA_CERTS", f"{v} (file missing)",
              "leftover from an earlier setup; Claude Code warns at start and then uses the "
              "settings' CA. Remove it: " + fix)
    else:
        r.add("INFO", "shell NODE_EXTRA_CA_CERTS", v,
              "fine: inside Claude Code the settings' CA is used; other Node programs keep this one")


def _stream_check(r, lines: list[str]) -> None:
    """Model replies should reach redact-guard in pieces as the model writes them. If they
    come with a Content-Length, something upstream (a proxy, a scanner) held the whole reply
    first, and Claude Code shows "check your network" while it waits."""
    starts = []
    for ln in lines:
        if '"model_stream_start"' in ln:
            try:
                starts.append(json.loads(ln))
            except ValueError:
                pass
    starts = starts[-20:]
    if not starts:
        return
    held = [e for e in starts if e.get("transfer") == "length"]
    if not held:
        r.add("PASS", "reply streaming", f"last {len(starts)} replies arrived as a live stream")
        return
    env = _claude_settings()[0].get("env", {})
    waits = "CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS" in env
    r.add("INFO" if waits else "WARN", "reply streaming",
          f"{len(held)} of the last {len(starts)} replies arrived whole (Content-Length), "
          f"slowest {max(e.get('first_byte_ms') or 0 for e in held) / 1000:.1f}s; something between "
          f"redact-guard and Anthropic holds each reply until it is complete",
          "Claude Code waits for long replies (CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS is set); "
          "the 'check your network' line can still show after 20s, and the reply still arrives"
          if waits else
          "re-run the installer so settings get CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS, or ask IT "
          "to stream text/event-stream from api.anthropic.com without buffering")


def run(config_path: str | None) -> int:
    r = Report()
    try:
        s = C.load(config_path)
        r.add("PASS", "config", config_path or "(defaults)")
    except Exception as e:
        r.add("FAIL", "config", str(e), "fix the YAML")
        return r.print()

    # vault key: the strongest setup keeps it unreadable for the account Claude Code runs as
    isolated = [Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "redact-guard" / "state" / "key",
                Path("/var/lib/redact-guard/key")]
    iso = next((k for k in isolated if _exists(k.parent)), None)
    if iso is not None:
        try:
            names = os.listdir(iso.parent)
        except PermissionError:
            r.add("PASS", "vault key isolation", f"{iso.parent} not readable from this account")
        else:
            if iso.name in names:
                r.add("FAIL", "vault key isolation", f"{iso} is readable by this account",
                      "don't run Claude Code (or this check) elevated/as root; re-run the isolated installer")
            else:
                r.add("WARN", "vault key", f"not created yet in {iso.parent}",
                      "the service creates it on first start; check its log")
    elif s.key_file.exists():
        if os.name != "nt" and s.key_file.stat().st_mode & 0o077:
            r.add("FAIL", "vault key permissions", str(s.key_file), f"chmod 600 {s.key_file}")
        else:
            r.add("WARN", "vault key isolation", f"{s.key_file} is readable by this account, so by any "
                  f"command Claude runs", "use the isolated install (Windows: install.ps1 elevated; "
                  "Linux: scripts/linux/install-system.sh)")
    else:
        r.add("WARN", "vault key", "not created yet", "it's created on first start")
    from . import healthproof
    r.add("PASS" if healthproof.load() else "WARN", "hook secret",
          "found" if healthproof.load() else "missing",
          "start redact-guard once (it creates ~/.config/redact-guard/hook-secret)")

    # detectors
    from .gitleaks import load
    try:
        rules, _, failed = load(s.detector.gitleaks_rules)
        st = "PASS" if not failed else "WARN"
        r.add(st, "gitleaks rules", f"{len(rules)} loaded" + (f", {len(failed)} skipped: "
                                                               f"{', '.join(failed[:5])}" if failed else ""))
    except Exception as e:
        r.add("WARN", "gitleaks rules", str(e), "check detectors.gitleaks_rules")

    # Claude Code settings
    cs, used = _claude_settings()
    env = cs.get("env", {})
    mode = env.get("REDACT_GUARD_MODE") or ("gateway" if env.get("ANTHROPIC_BASE_URL") else None)
    if not used:
        r.add("FAIL", "Claude Code settings", "none found",
              "run scripts/render_settings.py --apply (add --mode proxy for Remote Control)")
        return r.print()
    r.add("PASS" if mode else "FAIL", "mode", mode or "neither proxy nor gateway is configured",
          "run scripts/render_settings.py --apply")

    hooks = json.dumps(cs.get("hooks", {}))
    if "guard.py" in hooks and "PreToolUse" in hooks and "UserPromptSubmit" in hooks:
        r.add("PASS", "hooks", "PreToolUse + UserPromptSubmit")
        if " -I " not in hooks:
            r.add("WARN", "hook interpreter", "not run with python -I",
                  "re-run render_settings.py --apply (a repo's PYTHONPATH could hijack the hook)")
        # actually run it, as this account: if the interpreter can't start, Claude Code treats
        # that as a non-blocking error and the hook is silently off
        try:
            cmd = next(h["command"] for m in cs["hooks"].get("PreToolUse", []) for h in m.get("hooks", [])
                       if "guard.py" in h.get("command", ""))
            ev = json.dumps({"tool_name": "Bash", "tool_input": {"command": "psql -h db"}}).encode()
            pr = subprocess.run(cmd, shell=True, input=ev, capture_output=True, timeout=30)
            if pr.returncode == 0 and b'"deny"' in pr.stdout:
                r.add("PASS", "hook runs as you", "denied a test psql call")
            else:
                err = (pr.stderr or pr.stdout).decode("utf-8", "replace").strip().splitlines()
                r.add("FAIL", "hook runs as you", f"exit {pr.returncode}: {(err or [''])[-1][:160]}",
                      "the hook interpreter can't run for this account (Access denied? endpoint "
                      "protection?). Until this passes, the hooks are OFF.")
        except StopIteration:
            pass
        except Exception as e:
            r.add("FAIL", "hook runs as you", type(e).__name__, "see README: Windows 'Access denied'")
    else:
        r.add("FAIL", "hooks", "missing", "re-run render_settings.py --apply")
    # this project's .claude/settings*.json (run doctor from the project folder)
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "rg_guard", Path(__file__).resolve().parents[1] / "hooks" / "guard.py")
        g = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(g)
        prob = g.project_settings_problem()
        r.add("FAIL" if prob else "PASS", f"project settings ({Path.cwd().name})", prob or "nothing that re-routes traffic")
        tel = g.telemetry_problem()
        if tel:
            r.add("FAIL", "OpenTelemetry", tel, "unset OTEL_LOG_USER_PROMPTS / OTEL_LOG_TOOL_DETAILS")
    except Exception as e:
        r.add("WARN", "project settings", f"couldn't check ({type(e).__name__})")

    if mode == "proxy":
        url = env.get("REDACT_GUARD_URL", "http://127.0.0.1:8788")
        for k in ("https_proxy", "HTTPS_PROXY"):
            if env.get(k) != url:
                r.add("FAIL", f"settings env {k}", str(env.get(k)), f"must be {url}")
        if env.get("ANTHROPIC_BASE_URL"):
            r.add("FAIL", "ANTHROPIC_BASE_URL", env["ANTHROPIC_BASE_URL"], "unset it in proxy mode")
        for k in ("NO_PROXY", "no_proxy"):
            v = (env.get(k) or "").lower()
            if v.strip() == "*" or any(d in v for d in ANTHROPIC):
                r.add("FAIL", k, v, "must not include Anthropic/Claude hosts")
        ca = env.get("NODE_EXTRA_CA_CERTS", "")
        r.add("PASS" if ca and os.path.isfile(ca) else "FAIL", "NODE_EXTRA_CA_CERTS", ca or "unset",
              "python -m redact_guard proxy --init prints the right path")
        for k in ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "DISABLE_GROWTHBOOK"):
            if env.get(k) or os.environ.get(k):
                r.add("WARN", "Remote Control", f"{k} is set", "Remote Control is unavailable with it")
        # your shell's own proxy variables: inside Claude Code the settings' values win, and the
        # prompt hook checks the effective value on every prompt; programs you run outside
        # Claude Code keep using your shell's proxy as before
        for k in ("https_proxy", "HTTPS_PROXY"):
            v = os.environ.get(k)
            if v and v.rstrip("/") != url.rstrip("/") and not (k == "HTTPS_PROXY" and os.environ.get("https_proxy")):
                in_settings = (env.get(k) or "").rstrip("/") == url.rstrip("/")
                r.add("INFO" if in_settings else "WARN", f"shell {k}", v,
                      "fine: inside Claude Code the settings' value wins, and the prompt hook checks it "
                      "on every prompt" if in_settings else
                      "Claude Code's settings don't set it: re-run render_settings.py --apply")
        _shell_ca_check(r, env)
        try:
            from .healthproof import get_json
            info = get_json("http://redact-guard.invalid/healthz", url)
            r.add("PASS", "proxy running", f"{url}, vault entries: {info.get('vault_entries')}")
            from . import __version__
            if info.get("version") != __version__:
                r.add("FAIL", "running version", f"{info.get('version') or 'older than 2026-11-23s'}, "
                      f"installed: {__version__}",
                      "an old service process is still running: elevated, "
                      "Stop-ScheduledTask redact-guard; Start-ScheduledTask redact-guard")
        except Exception as e:
            r.add("FAIL", "proxy running", type(e).__name__, "start it: python -m redact_guard proxy")
    elif mode == "gateway":
        url = env.get("ANTHROPIC_BASE_URL", "")
        try:
            from .healthproof import get_json
            get_json(url.rstrip("/") + "/healthz")
            r.add("PASS", "gateway running", url)
        except Exception as e:
            r.add("FAIL", "gateway running", type(e).__name__, "start it: python -m redact_guard serve")
        r.add("WARN", "Remote Control", "unavailable in gateway mode", "use proxy mode if you want it")
        prox = next((os.environ.get(k) or env.get(k) for k in ("https_proxy", "HTTPS_PROXY", "http_proxy",
                                                                "HTTP_PROXY") if os.environ.get(k) or env.get(k)), "")
        np = (env.get("no_proxy") or env.get("NO_PROXY") or os.environ.get("no_proxy") or
              os.environ.get("NO_PROXY") or "").lower()
        if prox and "127.0.0.1" not in np and "localhost" not in np:
            r.add("FAIL", "gateway behind a proxy", f"{prox} is set and NO_PROXY doesn't exclude 127.0.0.1",
                  "re-run render_settings.py --apply (it sets NO_PROXY), or the unredacted request "
                  "goes to that proxy first")

    # existing proxy + TLS
    from . import upstream as U
    up, _ = U.detect(s.corp_url, {(s.proxy_host, s.proxy_port), (s.host, s.port)})
    r.add("WARN" if up.warning else "PASS", "existing proxy", up.describe(),
          "set corporate_proxy.url explicitly" if up.warning else "")
    if up.bypass:
        r.add("INFO", "existing proxy bypass list", ", ".join(up.bypass[:8]),
              "if Claude Code must reach any of these (e.g. an internal MCP server), add them with "
              "render_settings.py --no-proxy-extra")
    try:
        try:
            bundle = U.ca_bundle(s.corp_ca, (s.proxy_confdir or s.vault_dir / "mitm"))
        except PermissionError:                       # isolated install: build a scratch copy
            import tempfile
            bundle = U.ca_bundle(s.corp_ca, Path(tempfile.mkdtemp(prefix="rg-doctor-")))
    except Exception as e:
        bundle = None
        r.add("FAIL", "upstream CA bundle", str(e), "fix corporate_proxy.ca")
    err = _tls_check(up.url, bundle)
    r.add("PASS" if err is None else "FAIL", "reach api.anthropic.com upstream",
          "ok" if err is None else err,
          "export your proxy's root CA to a PEM file and set corporate_proxy.ca, or install it in "
          "the OS store")

    # platform layers
    if os.name == "nt":
        if "sandbox" in cs:
            r.add("WARN", "sandbox", "configured on native Windows", "re-render with --platform windows")
        if mode == "proxy":
            try:
                out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                      "(Get-NetFirewallRule -Group 'redact-guard-claude' -ErrorAction "
                                      "SilentlyContinue | Measure-Object).Count"],
                                     capture_output=True, text=True, timeout=20).stdout.strip()
                n = int(out or 0)
            except Exception:
                n = 0
            r.add("PASS" if n else "WARN", "firewall: claude.exe direct egress blocked", f"{n} rule(s)",
                  "elevated: scripts\\windows\\firewall-block-db.ps1 -BlockClaudeDirect -RegisterRefreshTask")
    else:
        sb = cs.get("sandbox", {})
        r.add("PASS" if sb.get("enabled") else "WARN", "Bash sandbox", "enabled" if sb.get("enabled") else "off",
              "render settings for posix")
        if sys.platform.startswith("linux") and sb.get("enabled"):
            missing = [b for b in ("bwrap", "socat") if not shutil.which(b)]
            r.add("FAIL" if missing else "PASS", "sandbox dependencies",
                  "missing: " + ", ".join(missing) if missing else "bwrap, socat",
                  "sudo apt-get install bubblewrap socat")

    # Claude Code version
    claude = shutil.which("claude")
    if claude:
        try:
            v = subprocess.run([claude, "--version"], capture_output=True, text=True, timeout=20).stdout
            r.add("PASS", "Claude Code", v.strip())
        except Exception:
            r.add("WARN", "Claude Code", "couldn't run claude --version")
    else:
        r.add("WARN", "Claude Code", "not on PATH")

    # recent refusals
    lines = None
    if s.audit_log:
        try:
            lines = s.audit_log.read_text(encoding="utf-8", errors="replace").splitlines()[-2000:]
        except FileNotFoundError:
            lines = None
        except OSError:
            r.add("PASS", "recent refusals", "audit log not readable from this account (isolated)",
                  f"sudo tail {s.audit_log}")
    if lines is not None:
        bad = [json.loads(ln).get("event") for ln in lines
               if any(e in ln for e in ('"uplink_refused"', '"ws_frame_refused"', '"canary_blocked"',
                                        '"redaction_error"'))]
        r.add("WARN" if bad else "PASS", "recent refusals", ", ".join(sorted(set(bad))) or "none",
              "see audit.jsonl; a refused upload means something couldn't be inspected")
        _stream_check(r, lines)
    return r.print()
