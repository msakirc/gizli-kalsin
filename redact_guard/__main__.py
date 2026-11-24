"""CLI: ``python -m redact_guard serve|scan``."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys

from aiohttp import web

from . import config as C
from . import healthproof
from .engine import Redactor
from .vault import ALL_CLASSES, Vault, load_or_create_key


def build_redactor(s: C.Settings, ephemeral: bool = False) -> Redactor:
    if ephemeral:
        vault = Vault(os.urandom(48), None, s.min_exact_len)
    else:
        key = load_or_create_key(s.key_file)
        path = None
        if s.persist:
            s.vault_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(s.vault_dir, 0o700)
            path = s.vault_dir / "vault.bin"
        vault = Vault(key, path, s.min_exact_len)
    return Redactor(vault, s.detector, s.engine)


def resolve_upstream(s: C.Settings, own: set, bundle_dir):
    from . import upstream as U
    up, creds = U.detect(s.corp_url, own)
    if s.corp_auth_env:
        creds = os.environ.get(s.corp_auth_env) or creds
    bundle = U.ca_bundle(s.corp_ca, bundle_dir)
    lg = logging.getLogger("redact_guard")
    lg.info('{"event":"upstream","proxy":%s,"source":%s,"auth":%s,"ca":%s}', json.dumps(up.url),
            json.dumps(up.source), "true" if creds else "false", json.dumps(bundle or "default"))
    if up.warning:
        lg.warning('{"event":"upstream_warning","message":%s}', json.dumps(up.warning))
    if up.bypass:
        lg.info('{"event":"upstream_bypass_list","hosts":%s,"hint":"hosts your existing proxy '
                'reaches directly; add any Claude Code needs with render_settings --no-proxy-extra"}',
                json.dumps(up.bypass))
    return up, creds, bundle


def _log_to_file(path: str) -> None:
    """Background services (Windows Scheduled Task, pythonw) have no console: send logging AND
    stdout/stderr to the log file, so library output can't crash on a missing stream and
    tracebacks are kept."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    stream = open(path, "a", encoding="utf-8", buffering=1)
    sys.stdout = sys.stderr = stream
    logging.basicConfig(level=os.environ.get("REDACT_GUARD_LOG", "INFO"), format="%(message)s",
                        stream=stream, force=True)
    # mitmproxy logs every client/server connect at INFO; keep the file to redact-guard's events
    logging.getLogger("mitmproxy").setLevel(os.environ.get("REDACT_GUARD_MITM_LOG", "WARNING"))


def _logged(fn):
    """Write an unexpected crash to the log before exiting (otherwise a service dies silently)."""
    def run(args):
        try:
            return fn(args)
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            logging.getLogger("redact_guard").exception('{"event":"crashed"}')
            raise
    run.__name__ = fn.__name__
    run.__doc__ = fn.__doc__
    return run


@_logged
def cmd_serve(args) -> int:
    from .egress import EgressProxy
    from .server import Gateway
    if args.log_file or sys.stderr is None:   # no console: Scheduled Task, pythonw
        _log_to_file(args.log_file or os.path.join(os.path.expanduser("~"), ".local", "share",
                                                   "redact-guard", "gateway.log"))
    s = C.load(args.config)
    if args.host:
        s.host = args.host
    if args.port:
        s.port = args.port
    api_key = os.environ.get(s.api_key_env) if s.api_key_env else None
    if s.api_key_env and not api_key:
        print(f"api_key_env={s.api_key_env} is set in config but the variable is empty", file=sys.stderr)
        return 2
    audit = None
    if s.audit_log:
        s.audit_log.parent.mkdir(parents=True, exist_ok=True)
        audit = open(s.audit_log, "a", encoding="utf-8")
        os.chmod(s.audit_log, 0o600)
    up, creds, bundle = resolve_upstream(s, {(s.host, s.port)}, s.vault_dir)
    gw = Gateway(build_redactor(s), s.upstream, api_key, s.unknown_post, audit,
                 upstream_proxy=up.url, proxy_auth=creds, ca_bundle=bundle,
                 health_secret=healthproof.load(s.hook_secret_file, create=True))

    async def main():
        runner = web.AppRunner(gw.app())
        await runner.setup()
        site = web.TCPSite(runner, s.host, s.port)
        await site.start()
        logging.getLogger("redact_guard").info(
            '{"event":"listening","host":"%s","port":%d,"upstream":"%s","vault_entries":%d}',
            s.host, s.port, s.upstream, len(gw.redactor.vault))
        if s.egress_enabled:
            eg = EgressProxy(s.egress_allow, s.egress_ports)
            await eg.serve(s.host, s.egress_port)
            logging.getLogger("redact_guard").info(
                '{"event":"egress_listening","port":%d,"allow":%d}', s.egress_port, len(s.egress_allow))
        await asyncio.Event().wait()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    return 0


PROXY_ALLOW_HOSTS = r"^(?:.+\.)?(?:anthropic\.com|claude\.ai|claude\.com|redact-guard\.invalid)(?::\d+)?$"


def _proxy_confdir(s: C.Settings):
    from pathlib import Path
    d = s.proxy_confdir or (s.vault_dir / "mitm")
    Path(d).mkdir(parents=True, exist_ok=True, mode=0o700)
    return Path(d)


def _ensure_ca(confdir) -> str:
    """Create the local CA (once). Returns the public cert path for NODE_EXTRA_CA_CERTS."""
    from mitmproxy.certs import CertStore
    CertStore.from_store(str(confdir), "mitmproxy", 2048)
    key = confdir / "mitmproxy-ca.pem"            # private key + cert: keep private
    if os.name == "nt":
        from .vault import _restrict_windows_acl
        _restrict_windows_acl(key)
    else:
        os.chmod(key, 0o600)
    return str(confdir / "mitmproxy-ca-cert.pem")


@_logged
def cmd_proxy(args) -> int:
    """Proxy mode: HTTPS proxy that redacts Anthropic traffic (keeps Remote Control usable)."""
    if args.log_file or sys.stderr is None:   # no console: Scheduled Task, pythonw
        _log_to_file(args.log_file or os.path.join(os.path.expanduser("~"), ".local", "share",
                                                   "redact-guard", "proxy.log"))
    s = C.load(args.config)
    if args.port:
        s.proxy_port = args.port
    confdir = _proxy_confdir(s)
    ca = _ensure_ca(confdir)
    if args.init:
        print(ca)
        return 0
    up, creds, bundle = resolve_upstream(s, {(s.proxy_host, s.proxy_port)}, confdir)
    if args.config:
        os.environ["REDACT_GUARD_CONFIG"] = os.path.abspath(args.config)
    from mitmproxy import options
    from mitmproxy.tools.dump import DumpMaster
    from .mitm_addon import RedactGuardAddon

    async def main():
        opts = options.Options(listen_host=s.proxy_host, listen_port=s.proxy_port,
                               confdir=str(confdir))
        master = DumpMaster(opts, with_termlog=False, with_dumper=False)   # our logging config applies
        # these options are defined by mitmproxy's own addons, so set them after loading
        master.options.update(allow_hosts=[PROXY_ALLOW_HOSTS], connection_strategy="lazy",
                              ssl_insecure=False,
                              # HTTP/1.1 on both sides unless REDACT_GUARD_HTTP2=1: rewritten SSE
                              # streams over h2 (e.g. via a TLS-inspecting proxy) may not end cleanly
                              http2=os.environ.get("REDACT_GUARD_HTTP2") == "1")
        if bundle:
            master.options.update(ssl_verify_upstream_trusted_ca=bundle)
        if up.url:
            # chain behind the existing proxy: Claude Code -> redact-guard -> your proxy -> internet
            master.options.update(mode=[f"upstream:{up.url}"])
            if creds:
                master.options.update(upstream_auth=creds)
        master.addons.add(RedactGuardAddon())
        logging.getLogger("redact_guard").info(
            '{"event":"proxy_listening","host":"%s","port":%d,"ca":"%s"}', s.proxy_host,
            s.proxy_port, ca.replace("\\", "/"))
        await master.run()
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    return 0


def cmd_scan(args) -> int:
    """Show what would be sent upstream for the given files (ephemeral vault)."""
    s = C.load(args.config)
    r = build_redactor(s, ephemeral=True)
    for f in args.files:
        text = open(f, encoding="utf-8", errors="replace").read()
        out = r.tokenize(text)
        back, _ = r.restore(out, ALL_CLASSES)
        status = "roundtrip=ok" if back == text else "roundtrip=MISMATCH"
        print(f"===== {f} ({status})")
        print(out)
    return 0


SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
             ".next", ".nuxt", "target", "vendor", ".terraform", ".tox", ".mypy_cache",
             ".pytest_cache", ".gradle", ".idea", ".vscode", "coverage", ".cache"}
def _review_re():
    import re
    return re.compile(r"(?i)(pass(?:wd|word)?|secret|token|api[_-]?key|private[_-]?key|credential|"
                      r"şifre|sifre|parola|vkn|tckn|iban|conn(?:ection)?[_-]?str|dsn)")


def cmd_audit(args) -> int:
    """Walk a project and report what would be redacted, and lines worth a manual look."""
    import re
    import subprocess
    from collections import Counter
    from pathlib import Path
    s = C.load(args.config)
    r = build_redactor(s, ephemeral=True)
    root = Path(args.dir).resolve()
    review_rx = _review_re()
    totals: Counter = Counter()
    per_file: list[tuple[str, Counter]] = []
    review: list[str] = []
    files = 0
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts) or not path.is_file():
            continue
        try:
            if path.stat().st_size > args.max_bytes:
                continue
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw[:8192]:
            continue
        text = raw.decode("utf-8", errors="replace")
        files += 1
        from .engine import Stats
        st = Stats()
        out = r.tokenize(text, st)
        c = Counter({k: v for k, v in st.counts.items() if k != "EXACT"})
        c["EXACT"] = st.counts.get("EXACT", 0)
        c = +c
        if c:
            per_file.append((str(path.relative_to(root)), c))
            totals.update(c)
        # lines with sensitive-sounding words where nothing was substituted
        for n, (a, b) in enumerate(zip(text.splitlines(), out.splitlines()), 1):
            if a == b and re.search(r"[:=]\s*\S", a):
                key = re.split(r"[:=]", a, maxsplit=1)[0].strip()[:60]
                if review_rx.search(key):
                    review.append(f"  {path.relative_to(root)}:{n}  {key} = <left as-is>")
    git_people = 0
    if (root / ".git").exists() and not args.no_git:
        try:
            log = subprocess.run(["git", "-C", str(root), "log", "-n", "300", "--format=fuller"],
                                 capture_output=True, text=True, timeout=30).stdout
            from .engine import Stats
            st = Stats()
            r.tokenize(log, st)
            git_people = st.counts.get("PERSON", 0) + st.counts.get("EMAIL", 0)
        except Exception:
            pass
    print(f"redact-guard audit: {root}")
    print(f"  files scanned: {files}   values substituted: {sum(totals.values())}")
    print("  by class: " + (", ".join(f"{k}={v}" for k, v in totals.most_common()) or "none"))
    if git_people:
        print(f"  git history (last 300 commits): {git_people} names/emails would be hidden")
    print("\n  top files:")
    for f, c in sorted(per_file, key=lambda x: -sum(x[1].values()))[:args.top]:
        print(f"    {sum(c.values()):5}  {f}  ({', '.join(f'{k}={v}' for k, v in c.most_common())})")
    if review:
        print(f"\n  review ({len(review)}): sensitive-looking keys whose value was NOT substituted.")
        print("  Usually fine (references, placeholders, booleans). If a real value is listed,")
        print("  add a custom pattern or report the format. Values are not printed.")
        for line in review[:args.top * 3]:
            print(line)
    print("\nNext: `redact-guard scan <file>` shows exactly what the model would see for one file.")
    return 0


def cmd_doctor(args) -> int:
    from .doctor import run
    return run(args.config)


def cmd_digest(args) -> int:
    """sha256 of a value read from stdin (keeps it out of shell history), for allow_digests."""
    import getpass
    import hashlib
    v = getpass.getpass("value to allow (not echoed): ") if sys.stdin.isatty() else sys.stdin.read().rstrip("\r\n")
    print(hashlib.sha256(v.encode()).hexdigest())
    return 0


def main(argv=None) -> int:
    logging.basicConfig(level=os.environ.get("REDACT_GUARD_LOG", "INFO"),
                        format="%(message)s", stream=sys.stderr or open(os.devnull, "w"))
    # mitmproxy logs every client/server connect at INFO; keep logs to redact-guard's own events
    logging.getLogger("mitmproxy").setLevel(os.environ.get("REDACT_GUARD_MITM_LOG", "WARNING"))
    ap = argparse.ArgumentParser(prog="redact-guard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("serve", help="run the redacting gateway")
    sp.add_argument("-c", "--config")
    sp.add_argument("--host")
    sp.add_argument("--port", type=int)
    sp.add_argument("--log-file", help="log here instead of stderr (used by the Windows logon task)")
    sp.set_defaults(fn=cmd_serve)
    px = sub.add_parser("proxy", help="run as an HTTPS proxy (proxy mode: Remote Control works)")
    px.add_argument("-c", "--config")
    px.add_argument("--port", type=int)
    px.add_argument("--init", action="store_true", help="create the local CA and print its cert path")
    px.add_argument("--log-file")
    px.set_defaults(fn=cmd_proxy)
    sc = sub.add_parser("scan", help="preview redaction of files (nothing is stored)")
    sc.add_argument("-c", "--config")
    sc.add_argument("files", nargs="+")
    sc.set_defaults(fn=cmd_scan)
    au = sub.add_parser("audit", help="scan a whole project: what gets hidden, what to review")
    au.add_argument("-c", "--config")
    au.add_argument("dir")
    au.add_argument("--top", type=int, default=20)
    au.add_argument("--max-bytes", type=int, default=2_000_000)
    au.add_argument("--no-git", action="store_true")
    au.set_defaults(fn=cmd_audit)
    dr = sub.add_parser("doctor", help="check the whole setup (PASS/WARN/FAIL)")
    dr.add_argument("-c", "--config")
    dr.set_defaults(fn=cmd_doctor)
    dg = sub.add_parser("digest", help="sha256 of a value from stdin, for detectors.allow_digests")
    dg.set_defaults(fn=cmd_digest)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
