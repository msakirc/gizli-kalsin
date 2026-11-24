"""Detectors. Each returns spans ``(start, end, cls)`` over the given text.

Detectors run in a fixed order inside :class:`redact_guard.engine.Redactor`;
earlier ones win (a span that overlaps an already-substituted token is
skipped). Spans cover *only the value* (never surrounding quotes or
delimiters), which is what makes ``restore(tokenize(x)) == x`` hold.

Over-redaction is safe (the round trip restores it exactly); under-redaction
is the leak. When in doubt, the detectors redact.
"""
from __future__ import annotations

import base64
import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Iterable

from . import vault as V


@dataclass
class Span:
    start: int
    end: int
    cls: str
    # extra (value, cls) pairs to teach the vault, e.g. the decoded form of a
    # base64 Kubernetes secret, so it is caught wherever it shows up later.
    learn: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class DetectorConfig:
    internal_domains: list[str] = field(default_factory=lambda: [
        ".internal", ".corp", ".local", ".lan", ".intra", ".intranet", ".home.arpa",
        # managed databases / caches / clusters: the hostname itself names your instance
        ".rds.amazonaws.com", ".cache.amazonaws.com", ".docdb.amazonaws.com",
        ".redshift.amazonaws.com", ".redshift-serverless.amazonaws.com", ".es.amazonaws.com",
        ".aoss.amazonaws.com", ".kafka.amazonaws.com", ".memorydb.amazonaws.com",
        ".elb.amazonaws.com", ".compute.amazonaws.com", ".eks.amazonaws.com",
        ".database.windows.net", ".redis.cache.windows.net", ".documents.azure.com",
        ".postgres.database.azure.com", ".mysql.database.azure.com", ".servicebus.windows.net",
        ".mongodb.net", ".cloudsql.goog", ".svc.cluster.local"])
    allow_values: set[str] = field(default_factory=set)
    allow_emails: set[str] = field(default_factory=lambda: {
        "noreply@anthropic.com", "git@github.com", "git@gitlab.com", "git@bitbucket.org"})
    allow_email_domains: set[str] = field(default_factory=lambda: {
        "example.com", "example.org", "example.net"})
    allow_users: set[str] = field(default_factory=set)
    names: list[str] = field(default_factory=list)
    custom: list[tuple[re.Pattern, str]] = field(default_factory=list)
    entropy: bool = True
    entropy_min_len: int = 32
    entropy_threshold: float = 4.3
    phones: bool = True
    turkish_ids: bool = True
    cards: bool = True
    vkn_unkeyed: bool = True        # checksum-valid 10-digit numbers without a "vkn:" label
    git_identities: bool = True
    gitleaks: bool = True
    gitleaks_rules: str | None = None   # path to your own gitleaks.toml (default: bundled)
    allow_digests: set[str] = field(default_factory=set)   # sha256 hex of values never redacted
    # The account names Claude Code runs as. Always hidden as USER wherever they appear, so
    # they're restored into shell commands (cd C:\Users\<you>\...), even when the name
    # looks like an ID number (a TCKN-shaped Windows username).
    own_usernames: list[str] = field(default_factory=list)
    public_hosts: set[str] = field(default_factory=lambda: {
        "github.com", "gitlab.com", "bitbucket.org", "registry.npmjs.org", "pypi.org",
        "files.pythonhosted.org", "docker.io", "registry-1.docker.io", "ghcr.io", "quay.io",
        "api.github.com", "raw.githubusercontent.com", "proxy.golang.org", "crates.io",
        "repo.maven.apache.org", "repo1.maven.org", "plugins.gradle.org", "api.nuget.org",
        "www.w3.org", "json-schema.org", "schema.org", "example.com", "example.org",
        "api.anthropic.com", "registry.terraform.io", "charts.helm.sh", "k8s.io"})
    allow_names: set[str] = field(default_factory=lambda: {
        "Claude", "Anthropic", "GitHub", "GitHub Actions", "GitLab", "Dependabot",
        "Renovate Bot", "renovate", "dependabot", "github-actions", "Copilot"})


Detector = Callable[[str, DetectorConfig], Iterable[Span]]

# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
_LITERAL_SKIP = {
    "", "true", "false", "yes", "no", "on", "off", "null", "none", "nil", "~",
    "undefined", "required", "optional", "string", "str", "number", "int",
    "integer", "boolean", "bool", "any", "unknown", "bytes", "object",
    "redacted", "<redacted>", "[redacted]", "***", "****", "xxx", "...",
    "secret", "password", "token", "default", "env", "self", "this",
}
_REF_PREFIXES = ("${", "$(", "{{", "<%", "%(", "#{", "!ref", "!sub", "!getatt",
                 "secretkeyref", "valuefrom", "vault:", "enc[", "op://",
                 "sops:", "awssm:", "process.env", "os.environ", "os.getenv",
                 "env(", "env.", "getenv(", "settings.", "config.", "<", "*", "&")


_CODE_ROOTS = {
    "self", "this", "cls", "args", "argv", "options", "opts", "option", "config", "cfg",
    "conf", "settings", "request", "req", "res", "response", "ctx", "context", "params",
    "props", "env", "process", "os", "app", "data", "payload", "body", "input", "form",
    "values", "credentials", "creds", "secrets", "kwargs", "vars", "obj", "state",
    "session", "auth", "window", "document", "module", "exports", "import", "meta",
    "user", "account", "field", "fields", "row", "record", "model", "instance", "item",
    "event", "msg", "message", "result", "spec", "parsed", "cli", "flags", "store",
    "flow", "f", "conn", "connection", "command", "client", "server", "url", "uri", "e", "err",
    "m", "o", "p", "r", "s", "x", "it", "opt", "ns", "info", "entry", "node", "target", "upstream",
    "proxy", "resp", "headers", "cookies", "loop", "transport", "sock", "socket", "addr", "peer",
}
_PY_KEYWORDS = {"await", "async", "lambda", "yield", "return", "not", "None", "True", "False",
                "self", "cls", "new", "this", "null", "nil", "undefined"}


def _is_reference_or_literal(v: str) -> bool:
    s = v.strip()
    low = s.lower()
    if low in _LITERAL_SKIP or V.TOKEN_RE.fullmatch(s):
        return True
    if low.startswith(_REF_PREFIXES):
        return True
    if re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", s):            # $DB_PASSWORD
        return True
    if "(" in s:                                                  # get_token()
        return True
    m = re.fullmatch(r"([A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*)+", s)
    if m and m.group(1).lower() in _CODE_ROOTS:                   # args.password
        return True
    if re.fullmatch(r"[a-z0-9]+(?:[-_][a-z0-9]+)+", s) and re.search(
            r"(?:^|[-_])(?:secret|password|passwd|key|keys|token|credentials?|tls|cert|creds)(?:[-_]|$)", s):
        return True                                               # orders-db-secret (a name)
    if re.fullmatch(r"[A-Z][A-Za-z]*(?:\[.*\]|<.*>)", s) or \
            re.match(r"(?:typing\.)?[A-Z][A-Za-z]*\[", s):          # Optional[str], Final[istr
        return True
    if s in _PY_KEYWORDS:
        return True
    return False


def is_code_identifier(v: str, key: str = "") -> bool:
    """An unquoted value that reads as a variable, not a credential: proxy_auth=proxy_auth,
    auth=BasicAuth, password=self.password, currentByte. Has no digits by design, since
    passwords nearly always do; quoted values are never treated as identifiers."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z_]*(?:\.[A-Za-z_][A-Za-z_]*)*", v):
        return False
    k = key.strip("\"' ").lower()
    last = re.split(r"[_.\-]", k)[-1] if k else ""
    return ("_" in v or "." in v or v.lower() == k or (last and v.lower().endswith(last))
            or bool(re.fullmatch(r"(?:[A-Z][a-z]+){2,}|[a-z]+(?:[A-Z][a-z]+)+", v)))


def _contains_token(s: str) -> bool:
    return "RDX_" in s


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


_PLAIN_USER_RE = re.compile(r"[a-z_][a-z0-9_.\-]{0,31}\$?|[A-Z][a-z]+(?:[._][A-Z][a-z]+)?", re.ASCII)


def looks_like_plain_username(v: str) -> bool:
    """deploy, git, svc_orders, ayse.demir, Administrator: not a token."""
    return bool(_PLAIN_USER_RE.fullmatch(v)) and not looks_like_secret(v)


def looks_random(v: str) -> bool:
    """Mixes letter cases/digits/symbols the way passwords and keys do (not a word)."""
    kinds = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    return kinds >= 3 or (kinds == 2 and len(v) >= 12 and shannon(v) >= 3.2)


def looks_like_secret(v: str) -> bool:
    """Credential-shaped: a known token format, or long and random-looking."""
    if not v or len(v) < 8:
        return False
    if any(rx.search(v) for rx in _KNOWN_TOKENS):
        return True
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
    if len(v) >= 16 and classes == 3 and shannon(v) >= 3.3:
        return True
    return len(v) >= 24 and shannon(v) >= 3.8


# --------------------------------------------------------------------------
# 1. private key blocks
# --------------------------------------------------------------------------
_PRIVKEY_RE = re.compile(
    r"-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY((?: BLOCK)?)-----"
    r"[\s\S]{0,16384}?-----END \1PRIVATE KEY\2-----")     # bounded: no quadratic scan


def privkey(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    for m in _PRIVKEY_RE.finditer(text):
        yield Span(m.start(), m.end(), V.PRIVKEY)


# --------------------------------------------------------------------------
# 2. URIs with credentials: scheme://user:pass@host
# --------------------------------------------------------------------------
_URI_CRED_RE = re.compile(
    r"\b(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]{1,20})://"
    r"(?P<user>[^\s:/@'\"`<>]*)(?::(?P<pw>[^\s@/'\"`<>]*))?@"
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[^\s/:'\"`<>?#,;@]+)")


def uri_credentials(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    for m in _URI_CRED_RE.finditer(text):
        user, pw, host = m.group("user"), m.group("pw"), m.group("host")
        if user and not _contains_token(user) and user not in cfg.allow_users \
                and not _is_reference_or_literal(user):
            # https://ghp_xxx@github.com, https://<api-token>@host: a user part with no password,
            # or one that looks like a credential, is a SECRET (never restored into the shell).
            cls_u = V.SECRET if (pw is None and m.group("scheme").lower() not in ("ssh", "sftp", "scp")
                                 and not looks_like_plain_username(user)) \
                or looks_like_secret(user) else V.USER
            yield Span(m.start("user"), m.end("user"), cls_u)
        if pw and not _contains_token(pw) and not _is_reference_or_literal(pw):
            yield Span(m.start("pw"), m.end("pw"), V.SECRET)
        if host and not _contains_token(host) and host.lower() not in ("localhost",) \
                and host.lower() not in cfg.public_hosts:
            cls = _classify_host(host.strip("[]"))
            if cls:
                s, e = m.start("host"), m.end("host")
                if host.startswith("["):
                    s, e = s + 1, e - 1
                yield Span(s, e, cls)


def _classify_host(h: str) -> str | None:
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return V.HOST if "." in h or len(h) > 2 else None
    if ip.is_loopback or ip.is_unspecified:
        return None
    if ip.version == 6:
        return V.IPV6
    return V.IPPRIV if (ip.is_private or ip in ipaddress.ip_network("100.64.0.0/10")) else V.IP


# --------------------------------------------------------------------------
# 3. auth headers & CLI credentials
# --------------------------------------------------------------------------
_AUTH_HDR_RE = re.compile(
    r"(?i)\b(?:proxy-)?authorization[\"']?\s*[:=]\s*[\"']?"
    r"(?:(?:bearer|basic|token|digest|negotiate|apikey)\s+)?(?P<v>[^\s'\",;]+)")
_COOKIE_RE = re.compile(r"(?im)^[ \t]*(?:set-)?cookie[ \t]*:[ \t]*(?P<v>[^\r\n]+?)[ \t]*\r?$")
_CURL_USER_RE = re.compile(r"(?:\s-u|\s--user)\s+[\"']?(?P<u>[^\s:\"']+):(?P<p>[^\s\"']+)")


def auth_headers(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    for m in _AUTH_HDR_RE.finditer(text):
        v = m.group("v")
        if not _contains_token(v) and not _is_reference_or_literal(v) and len(v) >= 4:
            yield Span(m.start("v"), m.end("v"), V.SECRET)
    for m in _COOKIE_RE.finditer(text):
        if not _contains_token(m.group("v")):
            yield Span(m.start("v"), m.end("v"), V.SECRET)
    for m in _CURL_USER_RE.finditer(text):
        if not _contains_token(m.group(0)):
            yield Span(m.start("u"), m.end("u"), V.USER)
            yield Span(m.start("p"), m.end("p"), V.SECRET)


# --------------------------------------------------------------------------
# 4. Kubernetes Secret manifests (data / stringData values)
# --------------------------------------------------------------------------
_K8S_KIND_RE = re.compile(r"(?m)^\s*kind:\s*[\"']?Secret[\"']?\s*$")
_K8S_JSON_KIND_RE = re.compile(r"\"kind\"\s*:\s*\"Secret\"")
_K8S_JSON_DATA_RE = re.compile(r"\"(?:data|stringData)\"\s*:\s*\{(?P<body>[^{}]*)\}")
_JSON_KV_RE = re.compile(r"\"(?:[^\"\\]|\\.)+\"\s*:\s*\"(?P<v>(?:[^\"\\]|\\.)*)\"")


def _yaml_documents(text: str):
    """Yield (offset, doc_text) for each `---`-separated YAML document."""
    pos = 0
    start = 0
    for line in text.splitlines(keepends=True):
        if re.match(r"^---\s*$", line.rstrip("\r\n")):
            yield start, text[start:pos]
            start = pos + len(line)
        pos += len(line)
    yield start, text[start:]


def k8s_secrets(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    if _K8S_KIND_RE.search(text):
        for off, doc in _yaml_documents(text):
            if not _K8S_KIND_RE.search(doc):
                continue
            pos = off
            block_indent: int | None = None
            for line in doc.splitlines(keepends=True):
                stripped = line.rstrip("\r\n")
                indent = len(stripped) - len(stripped.lstrip(" "))
                if block_indent is not None:
                    if stripped.strip() and indent <= block_indent:
                        block_indent = None
                    else:
                        m = re.match(r"^\s+[\w.\-]+:\s*(?P<q>[\"']?)(?P<v>[^\"'\s#][^\"'#]*?)(?P=q)\s*$",
                                     stripped)
                        if m and not _contains_token(m.group("v")):
                            v = m.group("v")
                            yield Span(pos + m.start("v"), pos + m.end("v"), V.SECRET,
                                       learn=_b64_learn(v))
                if block_indent is None and re.match(r"^\s*(data|stringData):\s*$", stripped):
                    block_indent = indent
                pos += len(line)
    if _K8S_JSON_KIND_RE.search(text):
        for dm in _K8S_JSON_DATA_RE.finditer(text):
            base = dm.start("body")
            for kv in _JSON_KV_RE.finditer(dm.group("body")):
                v = kv.group("v")
                if v and not _contains_token(v):
                    yield Span(base + kv.start("v"), base + kv.end("v"), V.SECRET,
                               learn=_b64_learn(v))


def _b64_learn(v: str) -> list[tuple[str, str]]:
    """Other forms of a secret worth knowing: its base64 decoding (k8s Secrets, basic auth)
    and its own base64 encodings (so `echo -n pw | base64` output is caught later)."""
    out: list[tuple[str, str]] = []
    try:
        raw = base64.b64decode(v, validate=True).decode("utf-8").strip()
        if len(raw) >= 4 and raw.isprintable():
            out.append((raw, V.SECRET))
    except Exception:
        pass
    if len(v) >= 8:
        b = v.encode()
        enc = base64.b64encode(b).decode()
        out += [(enc, V.SECRET), (enc.rstrip("="), V.SECRET),
                (base64.urlsafe_b64encode(b).decode().rstrip("="), V.SECRET)]
    return list(dict.fromkeys(out))


# --------------------------------------------------------------------------
# 5. keyed values: password: x / API_KEY=x / "token": "x" / <password>x</...>
# --------------------------------------------------------------------------
_SECRET_KEY = (r"[A-Za-z0-9_.\-]{0,64}?(?:pass(?:wd|word|phrase)?|pwd|secret|token|"
               r"api[_.\-]?key|apikey|access[_.\-]?key|private[_.\-]?key|"
               r"client[_.\-]?secret|credentials?|auth[_.\-]?(?:key|token|code)|"
               r"session[_.\-]?(?:id|key|secret)|signing[_.\-]?key|"
               r"encryption[_.\-]?key|master[_.\-]?key|salt|dsn|"
               r"connection[_.\-]?string|conn[_.\-]?str|webhook[_.\-]?url|"
               r"accountkey|sharedaccesskey|sas[_.\-]?token|auth|identitytoken)[A-Za-z0-9_.\-]{0,64}")
_USER_KEY = (r"(?:[A-Za-z0-9_.\-]{0,64}?[_.\-]|[A-Za-z0-9]{0,64}?[a-z0-9](?=(?-i:[A-Z])))?"   # db_user, basicAuthUsername
             r"(?:user(?:name)?|login|db[_.\-]?user|owner|"
             r"admin[_.\-]?user|uid)")
_HOST_KEY = (r"[A-Za-z0-9_.\-]{0,64}?(?:host(?:name)?s?|servers?|endpoints?|addr(?:ess)?(?:es)?|"
             r"fqdn|domain|ur[li]s?|servis|services?|svc|gateway|proxy|brokers?|origin|"
             r"bootstrap[_.\-]?servers|base[_.\-]?ur[li]|link)(?:[_.\-]?[A-Za-z0-9]+)??\d*")

_KEY_EXCLUDE = re.compile(
    r"(?i)(?:^|[_.\-])(?:max|min|num|n|total|count|limit|input|output|cached|"
    r"prompt|completion)[_.\-]?tokens?$|tokens?[_.\-]?(?:count|limit|usage|budget|"
    r"type|endpoint|url|uri|ttl|expiry|expires|expiration|lifetime|length|len|size|"
    r"refresh|file|path|name|ref|header|prefix|kind|format)$|tokeniz|passthrough|"
    r"bypass|compass|passenger|passive|[_.\-]?(?:len|length|ttl|timeout|expir[a-z]*|"
    r"policy|rotation|reset|hint|prompt|label|field|placeholder|enabled|required|"
    r"file|path|dir|name|ref|keyref|key_ref|mount|provider|type|manager|store|"
    r"rules|strength|regex|pattern|min|max|validator|confirm|confirmation|"
    r"count|header|param|id_field)$|existing[_.\-]?secret|secret[_.\-]?keys?$|"
    r"(?:password|username|user|token|secret)[_.\-]?key$|secret[_.\-]?(?:name|ref)")
# Auth-ish keys that are usually settings, not secrets (auth_enabled, authorization_url, author).
# They only exclude a key when it has no strong secret word: basicAuthenticationPassword is a secret.
_AUTH_EXCLUDE = re.compile(
    r"(?i)author|authorit|authoriz|authent|authz|auths$|auth[_.\-]?(?:enabled|disabled|type|mode|method|"
    r"methods|provider|providers|url|uri|endpoint|domain|server|required|strategy|flow|scheme|scope|"
    r"scopes|realm|path|file|config|plugin|backend|source|service|header|policy|level|version)$|"
    r"oauth[_.\-]?(?:enabled|provider|url|uri|scopes?|flow)$")
_STRONG_SECRET = re.compile(r"(?i)pass(?:wd|word|phrase)|pwd|secret|api[_.\-]?key|apikey|"
                            r"private[_.\-]?key|credential|auth[_.\-]?token|access[_.\-]?token")


def _secret_key_excluded(key: str) -> bool:
    if _KEY_EXCLUDE.search(key):
        return True
    return bool(_AUTH_EXCLUDE.search(key)) and not _STRONG_SECRET.search(key)
_USER_KEY_EXCLUDE = re.compile(r"(?i)user[_.\-]?(?:agent|data|guide|interface|space|land|mode)$|"
                               r"runasuser|fsgroup|^uid$")
_HOST_KEY_EXCLUDE = re.compile(r"(?i)(?:^|[_.\-])(?:virtual|vhost)$|hostnetwork|hostpath|hostport|"
                               r"hostpid|hostipc|hostaliases|server[_.\-]?side|serverless|domain[_.\-]?(?:model|events?|logic|layer)|"
                               r"[_.\-]?(?:port|timeout|enabled|class|type|path|count|retries|size|pattern|regex)$")

# Value: double-, single- or back-quoted, or unquoted up to a delimiter.
_VAL_ALTS = (r"(?:\"(?P<dq>(?:[^\"\\\n]|\\.)*)\"|'(?P<sq>(?:[^'\\\n]|\\.)*)'|"
             r"`(?P<bq>[^`\n]*)`|(?P<uq>[^\s,;'\"&}\])<>`|]+))")
_ASSIGN = r"[\"']?\s*(?:=>|:=|(?<![=!<>:])=(?!=)|:(?![:/]))[ \t]*"


def _keyed_re(keypat: str) -> re.Pattern:
    return re.compile(r"(?<![A-Za-z0-9_\-])[\"']?(?P<key>" + keypat + r")" + _ASSIGN + _VAL_ALTS, re.I)


_SECRET_ASSIGN_RE = _keyed_re(_SECRET_KEY)
_USER_ASSIGN_RE = _keyed_re(_USER_KEY)
_HOST_ASSIGN_RE = _keyed_re(_HOST_KEY)
_XML_RE = re.compile(r"<(?P<key>" + _SECRET_KEY + r")>(?P<v>[^<\n]{1,512})</(?P=key)>", re.I)
_FLAG_RE = re.compile(r"(?<![\w-])--(?P<key>" + _SECRET_KEY + r")(?:=|\s+)(?P<q>[\"']?)(?P<v>[^\s\"']+)(?P=q)", re.I)


def _val_group(m: re.Match) -> str:
    for g in ("dq", "sq", "bq", "uq"):
        if m.group(g) is not None:
            return g
    return "uq"


# ${NAME:default} (Spring), ${NAME:-default} / ${NAME:=default} / ${NAME-default} (shell)
_PLACEHOLDER_RE = re.compile(r"\$\{[A-Za-z_][\w.\-]*(?::-|:=|:\?|:|-)")


def _placeholder_default(v: str) -> tuple[int, str] | None:
    """For a `${NAME:default}` value, return (offset, default) of the innermost literal
    default; None when there is no default (a pure reference, nothing to redact)."""
    off = 0
    while True:
        m = _PLACEHOLDER_RE.match(v, off)
        if not m:
            return None if off == 0 else (off, v[off:].rstrip("}"))
        off = m.end()
        if not v.startswith("${", off):
            d = v[off:]
            depth, i = 0, 0
            for i, ch in enumerate(d):          # stop at the brace that closes the placeholder
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    if depth == 0:
                        d = d[:i]
                        break
                    depth -= 1
            return off, d


_URL_HOST_RE = re.compile(
    r"(?:[A-Za-z][A-Za-z0-9+.\-]{1,20}:)*"                    # jdbc:postgresql://, jdbc:mysql:loadbalance://
    r"(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]{1,20})://(?:[^\s/@]*@)?"
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9](?:[A-Za-z0-9\-_.]*[A-Za-z0-9])?)")
_HOSTNAME_STRICT = re.compile(r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9\-]{1,23}")
# two-label names (`up.url`, `cfg.server`) are usually code; accept them only with a real TLD
_COMMON_TLDS = {"com", "net", "org", "io", "dev", "app", "ai", "co", "tr", "de", "uk", "eu", "us",
                "nl", "fr", "it", "es", "ch", "at", "be", "se", "no", "fi", "pl", "ru", "az", "info",
                "biz", "cloud", "tech", "me", "xyz", "gov", "edu", "mil", "int", "local", "internal",
                "lan", "intra", "intranet", "localdomain", "corp", "home", "svc", "test", "example"}
_REVERSE_DNS_ROOTS = {"com", "org", "net", "io", "tr", "de", "uk", "java", "javax", "android", "kotlin"}
_FILE_LIKE = re.compile(r"(?i)\.(?:ya?ml|json|xml|properties|conf|cfg|ini|txt|log|sh|py|js|ts|java|"
                        r"kt|go|rb|php|html?|css|md|jar|war|zip|gz|tgz|pem|crt|key|p12|jks|sql|db|"
                        r"lock|toml|env|exe|dll|so)$")


def _host_ok(h: str, cfg: DetectorConfig) -> bool:
    lo = h.lower().strip("[]")
    return bool(lo) and lo not in ("localhost", "0.0.0.0") and not lo.startswith("127.") \
        and lo not in cfg.public_hosts and not _contains_token(h)


def _net_value_spans(v: str, base: int, cfg: DetectorConfig) -> list[Span]:
    """Host part of a URL / host[:port] value under a host- or URL-like key."""
    m = _URL_HOST_RE.match(v)
    if m:
        h = m.group("host")
        if not _host_ok(h, cfg) or m.group("scheme").lower() in ("file", "classpath", "jar"):
            return []
        s, e = base + m.start("host"), base + m.end("host")
        if h.startswith("["):
            s, e, h = s + 1, e - 1, h[1:-1]
        try:
            ipaddress.ip_address(h)
            cls = _classify_host(h)
        except ValueError:
            cls = V.HOST                        # single-label service names count (http://dis-servis)
        return [Span(s, e, cls)] if cls else []
    if "/" in v or v.startswith("."):
        return []
    h = v.rsplit(":", 1)[0] if re.search(r":\d{1,5}$", v) else v
    if ":" in h:                                # bare IPv6, or not a host at all
        try:
            ipaddress.IPv6Address(h)
        except ValueError:
            return []
    if not _host_ok(h, cfg):
        return []
    try:
        ipaddress.ip_address(h)
        cls = _classify_host(h)
    except ValueError:
        labels = h.split(".")
        if labels[0] in _CODE_ROOTS and not any(h.endswith(d) for d in cfg.internal_domains):
            return []                           # flow.request.host, self.local
        if not _HOSTNAME_STRICT.fullmatch(h) or labels[0] in _REVERSE_DNS_ROOTS \
                or _FILE_LIKE.search(h) or (len(labels) == 2 and (labels[1] not in _COMMON_TLDS
                                                                  or len(labels[0]) < 2)):
            return []
        cls = V.HOST
    return [Span(base, base + len(h), cls)] if cls else []


def key_class(key: str) -> str | None:
    """Which class a key's value belongs to (SECRET / USER / HOST), or None."""
    k = key.strip("\"' ")
    if not k or len(k) > 120:
        return None
    if re.fullmatch(_SECRET_KEY, k, re.I) and not _secret_key_excluded(k):
        return V.SECRET
    if re.fullmatch(_USER_KEY, k, re.I) and not _USER_KEY_EXCLUDE.search(k):
        return V.USER
    if re.fullmatch(_HOST_KEY, k, re.I) and not _HOST_KEY_EXCLUDE.search(k):
        return V.HOST
    return None


def value_spans(cls: str, v: str, vstart: int, cfg: DetectorConfig,
                unquoted: bool = False, key: str = "") -> list[Span]:
    """Spans for value ``v`` (at ``vstart``) of a key of class ``cls``."""
    if v is None or _contains_token(v):
        return []
    if v.lstrip().startswith("${"):
        pd = _placeholder_default(v)
        if pd is None:
            return []                           # ${DB_PASSWORD}: a reference, nothing to hide
        vstart, v = vstart + pd[0], pd[1]
        if not v:
            return []
    if _is_reference_or_literal(v):
        return []
    if unquoted and (v.endswith(":") or v[:1] in "{[|>"):
        return []                               # nested mapping / object / block scalar marker
    if unquoted and cls == V.SECRET and is_code_identifier(v, key):
        return []
    if unquoted and cls == V.USER and (v.lower() == key.strip("\"' ").lower()
                                       or v.split(".")[0] in _CODE_ROOTS and "." in v
                                       or v in _PY_KEYWORDS):
        return []                               # user=user, owner=self.owner (usernames have _ and .)
    if cls == V.USER and len(v) < 2:
        return []
    if cls == V.USER:
        if v in cfg.allow_users or re.fullmatch(r"\d+", v):
            return []
    if cls == V.HOST:
        return _net_value_spans(v, vstart, cfg)
    if cls == V.SECRET and re.fullmatch(r"\d{1,3}", v):
        return []                               # `password_min: 8`-style numbers
    learn = _b64_learn(v) if cls == V.SECRET and len(v) >= 8 else []
    return [Span(vstart, vstart + len(v), cls, learn=learn)]


def keyed_values(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    for rx, cls, excluded in ((_SECRET_ASSIGN_RE, V.SECRET, _secret_key_excluded),
                              (_USER_ASSIGN_RE, V.USER, _USER_KEY_EXCLUDE.search),
                              (_HOST_ASSIGN_RE, V.HOST, _HOST_KEY_EXCLUDE.search)):
        for m in rx.finditer(text):
            if excluded(m.group("key")):
                continue
            g = _val_group(m)
            yield from value_spans(cls, m.group(g), m.start(g), cfg, unquoted=(g == "uq"),
                                   key=m.group("key"))
    for m in _XML_RE.finditer(text):
        v = m.group("v")
        if not _secret_key_excluded(m.group("key")) and not _contains_token(v) \
                and not _is_reference_or_literal(v):
            yield Span(m.start("v"), m.end("v"), V.SECRET)
    for m in _FLAG_RE.finditer(text):
        v = m.group("v")
        if not _secret_key_excluded(m.group("key")) and not _contains_token(v) \
                and not _is_reference_or_literal(v):
            yield Span(m.start("v"), m.end("v"), V.SECRET)


# --------------------------------------------------------------------------
# 5b. structured pairs: the key and the value sit in different fields or lines
# --------------------------------------------------------------------------
_QV = r"(?:\"(?P<dq>(?:[^\"\\\n]|\\.)*)\"|'(?P<sq>[^'\n]*)'|(?P<uq>[^\s#][^\n#]*?))"
# k8s / compose / ECS env:  - name: DB_PASSWORD \n  value: x   (either order)
_YAML_NV_RE = re.compile(r"(?m)^(?P<ind>[ \t]*)(?:-[ \t]+)?name:[ \t]*[\"']?(?P<k>[\w.\-]+)[\"']?[ \t]*\r?\n"
                         r"(?P=ind)[ \t]*value:[ \t]*" + _QV + r"[ \t]*\r?$")
_YAML_VN_RE = re.compile(r"(?m)^(?P<ind>[ \t]*)(?:-[ \t]+)?value:[ \t]*" + _QV + r"[ \t]*\r?\n"
                         r"(?P=ind)[ \t]*name:[ \t]*[\"']?(?P<k>[\w.\-]+)[\"']?[ \t]*\r?$")
_JSON_NV_RE = re.compile(r"\"(?:name|Name|key|Key)\"\s*:\s*\"(?P<k>[^\"]{1,120})\"\s*,\s*"
                         r"\"(?:value|Value)\"\s*:\s*\"(?P<dq>(?:[^\"\\]|\\.)*)\"")
_JSON_VN_RE = re.compile(r"\"(?:value|Value)\"\s*:\s*\"(?P<dq>(?:[^\"\\]|\\.)*)\"\s*,\s*"
                         r"\"(?:name|Name|key|Key)\"\s*:\s*\"(?P<k>[^\"]{1,120})\"")
# .NET appSettings / XML:  <add key="DbPassword" value="x"/>  <param name="password" value="x"/>
_XML_KV_RE = re.compile(r"(?i)\b(?:key|name)\s*=\s*\"(?P<k>[^\"]{1,120})\"\s+value\s*=\s*"
                        r"(?:\"(?P<dq>[^\"]*)\"|'(?P<sq>[^']*)')")
# YAML block scalar:  password: |  \n    value lines
_BLOCK_RE = re.compile(r"(?m)^(?P<ind>[ \t]*)(?:-[ \t]+)?(?P<k>[\w.\-\"']+)[ \t]*:[ \t]*[|>][+\-]?\d?[ \t]*\r?\n"
                       r"(?P<body>(?:(?P=ind)[ \t]+\S[^\n]*(?:\n|$)|[ \t]*\r?\n)+)")
# Terraform state / outputs: {"sensitive": true, "value": "x"} in either order
_TF_SENS_RE = re.compile(r"\"value\"\s*:\s*\"(?P<v1>(?:[^\"\\]|\\.)*)\"\s*,\s*(?:\"type\"\s*:\s*\"[^\"]*\"\s*,\s*)?"
                         r"\"sensitive\"\s*:\s*true|\"sensitive\"\s*:\s*true\s*,\s*(?:\"type\"\s*:\s*\"[^\"]*\"\s*,\s*)?"
                         r"\"value\"\s*:\s*\"(?P<v2>(?:[^\"\\]|\\.)*)\"")
# .pgpass / pgpass.conf:  host:port:database:user:password
_PGPASS_RE = re.compile(r"(?m)^(?P<h>[A-Za-z0-9_.\-*\[\]]+):(?P<p>\d{1,5}|\*):(?P<d>[^:\s#]+):"
                        r"(?P<u>[^:\s]+):(?P<pw>(?:\\:|[^\s:])+)[ \t]*\r?$")
# database error messages: server at "db-prod-01" ... for user "orders_admin"; 'root'@'10.0.0.1'
_DB_ERR_HOST_RE = re.compile(r"(?i)\b(?:server at|host|server)\s+\"(?P<h>[A-Za-z0-9][\w.\-]{1,253})\"")
_DB_ERR_USER_RE = re.compile(r"(?i)\bfor user\s+[\"'](?P<u>[^\"'\s]{1,64})[\"']"
                             r"|\buser\s+'(?P<u2>[^'\s]{1,64})'@'(?P<h2>[^'\s]{1,253})'")
# PEM/OpenSSH body lines read without the BEGIN line (Read offset, grep -n)
_PEM_LINE_RE = re.compile(r"(?m)^(?:[ ]*\d+(?:\t|\u2192)|[^\s:]{1,200}:\d+[:\-])?(?P<b>[A-Za-z0-9+/]{60,76}={0,2})\r?$")
_PEM_KEY_PREFIXES = ("b3BlbnNzaC1rZXktdjE", "MIIE", "MIIJ", "MIIC", "MIIG", "MHcCAQEE", "MC4CAQAw", "MIGH")


def _grp_value(m: re.Match) -> tuple[str | None, int, bool]:
    for g in ("dq", "sq", "uq"):
        if g in m.re.groupindex and m.group(g) is not None:
            return m.group(g), m.start(g), g == "uq"
    return None, -1, False


def structured_pairs(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    for rx in (_YAML_NV_RE, _YAML_VN_RE, _JSON_NV_RE, _JSON_VN_RE, _XML_KV_RE):
        for m in rx.finditer(text):
            cls = key_class(m.group("k"))
            if not cls:
                continue
            v, st, uq = _grp_value(m)
            if v is not None:
                if uq:
                    v = v.rstrip()
                yield from value_spans(cls, v, st, cfg, unquoted=uq, key=m.group("k"))
    for m in _BLOCK_RE.finditer(text):
        if key_class(m.group("k")) != V.SECRET:
            continue
        base = m.start("body")
        for lm in re.finditer(r"(?m)^[ \t]*(?P<l>\S[^\r\n]*?)[ \t]*\r?$", m.group("body")):
            line = lm.group("l")
            if not _contains_token(line) and not line.startswith("-----"):
                yield Span(base + lm.start("l"), base + lm.end("l"), V.SECRET)
    for m in _TF_SENS_RE.finditer(text):
        g = "v1" if m.group("v1") is not None else "v2"
        v = m.group(g)
        if v and not _contains_token(v):
            yield Span(m.start(g), m.end(g), V.SECRET)
    for m in _PGPASS_RE.finditer(text):
        h, u, pw = m.group("h"), m.group("u"), m.group("pw")
        if h != "*" and not _contains_token(h):
            cls = _classify_host(h.strip("[]"))
            if cls and h.lower() not in ("localhost",):
                yield Span(m.start("h"), m.end("h"), cls)
        if u != "*" and not _contains_token(u) and u not in cfg.allow_users:
            yield Span(m.start("u"), m.end("u"), V.USER)
        if not _contains_token(pw):
            yield Span(m.start("pw"), m.end("pw"), V.SECRET)
    for m in _DB_ERR_HOST_RE.finditer(text):
        h = m.group("h")
        if _host_ok(h, cfg) and not h.isdigit():
            try:
                ipaddress.ip_address(h)
                continue                        # IPs are handled by ip_addresses
            except ValueError:
                yield Span(m.start("h"), m.end("h"), V.HOST)
    for m in _DB_ERR_USER_RE.finditer(text):
        for g in ("u", "u2"):
            if m.group(g) and not _contains_token(m.group(g)) and m.group(g) not in cfg.allow_users:
                yield Span(m.start(g), m.end(g), V.USER)
        if m.group("h2") and _host_ok(m.group("h2"), cfg) and m.group("h2") != "%":
            cls = _classify_host(m.group("h2"))
            if cls:
                yield Span(m.start("h2"), m.end("h2"), cls)
    lines = list(_PEM_LINE_RE.finditer(text))
    for i, m in enumerate(lines):
        b = m.group("b")
        nb = lines[i + 1] if i + 1 < len(lines) else None
        pb = lines[i - 1] if i else None
        run = (nb is not None and text.count("\n", m.end(), nb.start()) <= 1) or \
              (pb is not None and text.count("\n", pb.end(), m.start()) <= 1)
        if (run or b.startswith(_PEM_KEY_PREFIXES)) and not _contains_token(b) \
                and re.search(r"[a-z]", b) and re.search(r"[A-Z]", b) and re.search(r"\d", b):
            yield Span(m.start("b"), m.end("b"), V.PRIVKEY)


# --------------------------------------------------------------------------
# 6. well-known token formats (no key needed)
# --------------------------------------------------------------------------
_KNOWN_TOKENS = [re.compile(p) for p in (
    r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b",          # AWS key ids
    r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b",                          # GitHub
    r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b",
    r"\bglpat-[A-Za-z0-9_\-]{20,}\b",                              # GitLab
    r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b",                         # Slack
    r"\bhttps://hooks\.slack\.com/services/[A-Za-z0-9/]+",
    r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b",            # Stripe
    r"\bAIza[0-9A-Za-z_\-]{35}\b",                                 # Google API key
    r"\bya29\.[0-9A-Za-z_\-]{20,}",                                # Google OAuth
    r"\bsk-(?:ant-|proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b",         # Anthropic/OpenAI
    r"\bnpm_[A-Za-z0-9]{36}\b",
    r"\bhf_[A-Za-z0-9]{30,}\b",
    r"\bSG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64}\b",       # SendGrid
    r"\bdop_v1_[a-f0-9]{64}\b",
    r"\bshpat_[a-fA-F0-9]{32}\b",
    r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",  # JWT
    r"\b(?:AccountKey|SharedAccessKey)=[A-Za-z0-9+/=]{20,}",
)]


def known_tokens(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    for rx in _KNOWN_TOKENS:
        for m in rx.finditer(text):
            s, e = m.start(), m.end()
            val = m.group(0)
            if "=" in val and val.split("=", 1)[0] in ("AccountKey", "SharedAccessKey"):
                s += val.index("=") + 1
            if not _contains_token(text[s:e]):
                yield Span(s, e, V.SECRET)


# --------------------------------------------------------------------------
# 7. emails, ssh-style user@host, home directories
# --------------------------------------------------------------------------
_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b")
_SSH_RE = re.compile(r"(?<![A-Za-z0-9._%+\-/:])(?P<u>[a-z_][a-z0-9_.\-]{0,31})@(?P<h>[A-Za-z0-9][A-Za-z0-9.\-]*)")
_HOME_RE = re.compile(r"(?:/home/|/Users/|[A-Za-z]:[\\/]Users[\\/]|/[a-z]/Users/|/mnt/[a-z]/Users/|"
                      r"/var/home/|\\\\Users\\\\)(?P<u>[^/\\\s'\"`:]+)", re.I)
# DOMAIN\user (whoami, event logs, `net user`, file ACLs)
_DOMAIN_USER_RE = re.compile(r"(?<![\w\\/.:-])(?P<d>[A-Za-z][A-Za-z0-9\-]{1,14})\\(?P<u>[A-Za-z][\w.\-$]{0,30}|\d{5,20})"
                             r"(?![\\/\w])")
_DOMAIN_SKIP = {"nt authority", "authority", "builtin", "nt service", "service", "window manager",
                "manager", "font driver host", "host", "iis apppool", "apppool",
                "nt virtual machine", "machine", "application package authority"}
_FILE_EXTS = {"py", "js", "ts", "tsx", "jsx", "mjs", "cjs", "json", "yaml", "yml", "md", "txt", "cs",
              "java", "kt", "go", "rs", "c", "h", "cpp", "hpp", "sql", "sh", "ps1", "psm1", "bat",
              "cmd", "exe", "dll", "log", "xml", "html", "htm", "css", "scss", "ini", "cfg", "conf",
              "toml", "lock", "csproj", "sln", "config", "env", "png", "jpg", "jpeg", "svg", "gif",
              "zip", "gz", "tar", "pdf", "docx", "xlsx", "vue", "rb", "php", "swift", "tf", "hcl",
              "props", "targets", "resx", "razor", "cshtml", "ipynb", "pyc", "so", "jar", "war"}
_BUILTIN_ACCOUNTS = {"system", "localsystem", "local service", "network service", "administrators",
                     "users", "everyone", "guests", "authenticated users", "trustedinstaller"}


def emails(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    for m in _EMAIL_RE.finditer(text):
        v = m.group(0)
        low = v.lower()
        if low in cfg.allow_emails or low.split("@", 1)[1] in cfg.allow_email_domains:
            continue
        if _contains_token(v):
            continue
        yield Span(m.start(), m.end(), V.EMAIL)


def ssh_users(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    for m in _SSH_RE.finditer(text):
        u = m.group("u")
        if u in cfg.allow_users or u in ("git",) or _contains_token(m.group(0)):
            continue
        h = m.group("h")
        if not (re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", h) or "." in h or h == "localhost"):
            continue  # npm scopes (@types/x), decorators etc.
        if _EMAIL_RE.fullmatch(m.group(0)):
            continue  # an email address: the email detector (and its allowlist) owns it
        yield Span(m.start("u"), m.end("u"), V.USER)


def home_dirs(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    for m in _DOMAIN_USER_RE.finditer(text):
        d, u = m.group("d"), m.group("u")
        if d.lower() in _DOMAIN_SKIP or u.lower() in _BUILTIN_ACCOUNTS or u in cfg.allow_users \
                or _contains_token(m.group(0)):
            continue
        if u.isdigit() and not (d.isupper() or "-" in d or any(c.isdigit() for c in d)):
            continue                                    # logs\20261123 is a folder, ACME\10000000146 a user
        ext = u.rsplit(".", 1)[-1].lower() if "." in u else ""
        if ext in _FILE_EXTS:                           # src\file.py - a relative path, not a user
            continue
        yield Span(m.start("u"), m.end("u"), V.USER)
    for m in _HOME_RE.finditer(text):
        u = m.group("u")
        if u in cfg.allow_users or u in ("runner", "shared", "Shared", "Public", "linuxbrew",
                                        "Default", "All Users", "desktop.ini") \
                or _contains_token(u) or u.startswith(("$", "~", "*", "<", "{")):
            continue
        yield Span(m.start("u"), m.end("u"), V.USER)


# --------------------------------------------------------------------------
# 8. IP addresses
# --------------------------------------------------------------------------
_IPV4_RE = re.compile(r"(?<![\d.A-Za-z_])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                      r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.]\d|\d)")
_IPV6_RE = re.compile(r"(?<![:\w.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![:\w])")
_IP_SKIP = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "1.1.1.1", "8.8.8.8", "8.8.4.4"}


def ip_addresses(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    for m in _IPV4_RE.finditer(text):
        v = m.group(0)
        if v in _IP_SKIP or v.startswith(("255.", "0.")) or v in cfg.allow_values:
            continue
        # version strings like `v1.2.3.4` / `1.2.3.4-beta`
        before = text[max(0, m.start() - 1):m.start()]
        if before in ("v", "V", "@", "=") and re.search(r"(?i)version|v$|==", text[max(0, m.start() - 12):m.start()]):
            continue
        cls = _classify_host(v)
        if cls:
            yield Span(m.start(), m.end(), cls)
    for m in _IPV6_RE.finditer(text):
        v = m.group(0)
        if v.count(":") < 2 or v in ("::", "::1"):
            continue
        try:
            ip = ipaddress.IPv6Address(v)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_unspecified:
            continue
        yield Span(m.start(), m.end(), V.IPV6)


# --------------------------------------------------------------------------
# 9. national IDs, IBAN, cards, phones
# --------------------------------------------------------------------------
_TCKN_RE = re.compile(r"(?<![\w.\-])[1-9]\d{10}(?![\d.]\d|\w)")
_IBAN_RE = re.compile(r"(?i)\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
_CARD_RE = re.compile(r"(?<![\w\-.])(?:\d[ \-.]?){12,18}\d(?![\w\-]|\.\d)")
# Turkish landlines: 0212 555 12 34, (0312) 555-12-34, +90 212 555 12 34 (area codes 2xx-4xx)
_PHONE_TR_LAND_RE = re.compile(r"(?<![\w+])(?:\+90[ \-]?|0090[ \-]?|0)\(?[234]\d{2}\)?[ \-.]\d{3}"
                               r"[ \-.]?\d{2}[ \-.]?\d{2}(?!\w)")
_PHONE_TR_RE = re.compile(r"(?<![\w+])(?:\+90|0090|0)?[ \-(]?5\d{2}[ \-)]?\s?\d{3}[ \-]?\d{2}[ \-]?\d{2}(?!\w)")
_PHONE_INTL_RE = re.compile(r"(?<![\w+])\+[1-9]\d{0,2}[ \-]?(?:\(?\d{1,4}\)?[ \-]?){2,5}\d{2,4}(?!\w)")


def tckn_valid(s: str) -> bool:
    d = [int(c) for c in s]
    if len(d) != 11 or d[0] == 0:
        return False
    if ((sum(d[0:9:2]) * 7) - sum(d[1:8:2])) % 10 != d[9]:
        return False
    return sum(d[:10]) % 10 == d[10]


def iban_valid(s: str) -> bool:
    s = s.replace(" ", "")
    if not (15 <= len(s) <= 34):
        return False
    r = s[4:] + s[:4]
    num = "".join(str(int(c, 36)) for c in r)
    return int(num) % 97 == 1


def luhn_valid(s: str) -> bool:
    digits = [int(c) for c in s if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, dgt in enumerate(reversed(digits)):
        if i % 2:
            dgt *= 2
            if dgt > 9:
                dgt -= 9
        total += dgt
    return total % 10 == 0


def ids_and_numbers(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    if cfg.turkish_ids:
        for m in _TCKN_RE.finditer(text):
            if tckn_valid(m.group(0)):
                yield Span(m.start(), m.end(), V.TCKN)
    for m in _IBAN_RE.finditer(text):
        if iban_valid(m.group(0).upper()):
            yield Span(m.start(), m.end(), V.IBAN)
    if cfg.cards:
        for m in _CARD_RE.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if luhn_valid(digits) and re.match(r"(?:4|5[1-5]|2[2-7]|3[47]|3(?:0[0-5]|[68])|6(?:011|5))", digits):
                # avoid timestamps / ids: require separators, 15-16 digits, or a Diners 14
                if len(digits) in (15, 16) or (len(digits) == 14 and digits[:2] in ("30", "36", "38")) \
                        or re.search(r"[ \-.]", m.group(0)):
                    yield Span(m.start(), m.end(), V.CARD)
    if cfg.phones:
        for m in _PHONE_TR_RE.finditer(text):
            yield Span(m.start(), m.end(), V.PHONE)
        for m in _PHONE_TR_LAND_RE.finditer(text):
            yield Span(m.start(), m.end(), V.PHONE)
        for m in _PHONE_INTL_RE.finditer(text):
            if len(re.sub(r"\D", "", m.group(0))) >= 9:
                yield Span(m.start(), m.end(), V.PHONE)


# --------------------------------------------------------------------------
# 10. internal hostnames, names list, custom regexes
# --------------------------------------------------------------------------
def internal_hosts(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    if not cfg.internal_domains:
        return
    doms = sorted({d.strip().lstrip("*").lstrip(".").lower() for d in cfg.internal_domains if d.strip(" .*")},
                  key=len, reverse=True)
    suffixes = "|".join(re.escape(d) for d in doms)
    # the bare domain too (acme.com.tr itself), but not a bare TLD like "tr" or "internal"
    apex = "|".join(re.escape(d) for d in doms if "." in d)
    rx = re.compile(r"(?<![A-Za-z0-9\-_.])(?:(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+(?:"
                    + suffixes + r")" + (r"|(?:" + apex + r")" if apex else "") + r")(?![A-Za-z0-9\-_])", re.I)
    for m in rx.finditer(text):
        h = m.group(0)
        if _contains_token(h) or (h.split(".")[0] in _CODE_ROOTS and h.count(".") == 1):
            continue                            # self.local, cfg.internal: code, not a host
        yield Span(m.start(), m.end(), V.HOST)


def names_list(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    if not cfg.names:
        return
    alt = "|".join(re.escape(n) for n in sorted(cfg.names, key=len, reverse=True) if n.strip())
    rx = re.compile(r"(?<![\w])(?:" + alt + r")(?![\w])", re.I | re.UNICODE)
    for m in rx.finditer(text):
        yield Span(m.start(), m.end(), V.PERSON)


def custom_patterns(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    for rx, cls in cfg.custom:
        for m in rx.finditer(text):
            g = "value" if "value" in rx.groupindex else 0
            if m.group(g) and not _contains_token(m.group(g)):
                yield Span(m.start(g), m.end(g), cls)


# --------------------------------------------------------------------------
# 11. high-entropy strings (last resort)
# --------------------------------------------------------------------------
_ENTROPY_RE = re.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/_\-]{32,}={0,2}(?![A-Za-z0-9+/=_\-])")


def high_entropy(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    if not cfg.entropy:
        return
    for m in _ENTROPY_RE.finditer(text):
        v = m.group(0)
        if len(v) < cfg.entropy_min_len or _contains_token(v):
            continue
        if re.fullmatch(r"[0-9a-fA-F]+", v):          # git SHAs, sha256 digests
            continue
        if re.match(r"sha(?:1|256|384|512)-", v):       # SRI integrity hashes
            continue
        if re.search(r"(?:sha(?:1|256|384|512)-|integrity|sum)\s*[\"':=]*\s*$", text[max(0, m.start() - 16):m.start()]):
            continue
        if "/" in v and re.fullmatch(r"[A-Za-z0-9_\-./]+", v) and v.count("/") >= 2:
            continue                                    # paths
        if not (re.search(r"[a-z]", v) and re.search(r"[A-Z]", v) and re.search(r"\d", v)):
            continue
        if re.fullmatch(r"(?:[A-Za-z][a-z]+[_\-]?){4,}\d*", v):  # camelCase identifiers
            continue
        if shannon(v) >= cfg.entropy_threshold:
            yield Span(m.start(), m.end(), V.SECRET)


# --------------------------------------------------------------------------
# 12. secrets written in prose / Turkish, .netrc
# --------------------------------------------------------------------------
_PROSE_WORDS = {"required", "incorrect", "invalid", "wrong", "missing", "empty", "set", "not", "the",
                "a", "an", "too", "still", "expired", "valid", "correct", "stored", "saved", "hashed",
                "encrypted", "needed", "optional", "changed", "reset", "weak", "strong", "short",
                "long", "unknown", "same", "different", "in", "on", "at", "for", "from", "now",
                "yanlış", "yanlis", "gerekli", "boş", "bos", "hatalı", "hatali", "geçersiz", "gecersiz"}
_PROSE_RE = re.compile(
    r"(?i)(?<![\w])(?P<k>password|passwd|passphrase|secret|token|api[ _\-]?key|"
    r"ş?s?ifre(?:si|m|niz)?|parola(?:sı|si|m|nız|niz)?|gizli anahtar(?:ı|i)?)"
    r"(?:\s*[:=]\s*|\s+(?:is|was|=|olarak|şu|su)\s+(?:[:=]\s*)?)[`\"'“‘]?(?P<v>[^\s`\"'”’,;]{4,128})")
_TR_POSSESSIVE_RE = re.compile(
    r"(?i)(?<![\w])(?:ş|s)ifresi|parolası|parolasi")
_NETRC_RE = re.compile(r"(?m)\b(?P<k>login|password|account)\s+(?P<v>\S+)")


def prose_secrets(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    for m in _PROSE_RE.finditer(text):
        v = m.group("v").rstrip(".!?:)")
        if not v or v.lower() in _PROSE_WORDS or _contains_token(v) or _is_reference_or_literal(v):
            continue
        if is_code_identifier(v, m.group("k")) and text[m.start("v") - 1:m.start("v")] not in "\"'`":
            continue
        yield Span(m.start("v"), m.start("v") + len(v), V.SECRET)
    # Turkish possessive without a connector: "veritabanı şifresi Abc!23"
    for m in _TR_POSSESSIVE_RE.finditer(text):
        m2 = re.match(r"\s+[`\"']?(?P<v>[^\s`\"',;]{4,128})", text[m.end():])
        if m2:
            v = m2.group("v").rstrip(".!?:)")
            if re.search(r"[\d\W_]", v) and v.lower() not in _PROSE_WORDS and not _contains_token(v):
                st = m.end() + m2.start("v")
                yield Span(st, st + len(v), V.SECRET)
    if re.search(r"(?m)^\s*(?:machine|default)\s+\S+", text):
        for m in _NETRC_RE.finditer(text):
            v = m.group("v")
            if not _contains_token(v):
                yield Span(m.start("v"), m.end("v"), V.USER if m.group("k") == "login" else V.SECRET)


# --------------------------------------------------------------------------
# 13. git identities: authors, committers, trailers, blame, shortlog, config
# --------------------------------------------------------------------------
_GIT_TRAILER_RE = re.compile(
    r"(?im)^[ \t]*(?:author|commit|committer|tagger|co-authored-by|signed-off-by|reviewed-by|"
    r"acked-by|tested-by|reported-by|suggested-by|helped-by|cc|from|reported-and-tested-by)"
    r"\s*:\s*(?P<name>[^<>\n]+?)\s*<[^<>\n]*>")
_NAME_EMAIL_RE = re.compile(
    r"(?<![\w'.\-])(?P<name>[^\W\d_][\w'.\-]{0,40}(?:[ \t]+[^\W\d_][\w'.\-]{0,40}){0,4})[ \t]*"
    r"<[^<>\s@]{1,64}@[^<>\s]{1,255}>")
_BLAME_RE = re.compile(
    r"(?m)^\^?[0-9a-f]{7,40}\s+(?:[^\s(]+\s+)?\((?P<name>.+?)\s+\d{4}-\d{2}-\d{2}\s+"
    r"\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\s+\d+\)")
_BLAME_PORCELAIN_RE = re.compile(r"(?m)^(?:author|committer) (?P<name>[^\r\n]+?)\r?$")
_SHORTLOG_RE = re.compile(r"(?m)^[ \t]*\d+\t(?P<name>[^\t\r\n<]+?)(?:[ \t]+<[^>\r\n]+>)?[ \t]*\r?$")
_GITCONFIG_USER_RE = re.compile(r"(?ms)^\[user\][ \t]*$(?P<body>.*?)(?=^\[|\Z)")
_GITCONFIG_NAME_RE = re.compile(r"(?m)^[ \t]*name[ \t]*=[ \t]*(?P<name>[^\r\n]+?)[ \t]*\r?$")
_KEYED_NAME_RE = re.compile(
    r"(?im)(?:\b(?:user|author|committer)\.name|\bGIT_(?:AUTHOR|COMMITTER)_NAME)[ \t]*[=:][ \t]*"
    r"[\"']?(?P<name>[^\"'\r\n]+?)[\"']?[ \t]*\r?$")
_JSON_AUTHOR_RE = re.compile(
    r"\"(?:author|maintainer|contributor|owner)\"\s*:\s*\"(?P<name>[^\"<\n]+?)\s*(?:<[^\"]*>)?\s*\"", re.I)
_TOML_AUTHOR_RE = re.compile(r"\{\s*name\s*=\s*\"(?P<name>[^\"]+)\"\s*,\s*email\s*=", re.I)


_PERSONISH = re.compile(r"[^\W\d_][\w'.\-]*(?: [^\W\d_][\w'.\-]*){0,4}")


def _shortlog(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    """`git shortlog -sn` output only: every line is `<spaces><count>\t<Name>`, and the
    counts are not 1,2,3,... (which would be line numbers from a file read)."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines or len(lines) > 5000:
        return
    ms = [_SHORTLOG_RE.match(ln) for ln in lines]
    if not all(ms):
        return
    counts = [int(ln.split("\t", 1)[0]) for ln in lines]
    if len(counts) == 1 and counts[0] == 1:
        return
    if all(b == a + 1 for a, b in zip(counts, counts[1:])):
        return
    if not all(_PERSONISH.fullmatch(m.group("name").strip()) for m in ms):
        return
    for m in _SHORTLOG_RE.finditer(text):
        if _name_ok(m.group("name"), cfg):
            yield Span(m.start("name"), m.end("name"), V.PERSON)


def _name_ok(n: str, cfg: DetectorConfig) -> bool:
    n = n.strip()
    if not n or len(n) < 2 or _contains_token(n) or n in cfg.allow_names:
        return False
    if n.startswith("Claude ") or "[bot]" in n or n.lower().endswith(" bot"):
        return False
    if "@" in n or re.fullmatch(r"[\d\W]+", n):
        return False
    return True


def git_identities(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    if not cfg.git_identities:
        return
    for rx in (_GIT_TRAILER_RE, _NAME_EMAIL_RE, _BLAME_RE, _KEYED_NAME_RE, _JSON_AUTHOR_RE,
               _TOML_AUTHOR_RE):
        for m in rx.finditer(text):
            n = m.group("name")
            if _name_ok(n, cfg):
                lead = len(n) - len(n.lstrip())
                yield Span(m.start("name") + lead, m.start("name") + len(n.rstrip()), V.PERSON)
    if "author-mail" in text:
        for m in _BLAME_PORCELAIN_RE.finditer(text):
            if _name_ok(m.group("name"), cfg):
                yield Span(m.start("name"), m.end("name"), V.PERSON)
    yield from _shortlog(text, cfg)
    for um in _GITCONFIG_USER_RE.finditer(text):
        base = um.start("body")
        for m in _GITCONFIG_NAME_RE.finditer(um.group("body")):
            if _name_ok(m.group("name"), cfg):
                yield Span(base + m.start("name"), base + m.end("name"), V.PERSON)


# --------------------------------------------------------------------------
# 14. Turkish IDs with a label (always) and VKN (checksum)
# --------------------------------------------------------------------------
_ID_KEYED_RE = re.compile(
    r"(?i)(?<![\w])(?P<k>vkn|vergi[ _.\-]?(?:kimlik[ _.\-]?)?(?:no|numaras[ıi]|number)|vergi[ _.\-]?no|"
    r"tax[ _.\-]?(?:id|no|number)|tckn|tc[ _.\-]?(?:kimlik)?[ _.\-]?(?:no|numaras[ıi])?|"
    r"kimlik(?:[ _.\-]?(?:no|numaras[ıi]))?|national[ _.\-]?id)[\"']?\s*[:=]?\s*[\"']?(?P<v>\d{10,11})(?!\d)")
_ID_KEYED_SEP_RE = re.compile(
    r"(?i)(?<![\w])(?:vkn|vergi[ _.\-]?(?:no|numaras[ıi])|tckn|tc[ _.\-]?(?:kimlik)?[ _.\-]?(?:no)?|"
    r"kimlik(?:[ _.\-]?(?:no|numaras[ıi]))?)[\"']?\s*[:=]?\s*[\"']?(?P<v>\d(?:[ \-.]?\d){9,10})(?![\d\-.]\d)")
_VKN_RE = re.compile(r"(?<![\w.\-])\d{10}(?![\d.]\d|\w)")


def vkn_valid(s: str) -> bool:
    if len(s) != 10 or not s.isdigit():
        return False
    d = [int(c) for c in s]
    total = 0
    for i in range(9):
        tmp = (d[i] + (9 - i)) % 10
        val = (tmp * (2 ** (9 - i))) % 9
        if tmp != 0 and val == 0:
            val = 9
        total += val
    return (10 - total % 10) % 10 == d[9]


def turkish_ids(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    if not cfg.turkish_ids:
        return
    for m in _ID_KEYED_RE.finditer(text):
        v = m.group("v")
        yield Span(m.start("v"), m.end("v"), V.VKN if len(v) == 10 else V.TCKN)
    for m in _ID_KEYED_SEP_RE.finditer(text):        # TC 100 000 001 46, kimlik 100-000-001-46
        d = re.sub(r"\D", "", m.group("v"))
        if (len(d) == 11 and tckn_valid(d)) or (len(d) == 10 and vkn_valid(d)):
            yield Span(m.start("v"), m.end("v"), V.TCKN if len(d) == 11 else V.VKN)
    if cfg.vkn_unkeyed:
        for m in _VKN_RE.finditer(text):
            v = m.group(0)
            n = int(v)
            if 1_000_000_000 <= n <= 2_200_000_000:
                continue        # looks like a Unix timestamp; labelled VKNs are still caught
            if v.startswith("5"):
                continue        # Turkish mobile number without the leading 0 (phone detector)
            if vkn_valid(v):
                yield Span(m.start(), m.end(), V.VKN)


# --------------------------------------------------------------------------
# 15. Gitleaks community rules (~220 provider token formats)
# --------------------------------------------------------------------------
def gitleaks_rules(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    if not cfg.gitleaks:
        return
    from .gitleaks import load
    rules, global_allows, _ = load(cfg.gitleaks_rules)
    low = text.lower()
    for rule in rules:
        if rule.keywords and not any(k in low for k in rule.keywords):
            continue
        for m in rule.rx.finditer(text):
            g = rule.secret_group
            if g is None:
                g = next((i for i in range(1, (m.lastindex or 0) + 1) if m.group(i)), 0)
            secret = m.group(g) if g <= (m.lastindex or 0) else m.group(0)
            if not secret or _contains_token(secret) or _is_reference_or_literal(secret):
                continue
            if rule.entropy and shannon(secret) < rule.entropy:
                continue
            ls = text.rfind("\n", 0, m.start()) + 1
            le = text.find("\n", m.end())
            line = text[ls:le if le != -1 else len(text)]
            if any(a.hit(secret, m.group(0), line) for a in rule.allows + global_allows):
                continue
            start = m.start(g) if g else m.start()
            yield Span(start, start + len(secret), V.SECRET)


# Order matters: specific before generic.
def own_usernames(text: str, cfg: DetectorConfig) -> Iterable[Span]:
    names = [n for n in cfg.own_usernames if n and len(n) >= 3]
    if not names:
        return
    rx = re.compile(r"(?<![\w.\-])(?:" + "|".join(re.escape(n) for n in sorted(names, key=len, reverse=True))
                    + r")(?![\w\-]|\.\w)", re.I)
    for m in rx.finditer(text):
        if not _contains_token(text[max(0, m.start() - 24):m.end()]):
            yield Span(m.start(), m.end(), V.USER)


PIPELINE: list[Detector] = [
    privkey,
    uri_credentials,
    auth_headers,
    k8s_secrets,
    own_usernames,
    git_identities,
    keyed_values,
    structured_pairs,
    prose_secrets,
    known_tokens,
    gitleaks_rules,
    turkish_ids,
    emails,
    ssh_users,
    home_dirs,
    ip_addresses,
    ids_and_numbers,
    internal_hosts,
    names_list,
    custom_patterns,
    high_entropy,
]
