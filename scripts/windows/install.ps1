<#
.SYNOPSIS
  Install redact-guard on Windows. Run in an ELEVATED PowerShell (default, isolated install).

.DESCRIPTION
  Default (isolated, recommended):
    - redact-guard runs as SYSTEM (Scheduled Task at startup). Its vault, key, local CA private
      key, logs and config live in C:\ProgramData\redact-guard\state, readable only by SYSTEM
      and Administrators. Claude Code runs as you, un-elevated, so nothing it runs (Bash,
      PowerShell, a script it wrote) can read the key and decrypt the vault.
    - The install folder ($Root) is made read-only for Users, so Claude can't edit the hooks
      or the config to switch redaction off for the next session.
    - Only the public CA certificate is exported, to C:\ProgramData\redact-guard\public\ca.pem.
    - Your existing proxy is detected NOW (as you) and written into the config, because the
      SYSTEM account doesn't see your user proxy settings.
    Never run Claude Code itself in an elevated ("Run as administrator") terminal: an elevated
    process can read the state folder.

  -NoLock: don't make the install folder read-only for Users (use if your endpoint protection
    blocks Python after the ACL change; protect the folder another way).

  -PerUser: the old per-user install (task runs as you, state in your profile). Weaker: any
    process running as you, including Claude's shell, can read the key.

  -Mode proxy (default): HTTPS proxy on 127.0.0.1:8788, Remote Control keeps working.
  -Mode gateway: ANTHROPIC_BASE_URL gateway on 127.0.0.1:8787, no Remote Control.
  -ApplySettings: merge the Windows Claude Code settings into %USERPROFILE%\.claude\settings.json
    (backup first) and add the placeholder note to %USERPROFILE%\.claude\CLAUDE.md.
    For the strongest setup, also install them as managed settings (see README).

.EXAMPLE
  # elevated PowerShell
  cd C:\redact-guard
  powershell -ExecutionPolicy Bypass -File scripts\windows\install.ps1 -ApplySettings
#>
param(
  [ValidateSet("proxy", "gateway")][string]$Mode = "proxy",
  [switch]$ApplySettings,
  [switch]$NoTask,
  [switch]$PerUser,
  [switch]$NoLock,
  [string]$Python = "py"
)
$ErrorActionPreference = "Stop"
Write-Host "redact-guard installer 2026-11-24x"
$Root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
Write-Host "redact-guard root: $Root"
if ($Root -match '\s') {
  Write-Warning "The path contains spaces. It works, but C:\redact-guard is simpler for hooks."
}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $PerUser -and -not $isAdmin) {
  throw "The isolated install needs an elevated PowerShell (Run as administrator). Use -PerUser for the weaker per-user install."
}

# 1. venv + deps + tests
if (-not (Test-Path "$Root\.venv\Scripts\python.exe")) {
  if ($Python -eq "py") { & py -3 -m venv "$Root\.venv" } else { & $Python -m venv "$Root\.venv" }
}
$Py  = "$Root\.venv\Scripts\python.exe"
$PyW = "$Root\.venv\Scripts\pythonw.exe"
& $Py -m pip install --upgrade pip | Out-Null
& $Py -m pip install -r "$Root\requirements-dev.txt"
# make `python -m redact_guard` work from any folder (doctor runs in your project)
$site = & $Py -c "import sysconfig; print(sysconfig.get_paths()['purelib'])"
Set-Content -Path (Join-Path $site "redact_guard_root.pth") -Value $Root -Encoding ascii
& $Py -m pytest -q -p no:cacheprovider "$Root\tests"
if ($LASTEXITCODE -ne 0) { throw "tests failed - not installing the task" }

# The hooks run with the Python launcher (py -3 -I -S), independent of the venv.
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
  Write-Warning "The Python launcher 'py' is not on PATH. Re-run render_settings.py with --python <full path to python.exe>."
}
$cmd = if ($Mode -eq "proxy") { "proxy" } else { "serve" }

# Protect a folder by setting ITS ACL only and making everything inside inherit it. (Setting ACLs
# on every file with /T can leave single files with no access at all, e.g. a leftover config
# or python.exe, which then fails with "Access denied" even for administrators.)
function Test-Readable([string]$Item) {
  $ErrorActionPreference = "Continue"
  try {
    if ([IO.Directory]::Exists($Item)) { [void][IO.Directory]::EnumerateFileSystemEntries($Item).GetEnumerator().MoveNext() }
    else { [IO.File]::Open($Item, 'Open', 'Read', 'ReadWrite').Close() }
    return $true
  } catch { return $false }
}
function Set-FolderAcl([string]$Path, [string[]]$Grants) {
  # Windows PowerShell 5.1 turns a native command's stderr into errors; with the script-wide
  # "Stop" that aborts on the first expected "access denied". Native output is just information here.
  $ErrorActionPreference = "Continue"
  & icacls $Path /inheritance:r /grant:r @Grants /Q 2>&1 | Out-Null
  # one bulk pass: everything inside inherits the folder's ACL (fast, even for a venv)
  & icacls (Join-Path $Path "*") /reset /T /C /Q 2>&1 | Out-Null
  # then fix only what is still unreadable (e.g. a key an earlier build left owned by SYSTEM and
  # granted to nobody): take it over for Administrators, reset it. Second pass reaches the
  # contents of folders that couldn't be listed before.
  for ($pass = 0; $pass -lt 2; $pass++) {
    $bad = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
             Where-Object { -not (Test-Readable $_.FullName) } | ForEach-Object { $_.FullName })
    if ($bad.Count -eq 0) { break }
    foreach ($item in $bad) {
      & takeown /F $item /A 2>&1 | Out-Null
      & icacls $item /reset /C /Q 2>&1 | Out-Null
      if (-not (Test-Readable $item)) { Write-Warning "could not repair permissions on $item" }
    }
  }
}

# Replace a file that an earlier run may have left without any permissions: delete it, and if
# that is refused, take ownership for Administrators (allowed for admins), reset it, delete it.
function Remove-Leftover([string]$File) {
  $ErrorActionPreference = "Continue"
  if (-not (Test-Path -LiteralPath $File)) { return }
  try { Remove-Item -LiteralPath $File -Force -ErrorAction Stop; return } catch {}
  & takeown /F $File /A | Out-Null
  & icacls $File /reset /C /Q | Out-Null
  Remove-Item -LiteralPath $File -Force -ErrorAction Stop
}
$GrantAdmin = @("*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
$GrantRead  = $GrantAdmin + @("*S-1-5-32-545:(OI)(CI)RX")

if ($PerUser) {
  $Config = "$Root\config\redact-guard.yaml"
  $log = Join-Path $env:LOCALAPPDATA "redact-guard\$Mode.log"
  New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
  if ($Mode -eq "proxy") { & $Py -m redact_guard proxy --init -c $Config | Out-Null }
  $ca = (Join-Path $env:USERPROFILE ".local\share\redact-guard\mitm\mitmproxy-ca-cert.pem")
  $Exe = $PyW
  $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive
  $trigger   = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
} else {
  $Data   = Join-Path $env:ProgramData "redact-guard"
  $State  = Join-Path $Data "state"
  $Public = Join-Path $Data "public"
  New-Item -ItemType Directory -Force -Path $State, $Public | Out-Null
  $Config = Join-Path $State "redact-guard.yaml"
  $log    = Join-Path $State "$Mode.log"

  # Re-run after a partial install: make sure Administrators (this session) can still write
  # the state folder, then probe whether *Python* may write there. If PowerShell can and
  # Python can't, endpoint protection is blocking python.exe; say so instead of half-installing.
  Set-FolderAcl $State $GrantAdmin       # also repairs files a previous run left inaccessible
  Set-FolderAcl $Public $GrantRead
  $probe = Join-Path $State "write-probe.txt"
  $psOk = $true; try { Set-Content -Path $probe -Value "ps" -ErrorAction Stop } catch { $psOk = $false }
  $ErrorActionPreference = "Continue"
  & $Py -c "import sys; open(sys.argv[1], 'w').write('py')" $probe 2>$null
  $pyOk = ($LASTEXITCODE -eq 0)
  $ErrorActionPreference = "Stop"
  Remove-Item $probe -ErrorAction SilentlyContinue
  if (-not $pyOk) {
    if ($psOk) {
      throw ("PowerShell can write $State but $Py can't. Your endpoint protection (e.g. Trend Micro " +
             "Behavior Monitoring) is blocking this python.exe. Ask IT for an exclusion for " +
             "$Py and $State, then re-run. See README: Windows 'Access denied'.")
    }
    throw "Even PowerShell (elevated) can't write $State. Check: icacls $State ; whoami /groups"
  }

  # Detect the existing proxy as YOU (SYSTEM can't see your HKCU / environment).
  $corp = & $Py -c "from redact_guard import upstream as U; up,_=U.detect('auto', {('127.0.0.1',8788),('127.0.0.1',8787)}); print(up.url or 'none')"
  Write-Host "existing proxy detected: $corp"
  if ($env:CORP_PROXY_AUTH) { Write-Warning "CORP_PROXY_AUTH is a user variable; SYSTEM won't see it. Set it as a machine variable for the task." }

  # Config: your config\redact-guard.yaml with the state paths and the proxy pinned.
  $stateFwd = $State -replace "\\", "/"
  $tmpCfg = Join-Path $env:TEMP "redact-guard.yaml"
  & $Py -c @"
import sys, yaml
src, dst, state, corp, me, public = sys.argv[1:7]
c = yaml.safe_load(open(src, encoding='utf-8')) or {}
det = c.setdefault('detectors', {}) or {}
c['detectors'] = det
own = list(det.get('own_usernames') or [])
if me and me not in own:
    own.append(me)              # the SYSTEM service can't know who you are
det['own_usernames'] = own
c.setdefault('vault', {})
c['vault']['dir'] = state
c['vault']['key_file'] = state + '/key'
c['audit_log'] = state + '/audit.jsonl'
c['hook_secret_file'] = public + '/hook-secret'   # where the prompt hook (running as you) looks
c.setdefault('proxy', {})['confdir'] = state + '/mitm'
cp = c.setdefault('corporate_proxy', {})
if str(cp.get('url', 'auto')) == 'auto':
    cp['url'] = corp
yaml.safe_dump(c, open(dst, 'w', encoding='utf-8'), sort_keys=False, allow_unicode=True)
"@ "$Root\config\redact-guard.yaml" $tmpCfg $stateFwd $corp $env:USERNAME ($Public -replace "\\", "/")
  if ($LASTEXITCODE -ne 0) { throw "could not build the config from $Root\config\redact-guard.yaml" }
  Remove-Leftover $Config                 # a leftover file may have a broken ACL
  Copy-Item -Force $tmpCfg $Config        # PowerShell does the write into the protected folder
  Remove-Item $tmpCfg -ErrorAction SilentlyContinue

  # hook secret: readable by you (the prompt hook), written once here
  $secretFile = Join-Path $Public "hook-secret"
  if (-not (Test-Path $secretFile) -or -not (Get-Content $secretFile -ErrorAction SilentlyContinue)) {
    Remove-Leftover $secretFile
    $bytes = New-Object byte[] 32
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    Set-Content -Path $secretFile -Value (($bytes | ForEach-Object { $_.ToString("x2") }) -join "") -Encoding ascii
  }

  if ($Mode -eq "proxy") {
    & $Py -m redact_guard proxy --init -c $Config | Out-Null
    Remove-Leftover (Join-Path $Public "ca.pem")
    Copy-Item -Force (Join-Path $State "mitm\mitmproxy-ca-cert.pem") (Join-Path $Public "ca.pem")
  }
  # state: SYSTEM + Administrators only. public: readable by Users.
  Set-FolderAcl $State $GrantAdmin
  Set-FolderAcl $Public $GrantRead
  $ca = Join-Path $Public "ca.pem"
  $Exe = $Py
  $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
  $trigger   = New-ScheduledTaskTrigger -AtStartup
}

# 2. the task
if (-not $NoTask) {
  $action   = New-ScheduledTaskAction -Execute $Exe `
                -Argument "-E -m redact_guard $cmd -c `"$Config`" --log-file `"$log`"" `
                -WorkingDirectory $Root
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
                -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
  # Stop the old service first: the task ignores a start while an instance is still running,
  # so without this the previous version would keep serving.
  Stop-ScheduledTask -TaskName "redact-guard" -ErrorAction SilentlyContinue
  Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match "-m\s+redact_guard\s+(proxy|serve)\b" } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 2
  Register-ScheduledTask -TaskName "redact-guard" -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description "redact-guard for Claude Code" -Force | Out-Null
  Start-ScheduledTask -TaskName "redact-guard"
  # first start can take a while (loading ~220 rules, building the CA bundle, endpoint scanning)
  $h = $null
  for ($i = 0; $i -lt 30 -and -not $h; $i++) {
    Start-Sleep -Seconds 2
    try {
      if ($Mode -eq "proxy") {
        $h = Invoke-RestMethod -Uri "http://redact-guard.invalid/healthz" -Proxy "http://127.0.0.1:8788" -TimeoutSec 5
      } else {
        $h = Invoke-RestMethod -Uri "http://127.0.0.1:8787/healthz" -TimeoutSec 5
      }
    } catch { $h = $null }
  }
  $want = (& $Py -c "import redact_guard; print(redact_guard.__version__)").Trim()
  if ($h -and $h.version -ne $want) {
    Write-Warning "redact-guard answered, but as version '$($h.version)' instead of '$want': an old process is still running."
    $h = $null
  }
  try {
    if (-not $h) { throw "no answer after 60 s" }
    Write-Host "redact-guard healthy: $($h | ConvertTo-Json -Compress)"
  } catch {
    Write-Warning "redact-guard is not answering. Last lines of $log :"
    if (Test-Path $log) { Get-Content $log -Tail 25 | ForEach-Object { Write-Host "    $_" } }
    else { Write-Host "    (no log yet: the task may not have started; see Task Scheduler > redact-guard > History)" }
    $t = Get-ScheduledTaskInfo -TaskName "redact-guard" -ErrorAction SilentlyContinue
    if ($t) { Write-Host "    task last result: 0x$('{0:X}' -f $t.LastTaskResult)" }
  }
}

# 3. Claude Code settings
$caFwd = $ca -replace "\\", "/"
$renderArgs = @("$Root\scripts\render_settings.py", "--platform", "windows", "--mode", $Mode, "--ca", $caFwd,
                "--guard-root", $Root)
if ($ApplySettings) {
  & $Py @renderArgs --apply
} else {
  Write-Host "Next (as you, not elevated):  & `"$Py`" $($renderArgs -join ' ') --apply"
}
# 4. lock the install folder LAST: Users may read and run, not write (protects hooks/guard.py,
#    the code and the venv from edits). Verified afterwards; rolled back if Python stops starting
#    (some endpoint-protection products react to ACL changes on executables).
function Test-Py { $ErrorActionPreference = "Continue"; try { $o = & $Py -c "print('ok')" 2>&1; return ($LASTEXITCODE -eq 0 -and "$o" -match "ok") } catch { return $false } }
if (-not $PerUser -and -not $NoLock) {
  $acl = Join-Path $env:TEMP "redact-guard-acl-backup.txt"
  & icacls $Root /save $acl /T /Q | Out-Null
  Set-FolderAcl $Root $GrantRead
  if (Test-Py) {
    Write-Host "install folder locked: Users can read and run it, not change it."
  } else {
    Write-Warning "Python stopped starting after locking $Root (Access denied). Restoring the previous permissions."
    & icacls (Split-Path $Root) /restore $acl /Q | Out-Null
    if (-not (Test-Py)) { & icacls $Root /reset /T /Q | Out-Null }
    if (Test-Py) { Write-Warning "Restored. The folder is NOT locked; see the README (Windows: 'Access denied')." }
    else { Write-Warning "Python still can't start. This is not the ACL: check your endpoint protection (Trend Micro) logs." }
  }
}

Write-Host ""
Write-Host "Check everything (as you, NOT elevated):  & `"$Py`" -m redact_guard doctor -c `"$Root\config\redact-guard.yaml`""
Write-Host ""
Write-Host "Then, after installing Claude Code, elevated, put a network boundary around it:"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$Root\scripts\windows\firewall-block-db.ps1`" -BlockClaudeDirect -RegisterRefreshTask"
Write-Host "  (add -Strict -ProxyPorts <port> only on a VM that is NOT domain-joined: -Strict also blocks"
Write-Host "   Kerberos/LDAP/SMB, so domain logon, group policy and file shares stop working)"
