<#
.SYNOPSIS
  Windows Firewall layer for redact-guard: block outbound database traffic from this VM.

.DESCRIPTION
  Native Windows has no Claude Code Bash sandbox, so this replaces its network layer.
  Rules apply to every program on the VM (Windows Firewall can't scope rules to
  "whatever Claude Code spawns"), so use it on a VM dedicated to this work.

  Default: block outbound TCP/UDP to common database ports.
  -Strict: NOT for domain-joined (company) machines - it also blocks Kerberos, LDAP and SMB, so
           domain logon, group policy, file shares and agents that report to a server break.
           Additionally sets the default outbound action to Block and allows only
           DNS, NTP, HTTP and HTTPS (plus -ProxyPorts, e.g. 8080,3128, if your existing
           corporate proxy listens on a non-standard port). Database protocols, SSH and SMB then can't leave
           the VM at all. Inbound RDP is unaffected.
  -BlockClaudeDirect: block every Claude Code binary (claude.exe) from reaching anything but
           loopback, so in proxy mode it can only talk to redact-guard. Re-run after
           Claude Code updates (or use -RegisterRefreshTask).
  -RegisterRefreshTask: with -BlockClaudeDirect, also re-apply it at every logon (elevated task).
  -Remove: delete all redact-guard rules (and with -Strict, restore Allow as the default).

  Note: Windows Firewall does not filter loopback. Don't run a database inside the VM.

.EXAMPLE
  # elevated PowerShell
  powershell -ExecutionPolicy Bypass -File scripts\windows\firewall-block-db.ps1
  powershell -ExecutionPolicy Bypass -File scripts\windows\firewall-block-db.ps1 -Strict
  powershell -ExecutionPolicy Bypass -File scripts\windows\firewall-block-db.ps1 -Remove -Strict
#>
param([switch]$Strict, [switch]$Remove, [switch]$BlockClaudeDirect, [switch]$RegisterRefreshTask,
      [switch]$OnlyClaude, [string]$UserProfile = $env:USERPROFILE, [int[]]$ExtraTcpPorts = @(),
      [int[]]$ProxyPorts = @())
$ErrorActionPreference = "Stop"
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this from an elevated (Administrator) PowerShell."
}
$Group = "redact-guard"
$ClaudeGroup = "redact-guard-claude"

function Set-ClaudeDirectBlock {
  # Windows Firewall does not filter loopback, so blocking all outbound traffic for
  # claude.exe still lets it reach the local redact-guard proxy - and nothing else.
  Get-NetFirewallRule -Group $ClaudeGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  $paths = @()
  $cmd = Get-Command claude -ErrorAction SilentlyContinue
  if ($cmd -and $cmd.Source -like "*.exe") {
    # WinGet puts a symlink in ...\WinGet\Links; a firewall rule must name the real file
    $item = Get-Item -LiteralPath $cmd.Source -ErrorAction SilentlyContinue
    if ($item -and $item.LinkType -and $item.Target) { $paths += @($item.Target) } else { $paths += $cmd.Source }
  }
  foreach ($dir in @("$UserProfile\.local\bin", "$UserProfile\.local\share\claude",
                     "$UserProfile\AppData\Local\AnthropicClaude", "$UserProfile\AppData\Local\Programs\claude",
                     "$UserProfile\AppData\Local\Microsoft\WinGet\Packages")) {
    if (Test-Path $dir) {
      $paths += Get-ChildItem $dir -Recurse -File -Include "claude*.exe" -ErrorAction SilentlyContinue |
                Where-Object { -not $_.LinkType -and ($dir -notlike "*WinGet*" -or $_.FullName -like "*Anthropic.ClaudeCode*") } |
                ForEach-Object { $_.FullName }
    }
  }
  $paths = $paths | Sort-Object -Unique
  if (-not $paths) {
    Write-Warning "No claude.exe found. npm installs run under node.exe, which this can't single out; use the native installer."
    return
  }
  foreach ($p in $paths) {
    New-NetFirewallRule -DisplayName "redact-guard: claude direct egress blocked ($([IO.Path]::GetFileName((Split-Path $p))))" `
      -Group $ClaudeGroup -Direction Outbound -Action Block -Program $p -Profile Any | Out-Null
    Write-Host "claude can only reach loopback: $p"
  }
}

if ($OnlyClaude) { Set-ClaudeDirectBlock; return }      # used by the logon refresh task

if ($Remove) {
  Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  Get-NetFirewallRule -Group $ClaudeGroup -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  Unregister-ScheduledTask -TaskName "redact-guard-firewall-refresh" -Confirm:$false -ErrorAction SilentlyContinue
  if ($Strict) { Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow }
  Write-Host "redact-guard firewall rules removed."
  return
}

# SQL Server, Oracle, MySQL/MariaDB, PostgreSQL/pgbouncer, MongoDB, Redis/Sentinel,
# Cassandra, Elasticsearch/OpenSearch, ClickHouse, CockroachDB, CouchDB, Neo4j,
# Memcached, etcd, InfluxDB, ArangoDB, RethinkDB, Db2, Firebird
$tcp = @(1433, 1434, 1521, 1522, 2483, 2484, 3306, 33060, 5432, 5433, 6432,
         27017, 27018, 27019, 6379, 6380, 26379, 9042, 9160, 9200, 9300,
         8123, 9440, 26257, 5984, 6984, 7474, 7687, 11211, 2379, 2380, 8086,
         8529, 28015, 50000, 3050) + $ExtraTcpPorts
$tcpStr = $tcp | ForEach-Object { "$_" }

Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "redact-guard: block outbound DB (TCP)" -Group $Group `
  -Direction Outbound -Action Block -Protocol TCP -RemotePort $tcpStr -Profile Any | Out-Null
New-NetFirewallRule -DisplayName "redact-guard: block outbound DB (UDP)" -Group $Group `
  -Direction Outbound -Action Block -Protocol UDP -RemotePort "1434","11211" -Profile Any | Out-Null
Write-Host "Blocked outbound TCP ports: $($tcp -join ', ')"

if ($Strict) {
  New-NetFirewallRule -DisplayName "redact-guard: allow HTTP/HTTPS out" -Group $Group `
    -Direction Outbound -Action Allow -Protocol TCP -RemotePort "80","443" -Profile Any | Out-Null
  New-NetFirewallRule -DisplayName "redact-guard: allow DNS out (UDP)" -Group $Group `
    -Direction Outbound -Action Allow -Protocol UDP -RemotePort "53" -Profile Any | Out-Null
  New-NetFirewallRule -DisplayName "redact-guard: allow DNS out (TCP)" -Group $Group `
    -Direction Outbound -Action Allow -Protocol TCP -RemotePort "53" -Profile Any | Out-Null
  if ($ProxyPorts.Count -gt 0) {
    New-NetFirewallRule -DisplayName "redact-guard: allow corporate proxy out" -Group $Group `
      -Direction Outbound -Action Allow -Protocol TCP -RemotePort ($ProxyPorts | ForEach-Object { "$_" }) `
      -Profile Any | Out-Null
  }
  New-NetFirewallRule -DisplayName "redact-guard: allow NTP out" -Group $Group `
    -Direction Outbound -Action Allow -Protocol UDP -RemotePort "123" -Profile Any | Out-Null
  Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
  Write-Host "Strict mode: outbound default is now Block (only DNS, NTP, HTTP, HTTPS allowed)."
}

if ($BlockClaudeDirect) {
  Set-ClaudeDirectBlock
  if ($RegisterRefreshTask) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
      -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -OnlyClaude -UserProfile `"$UserProfile`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    Register-ScheduledTask -TaskName "redact-guard-firewall-refresh" -Action $action -Trigger $trigger `
      -RunLevel Highest -User "SYSTEM" -Force | Out-Null
    Write-Host "Registered logon task 'redact-guard-firewall-refresh' (keeps the rule current after updates)."
  }
}

Write-Host "Test (should fail):  Test-NetConnection <your-db-host> -Port 5432"
