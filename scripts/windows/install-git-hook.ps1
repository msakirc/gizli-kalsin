<#
.SYNOPSIS
  Install the placeholder-blocking git hooks into one repository (Windows).
  Git for Windows runs these sh scripts with its bundled shell.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\windows\install-git-hook.ps1 C:\work\orders-api
#>
param([Parameter(Mandatory = $true)][string]$Repo)
$ErrorActionPreference = "Stop"
$Here = Resolve-Path (Join-Path $PSScriptRoot "..")
$hooks = (& git -C $Repo rev-parse --git-path hooks).Trim()
if (-not [System.IO.Path]::IsPathRooted($hooks)) { $hooks = Join-Path $Repo $hooks }
New-Item -ItemType Directory -Force -Path $hooks | Out-Null
foreach ($h in "pre-commit", "commit-msg") {
  $dest = Join-Path $hooks $h
  if ((Test-Path $dest) -and -not ((Get-Content $dest -Raw) -match "redact-guard")) {
    Write-Warning "skip ${h}: $dest already exists (call $Here\$h from it)"
    continue
  }
  # copy (symlinks need Developer Mode on Windows); keep LF line endings for sh
  $content = (Get-Content (Join-Path $Here $h) -Raw) -replace "`r`n", "`n"
  [System.IO.File]::WriteAllText($dest, $content)
  Write-Host "installed $h -> $dest"
}
